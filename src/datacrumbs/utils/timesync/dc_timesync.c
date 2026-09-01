// dc_timesync: datacrumbs cross-node time reconciliation.
//
// Measures the offset+skew between two nodes' NIC PTP hardware clocks (PHCs)
// using a two-step, HW-timestamped UDP exchange over IPv6 link-local on a mlx5
// fabric netdev, and the local PHC<->CLOCK_MONOTONIC bridge. This lets the
// datacrumbs server remap each event's MONOTONIC timestamp onto a shared
// cross-node timeline (see the server-side consumer) so a distributed app can
// be explained on one axis -- without disciplining/steering the host clock.
//
// This file currently provides the measurement primitive + a self-test:
//   responder:  sudo dc_timesync <iface> resp
//   initiator:  sudo dc_timesync <iface> init <peer_ll_ipv6> [count]
// The periodic daemon (sliding fit + seqlock mmap snapshot the server reads) is
// layered on top of these primitives.
//
// TX HW timestamps come back on the socket error queue (MSG_ERRQUEUE); RX HW
// timestamps arrive as SCM_TIMESTAMPING cmsgs. Needs CAP_NET_ADMIN (sudo) to
// arm NIC timestamping via SIOCSHWTSTAMP.

#define _GNU_SOURCE
#include <datacrumbs/utils/common/constants.h>
#include <arpa/inet.h>
#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <errno.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <linux/errqueue.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PORT 3199
#define MAGIC 0xDC757301u
enum { T_REQ = 1, T_RESP = 2, T_FUP = 3 };

struct __attribute__((packed)) msg_t {
  uint32_t magic;
  uint32_t seq;
  uint8_t type;
  uint64_t t_rx;  // responder RX hw ts (in FUP)
  uint64_t t_tx;  // responder TX hw ts (in FUP)
};

static uint64_t ns(const struct timespec* t) {
  return (uint64_t)t->tv_sec * 1000000000ull + t->tv_nsec;
}

// Resolve the PHC index that hardware-stamps a given netdev (ETHTOOL_GET_TS_INFO),
// so we open the right /dev/ptpN instead of hardcoding it. Returns -1 on failure.
static int phc_index_of(const char* iface) {
  struct ethtool_ts_info info = {0};
  info.cmd = ETHTOOL_GET_TS_INFO;
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  ifr.ifr_data = (void*)&info;
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  int rc = ioctl(fd, SIOCETHTOOL, &ifr);
  close(fd);
  if (rc < 0) {
    fprintf(stderr, "ETHTOOL_GET_TS_INFO(%s): %s\n", iface, strerror(errno));
    return -1;
  }
  return info.phc_index;
}

// Arm hardware timestamping on the NIC (all rx filters, tx on).
static int arm_hwtstamp(const char* iface) {
  struct hwtstamp_config cfg = {0};
  cfg.tx_type = HWTSTAMP_TX_ON;
  cfg.rx_filter = HWTSTAMP_FILTER_ALL;
  struct ifreq ifr = {0};
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
  ifr.ifr_data = (void*)&cfg;
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  int rc = ioctl(fd, SIOCSHWTSTAMP, &ifr);
  close(fd);
  if (rc < 0) fprintf(stderr, "SIOCSHWTSTAMP(%s): %s\n", iface, strerror(errno));
  return rc;
}

static int mk_socket(const char* iface) {
  int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }
  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0)
    perror("SO_BINDTODEVICE");
  int flags = SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE |
              SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_OPT_TSONLY;
  if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
    perror("SO_TIMESTAMPING");
    return -1;
  }
  struct sockaddr_in6 a = {0};
  a.sin6_family = AF_INET6;
  a.sin6_port = htons(PORT);
  a.sin6_scope_id = if_nametoindex(iface);
  if (bind(fd, (struct sockaddr*)&a, sizeof(a)) < 0) {
    perror("bind");
    return -1;
  }
  return fd;
}

// Pull the raw-hardware SCM_TIMESTAMPING out of a cmsg stream. Returns ns or 0.
static uint64_t scan_hwts(struct msghdr* m) {
  for (struct cmsghdr* c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c)) {
    if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPING) {
      struct timespec* ts = (struct timespec*)CMSG_DATA(c);
      return ns(&ts[2]);  // [0]=sw [1]=deprecated [2]=raw hw
    }
  }
  return 0;
}

// Drain any stale packets (normal + error queue) so a round uses only fresh
// timestamps -- prevents a slow-turnaround peer from building a backlog that
// makes RX timestamps drift later each round.
static void drain_stale(int fd, int errq_only) {
  char ctrl[256], buf[256];
  struct iovec iov = {buf, sizeof(buf)};
  for (int q = errq_only ? 1 : 0; q < 2; q++) {
    int flags = MSG_DONTWAIT | (q ? MSG_ERRQUEUE : 0);
    for (int i = 0; i < 64; i++) {
      struct msghdr m = {0};
      m.msg_iov = &iov;
      m.msg_iovlen = 1;
      m.msg_control = ctrl;
      m.msg_controllen = sizeof(ctrl);
      if (recvmsg(fd, &m, flags) < 0) break;
    }
  }
}

// Recover the HW TX timestamp for a just-sent packet from the error queue.
// Fully drains the queue and returns the FRESHEST (last) timestamp -- if more TX
// timestamps accumulated than were drained (e.g. a two-packet turnaround), the
// oldest would otherwise be returned and drift staler every round.
static uint64_t get_tx_ts(int fd) {
  char ctrl[256], buf[256];
  uint64_t last = 0;
  for (int tries = 0; tries < 10; tries++) {
    struct pollfd p = {.fd = fd, .events = POLLERR};
    if (poll(&p, 1, 50) <= 0) {
      if (last) break;  // got one already and queue drained
      continue;
    }
    // drain everything currently queued, keeping the most recent
    for (;;) {
      struct iovec iov = {buf, sizeof(buf)};
      struct msghdr m = {0};
      m.msg_iov = &iov;
      m.msg_iovlen = 1;
      m.msg_control = ctrl;
      m.msg_controllen = sizeof(ctrl);
      if (recvmsg(fd, &m, MSG_ERRQUEUE | MSG_DONTWAIT) < 0) break;
      uint64_t t = scan_hwts(&m);
      if (t) last = t;
    }
    if (last) break;
  }
  return last;
}

static uint64_t recv_msg(int fd, struct msg_t* out, struct sockaddr_in6* from) {
  char ctrl[256];
  struct iovec iov = {out, sizeof(*out)};
  struct msghdr m = {0};
  m.msg_iov = &iov;
  m.msg_iovlen = 1;
  m.msg_control = ctrl;
  m.msg_controllen = sizeof(ctrl);
  m.msg_name = from;
  m.msg_namelen = from ? sizeof(*from) : 0;
  if (recvmsg(fd, &m, 0) < 0) return 0;
  return scan_hwts(&m);
}

// PHC vs CLOCK_MONOTONIC bridge. Prefer PRECISE (atomic PHC<->monoraw); if the
// NIC lacks it (no PCIe PTM, common on mlx5), fall back to PTP_SYS_OFFSET which
// brackets a PHC read between two CLOCK_REALTIME reads, then hop REALTIME->MONOTONIC.
static int64_t phc_mono_offset(int phc_index, uint64_t* phc_out) {
  char dev[32];
  snprintf(dev, sizeof(dev), "/dev/ptp%d", phc_index);
  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
    return 0;
  }
  struct ptp_sys_offset_precise op = {0};
  if (ioctl(fd, PTP_SYS_OFFSET_PRECISE, &op) == 0) {
    close(fd);
    uint64_t phc = (uint64_t)op.device.sec * 1000000000ull + op.device.nsec;
    uint64_t mono = (uint64_t)op.sys_monoraw.sec * 1000000000ull + op.sys_monoraw.nsec;
    if (phc_out) *phc_out = phc;
    return (int64_t)(phc - mono);
  }
  struct ptp_sys_offset os = {0};
  os.n_samples = 5;
  if (ioctl(fd, PTP_SYS_OFFSET, &os) < 0) {
    fprintf(stderr, "PTP_SYS_OFFSET %s: %s\n", dev, strerror(errno));
    close(fd);
    return 0;
  }
  close(fd);
  // ts layout: sys,phc,sys,phc,...  pick the middle phc and its bracketing sys.
  int k = os.n_samples / 2;
  uint64_t sys0 = (uint64_t)os.ts[2 * k].sec * 1000000000ull + os.ts[2 * k].nsec;
  uint64_t phc = (uint64_t)os.ts[2 * k + 1].sec * 1000000000ull + os.ts[2 * k + 1].nsec;
  uint64_t sys1 = (uint64_t)os.ts[2 * k + 2].sec * 1000000000ull + os.ts[2 * k + 2].nsec;
  uint64_t sys = (sys0 + sys1) / 2;  // CLOCK_REALTIME midpoint
  // REALTIME -> MONOTONIC hop (read both close together)
  struct timespec rt, mo;
  clock_gettime(CLOCK_REALTIME, &rt);
  clock_gettime(CLOCK_MONOTONIC, &mo);
  int64_t rt_minus_mono = (int64_t)(ns(&rt) - ns(&mo));
  if (phc_out) *phc_out = phc;
  return (int64_t)(phc - sys) + rt_minus_mono;  // add to CLOCK_MONOTONIC ns -> PHC ns
}

// Populate the v2 local clock registry: for every /dev/ptpN on this node, the offset that maps its
// ns onto the SYNCED PHC's ns (the one the cross-node fit is expressed in). A hw timestamp from any
// NIC can then be remapped to the reference; without this, a timestamp from another PHC lands ~20 s
// away (BlueField has 4 independent PHCs and the fit only covers one).
//
// Sign: phc_mono_offset() returns (phc - mono), so with t_k = mono + off_k and
// t_synced = mono + off_synced, we need delta = t_synced - t_k = off_synced - off_k.
//
// Accuracy: both reads use PTP_SYS_OFFSET_PRECISE (hardware cross-timestamping), and the PHCs share
// the NIC oscillator so their relative drift is ~2 ns/s -- over the microseconds between the two
// ioctls the induced error is sub-ns. Re-reading the synced PHC per entry bounds it further.
static uint64_t mono_ns(void);  // fwd decl (defined below)
static void fill_clock_registry(struct dc_timesync_snapshot* v, int synced_phc) {
  v->synced_phc_index = synced_phc;
  v->n_clocks = 0;
  for (int k = 0; k < 64 && v->n_clocks < DC_TIMESYNC_MAX_CLOCKS; k++) {
    char dev[32];
    snprintf(dev, sizeof(dev), "/dev/ptp%d", k);
    if (access(dev, R_OK) != 0) continue;
    struct dc_timesync_clock* c = &v->clocks[v->n_clocks];
    c->phc_index = k;
    c->updated_mono_ns = mono_ns();
    if (k == synced_phc) {  // identity by definition
      c->delta_to_synced_ns = 0;
      c->valid = 1;
      v->n_clocks++;
      continue;
    }
    int64_t off_synced = phc_mono_offset(synced_phc, NULL);
    int64_t off_k = phc_mono_offset(k, NULL);
    if (off_synced == 0 || off_k == 0) {  // unreadable -> mark invalid rather than publish a lie
      c->delta_to_synced_ns = 0;
      c->valid = 0;
    } else {
      c->delta_to_synced_ns = off_synced - off_k;
      c->valid = 1;
    }
    v->n_clocks++;
  }
}

// ---- HCA free-running raw clock <-> synced PHC sliding fit (optional) ----
// The DOCA fabric CQE hw ts is the HCA free-running clock, which /dev/ptp does not expose. When the
// daemon is told the fabric ib device (DC_TIMESYNC_RAW_DEV), it reads that same clock via
// ibv_query_rt_values_ex each cycle and publishes a raw->synced-PHC fit, so an unprivileged consumer
// (the DOCA CQE hook) maps a completion ts straight onto the global epoch with no local anchor.
static struct ibv_context* g_raw_ctx = NULL;

static void raw_open(const char* dev) {
  int n = 0;
  struct ibv_device** list = ibv_get_device_list(&n);
  if (!list) return;
  for (int i = 0; i < n; i++)
    if (strcmp(ibv_get_device_name(list[i]), dev) == 0) {
      g_raw_ctx = ibv_open_device(list[i]);
      break;
    }
  ibv_free_device_list(list);
  if (!g_raw_ctx) fprintf(stderr, "DC_TIMESYNC_RAW_DEV=%s: no such ib device\n", dev);
}

static uint64_t raw_now(void) {
  if (!g_raw_ctx) return 0;
  struct ibv_values_ex v = {0};
  v.comp_mask = IBV_VALUES_MASK_RAW_CLOCK;
  if (ibv_query_rt_values_ex(g_raw_ctx, &v) != 0) return 0;
  return ns(&v.raw_clock);
}

// Sliding window of (raw, synced_phc - raw) samples; a least-squares line gives the fit the reader
// extrapolates from, so its skew term absorbs the ~4 ppm HCA<->PHC servo drift (drift-free).
#define RAWWIN 16
static uint64_t raw_w_raw[RAWWIN];
static int64_t raw_w_d[RAWWIN];
static int raw_n = 0, raw_i = 0;

// Read the HCA raw clock bracketed around a synced-PHC read, so the (phc - raw) sample is free of the
// read gap: raw and phc share the NIC oscillator, so the bracket midpoint pins them to one instant.
// Returns 0 (no fit) when the raw device is not configured.
static uint64_t raw_paired(int synced_phc, uint64_t* phc_out) {
  uint64_t a = raw_now();
  if (a == 0) return 0;
  int64_t br = phc_mono_offset(synced_phc, phc_out);
  uint64_t b = raw_now();
  (void)br;
  return (a + b) / 2;
}

static void raw_fit_update(uint64_t raw, uint64_t phc_synced, struct dc_timesync_snapshot* v) {
  if (!g_raw_ctx || raw == 0 || phc_synced == 0) return;
  raw_w_raw[raw_i] = raw;
  raw_w_d[raw_i] = (int64_t)(phc_synced - raw);
  raw_i = (raw_i + 1) % RAWWIN;
  if (raw_n < RAWWIN) raw_n++;
  if (raw_n < 2) return;
  int base = (raw_i + RAWWIN - raw_n) % RAWWIN;
  uint64_t t0 = raw_w_raw[base];
  double sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (int j = 0; j < raw_n; j++) {
    int idx = (base + j) % RAWWIN;
    double x = (double)((int64_t)(raw_w_raw[idx] - t0)) / 1e9;
    double y = (double)raw_w_d[idx];
    sx += x;
    sy += y;
    sxx += x * x;
    sxy += x * y;
  }
  double denom = raw_n * sxx - sx * sx;
  double b = denom != 0 ? (raw_n * sxy - sx * sy) / denom : 0;
  double a = (sy - b * sx) / raw_n;
  v->raw_anchor_ns = (int64_t)t0;
  v->raw_to_synced_ns = (int64_t)a;
  v->raw_skew_ppb = (int64_t)b;
  v->raw_valid = 1;
}

// Handle one responder turn: wait (up to the socket's SO_RCVTIMEO) for a REQ and
// reply with RESP + a FUP carrying our RX/TX hw timestamps. Returns 1 if a REQ
// was served, 0 on timeout (lets a caller wake periodically to do other work).
static int respond_once(int fd) {
  struct msg_t in, out;
  struct sockaddr_in6 from = {0};
  uint64_t t_rx = recv_msg(fd, &in, &from);
  if (!t_rx || in.magic != MAGIC || in.type != T_REQ) return 0;
  from.sin6_port = htons(PORT);
  out = (struct msg_t){.magic = MAGIC, .seq = in.seq, .type = T_RESP};
  drain_stale(fd, 1);  // so get_tx_ts picks up only THIS RESP's timestamp
  sendto(fd, &out, sizeof(out), 0, (struct sockaddr*)&from, sizeof(from));
  out.type = T_FUP;
  out.t_rx = t_rx;
  out.t_tx = get_tx_ts(fd);
  sendto(fd, &out, sizeof(out), 0, (struct sockaddr*)&from, sizeof(from));
  return 1;
}

// One two-step exchange with peer. offset/delay in ns; ta_s = our send hw ts
// (local PHC ns). Returns 0 on success, -1 if any of the four timestamps missing.
static int do_exchange(int fd, struct sockaddr_in6* peer, uint32_t seq, int64_t* offset_out,
                       int64_t* delay_out, uint64_t* ta_s_out) {
  drain_stale(fd, 0);
  struct msg_t req = {.magic = MAGIC, .seq = seq, .type = T_REQ};
  sendto(fd, &req, sizeof(req), 0, (struct sockaddr*)peer, sizeof(*peer));
  uint64_t ta_s = get_tx_ts(fd);
  struct msg_t r;
  uint64_t ta_r = 0, tb_r = 0, tb_s = 0;
  for (int got = 0; got < 3;) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 500) <= 0) break;
    uint64_t rx = recv_msg(fd, &r, NULL);
    if (r.magic != MAGIC || r.seq != seq) continue;
    if (r.type == T_RESP) {
      ta_r = rx;
      got |= 1;
    } else if (r.type == T_FUP) {
      tb_r = r.t_rx;
      tb_s = r.t_tx;
      got |= 2;
    }
  }
  if (!ta_s || !ta_r || !tb_r || !tb_s) return -1;
  int64_t fwd = (int64_t)(tb_r - ta_s);  // A->B transit (mixed clock domains)
  int64_t rev = (int64_t)(ta_r - tb_s);  // B->A transit
  *offset_out = (fwd - rev) / 2;         // local->ref PHC offset
  *delay_out = (fwd + rev) / 2;          // one-way delay
  *ta_s_out = ta_s;
  return 0;
}

// Map (create) the seqlock snapshot file the server reads. Returns NULL on error.
static struct dc_timesync_snapshot* map_snapshot(const char* path) {
  int fd = open(path, O_RDWR | O_CREAT, 0644);
  if (fd < 0) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    return NULL;
  }
  if (ftruncate(fd, sizeof(struct dc_timesync_snapshot)) < 0) {
    close(fd);
    return NULL;
  }
  void* p =
      mmap(NULL, sizeof(struct dc_timesync_snapshot), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (p == MAP_FAILED) {
    perror("mmap");
    return NULL;
  }
  return (struct dc_timesync_snapshot*)p;
}

// Read-only map of the snapshot (server + dump run unprivileged; the daemon
// writes it as root with 0644, so readers must not request write access).
static struct dc_timesync_snapshot* map_snapshot_ro(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    return NULL;
  }
  void* p = mmap(NULL, sizeof(struct dc_timesync_snapshot), PROT_READ, MAP_SHARED, fd, 0);
  close(fd);
  if (p == MAP_FAILED) {
    perror("mmap");
    return NULL;
  }
  return (struct dc_timesync_snapshot*)p;
}

// Seqlock publish: bump seq odd, write body, bump seq even. Readers retry while odd.
static void publish(struct dc_timesync_snapshot* s, const struct dc_timesync_snapshot* v) {
  uint32_t next = (s->seq | 1) + 1;                       // ensure we land on an even value
  __atomic_store_n(&s->seq, next - 1, __ATOMIC_RELAXED);  // odd: write in progress
  __atomic_thread_fence(__ATOMIC_RELEASE);
  s->magic = DC_TIMESYNC_MAGIC;
  s->valid = v->valid;
  s->ref_id = v->ref_id;
  s->self_id = v->self_id;
  s->bridge_mono_to_phc_ns = v->bridge_mono_to_phc_ns;
  s->anchor_phc_ns = v->anchor_phc_ns;
  s->offset_ns = v->offset_ns;
  s->skew_ppb = v->skew_ppb;
  s->updated_mono_ns = v->updated_mono_ns;
  s->residual_rms_ns = v->residual_rms_ns;
  // v2 local clock registry -- must be copied here too; this function is field-by-field, not a
  // memcpy, so any field added to the struct is silently dropped until it is added below.
  s->n_clocks = v->n_clocks;
  s->synced_phc_index = v->synced_phc_index;
  for (uint32_t i = 0; i < v->n_clocks && i < DC_TIMESYNC_MAX_CLOCKS; i++) s->clocks[i] = v->clocks[i];
  s->raw_valid = v->raw_valid;
  s->raw_anchor_ns = v->raw_anchor_ns;
  s->raw_to_synced_ns = v->raw_to_synced_ns;
  s->raw_skew_ppb = v->raw_skew_ppb;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&s->seq, next, __ATOMIC_RELAXED);  // even: consistent
}

static uint64_t mono_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return ns(&t);
}

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);  // line-buffered so logs survive SIGTERM
  if (argc < 3) {
    fprintf(stderr,
            "usage: %s <iface> resp|init [peer_ll] [count]\n"
            "       %s <iface> daemon <self_id> <ref_id> [ref_ll] [cadence_ms]\n",
            argv[0], argv[0]);
    return 2;
  }
  const char *iface = argv[1], *role = argv[2];

  if (strcmp(role, "dump") == 0) {  // inspect the published snapshot (no NIC/sudo needed)
    const char* snap_path = getenv(DATACRUMBS_ENV_TIMESYNC_SNAPSHOT);
    if (!snap_path) snap_path = DC_TIMESYNC_DEFAULT_PATH;
    struct dc_timesync_snapshot* shm = map_snapshot_ro(snap_path);
    if (!shm) return 1;
    printf("snapshot %s: magic=%#x seq=%u valid=%u self=%u ref=%u\n", snap_path, shm->magic,
           shm->seq, shm->valid, shm->self_id, shm->ref_id);
    printf("  bridge_mono_to_phc=%lld ns  anchor_phc=%lld ns\n",
           (long long)shm->bridge_mono_to_phc_ns, (long long)shm->anchor_phc_ns);
    printf("  offset=%lld ns  skew=%lld ppb  residual_rms=%.0f ns  age=%lldms\n",
           (long long)shm->offset_ns, (long long)shm->skew_ppb, shm->residual_rms_ns,
           (long long)((mono_ns() - shm->updated_mono_ns) / 1000000));
    // local clock registry: how to remap a hw ts from ANY local PHC onto the synced one
    printf("  clocks: n=%u synced_phc=/dev/ptp%d\n", shm->n_clocks, shm->synced_phc_index);
    for (uint32_t i = 0; i < shm->n_clocks && i < DC_TIMESYNC_MAX_CLOCKS; i++)
      printf("    /dev/ptp%-2d valid=%u delta_to_synced=%lld ns%s\n", shm->clocks[i].phc_index,
             shm->clocks[i].valid, (long long)shm->clocks[i].delta_to_synced_ns,
             shm->clocks[i].phc_index == shm->synced_phc_index ? "  (synced)" : "");
    printf("  raw fit: valid=%u anchor=%lld raw_to_synced=%lld ns skew=%lld ppb\n", shm->raw_valid,
           (long long)shm->raw_anchor_ns, (long long)shm->raw_to_synced_ns,
           (long long)shm->raw_skew_ppb);
    return 0;
  }

  int phc = phc_index_of(iface);
  if (phc < 0) return 1;
  if (arm_hwtstamp(iface) < 0) return 1;
  int fd = mk_socket(iface);
  if (fd < 0) return 1;

  // local PHC<->MONOTONIC bridge (secondary; the cross-node offset is primary)
  uint64_t phc_now = 0;
  int64_t bridge = phc_mono_offset(phc, &phc_now);
  printf("# %s iface=%s phc=/dev/ptp%d PHC=%llu bridge(phc-mono)=%lld ns\n", role, iface, phc,
         (unsigned long long)phc_now, (long long)bridge);

  if (strcmp(role, "daemon") == 0) {
    if (argc < 5) {
      fprintf(stderr, "daemon needs <self_id> <ref_id>\n");
      return 2;
    }
    uint32_t self_id = (uint32_t)atoi(argv[3]);
    uint32_t ref_id = (uint32_t)atoi(argv[4]);
    int cadence_ms = argc > 6 ? atoi(argv[6]) : 1000;
    const char* snap_path = getenv(DATACRUMBS_ENV_TIMESYNC_SNAPSHOT);
    if (!snap_path) snap_path = DC_TIMESYNC_DEFAULT_PATH;
    struct dc_timesync_snapshot* shm = map_snapshot(snap_path);
    if (!shm) return 1;
    printf("# daemon self=%u ref=%u cadence=%dms snapshot=%s\n", self_id, ref_id, cadence_ms,
           snap_path);
    const char* raw_dev = getenv(DATACRUMBS_ENV_TIMESYNC_RAW_DEV);  // fabric ib device -> publish raw-clock fit
    if (raw_dev && *raw_dev) raw_open(raw_dev);

    if (self_id == ref_id) {
      // reference node: serve initiators + publish an identity snapshot (its PHC
      // IS the reference, so offset=0/skew=0; only the local mono<->phc bridge moves).
      struct timeval tv = {1, 0};  // wake ~1 Hz even with no traffic to refresh bridge
      setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      uint64_t last_pub = 0;
      for (;;) {
        respond_once(fd);
        uint64_t now = mono_ns();
        if (now - last_pub < (uint64_t)cadence_ms * 1000000ull) continue;
        uint64_t phc_ref = 0;
        int64_t br = phc_mono_offset(phc, &phc_ref);
        struct dc_timesync_snapshot v = {0};
        v.valid = 1;
        v.ref_id = ref_id;
        v.self_id = self_id;
        v.bridge_mono_to_phc_ns = br;
        v.anchor_phc_ns = (int64_t)phc_ref;
        v.updated_mono_ns = now;
        fill_clock_registry(&v, phc);
        uint64_t raw_phc = 0, raw = raw_paired(phc, &raw_phc);
        raw_fit_update(raw, raw_phc, &v);
        publish(shm, &v);
        last_pub = now;
      }
    }

    // non-reference node: sync to the reference, sliding-window fit, publish.
    if (argc < 6) {
      fprintf(stderr, "daemon (non-ref) needs ref_ll\n");
      return 2;
    }
    struct sockaddr_in6 peer = {0};
    peer.sin6_family = AF_INET6;
    peer.sin6_port = htons(PORT);
    peer.sin6_scope_id = if_nametoindex(iface);
    if (inet_pton(AF_INET6, argv[5], &peer.sin6_addr) != 1) {
      fprintf(stderr, "bad ref_ll\n");
      return 2;
    }

#define WIN 16
    uint64_t win_phc[WIN];
    int64_t win_off[WIN];
    int wn = 0, wi = 0;
    uint32_t seq = 0, warm = 1;
    for (;;) {
      int64_t off, dly;
      uint64_t ta_s;
      if (do_exchange(fd, &peer, seq++, &off, &dly, &ta_s) == 0 && !warm) {
        win_phc[wi] = ta_s;
        win_off[wi] = off;
        wi = (wi + 1) % WIN;
        if (wn < WIN) wn++;
        if (wn >= 2) {
          int base = (wi + WIN - wn) % WIN;  // oldest sample
          uint64_t t0 = win_phc[base];
          double sx = 0, sy = 0, sxx = 0, sxy = 0;
          for (int j = 0; j < wn; j++) {
            int idx = (base + j) % WIN;
            double x = (double)((int64_t)(win_phc[idx] - t0)) / 1e9;
            double y = (double)win_off[idx];
            sx += x;
            sy += y;
            sxx += x * x;
            sxy += x * y;
          }
          double denom = wn * sxx - sx * sx;
          double b = denom != 0 ? (wn * sxy - sx * sy) / denom : 0;
          double a = (sy - b * sx) / wn;
          double var = 0;
          for (int j = 0; j < wn; j++) {
            int idx = (base + j) % WIN;
            double x = (double)((int64_t)(win_phc[idx] - t0)) / 1e9;
            double e = (double)win_off[idx] - (a + b * x);
            var += e * e;
          }
          uint64_t phc2 = 0;
          int64_t br = phc_mono_offset(phc, &phc2);
          struct dc_timesync_snapshot v = {0};
          v.valid = 1;
          v.ref_id = ref_id;
          v.self_id = self_id;
          v.bridge_mono_to_phc_ns = br;
          v.anchor_phc_ns = (int64_t)t0;
          v.offset_ns = (int64_t)a;  // local->ref offset at anchor t0
          v.skew_ppb = (int64_t)b;   // ns per second
          v.updated_mono_ns = mono_ns();
          v.residual_rms_ns = __builtin_sqrt(var / wn);
          fill_clock_registry(&v, phc);
          uint64_t raw_phc = 0, raw = raw_paired(phc, &raw_phc);
          raw_fit_update(raw, raw_phc, &v);
          publish(shm, &v);
        }
      }
      warm = 0;  // discard only the very first (cold-start) exchange
      // Serve peers while idle instead of sleeping blind. With only the reference answering, the
      // topology is a star: it has no cycles, so loop-closure checks are impossible, and those are
      // the only way to bound path asymmetry (a two-way exchange cannot separate it from offset).
      // respond_once ignores anything that is not a T_REQ, so our own replies pass through safely.
      uint64_t idle_until = mono_ns() + (uint64_t)cadence_ms * 1000000ull;
      for (;;) {
        int64_t left_ms = ((int64_t)idle_until - (int64_t)mono_ns()) / 1000000;
        if (left_ms <= 0) break;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, (int)left_ms) > 0) respond_once(fd);
      }
    }
  }

  if (strcmp(role, "resp") == 0) {
    printf("# responder ready on port %d\n", PORT);
    for (;;) {
      struct msg_t in, out;
      struct sockaddr_in6 from = {0};
      uint64_t t_rx = recv_msg(fd, &in, &from);
      if (in.magic != MAGIC || in.type != T_REQ) continue;
      from.sin6_port = htons(PORT);
      out = (struct msg_t){.magic = MAGIC, .seq = in.seq, .type = T_RESP};
      // clear the errqueue right before this send so get_tx_ts can only pick up
      // THIS RESP's timestamp (a prior FUP's ts may have landed during the recv wait).
      drain_stale(fd, 1);
      sendto(fd, &out, sizeof(out), 0, (struct sockaddr*)&from, sizeof(from));
      uint64_t t_tx = get_tx_ts(fd);
      out.type = T_FUP;
      out.t_rx = t_rx;
      out.t_tx = t_tx;
      sendto(fd, &out, sizeof(out), 0, (struct sockaddr*)&from, sizeof(from));
    }
  }

  // initiator
  if (argc < 4) {
    fprintf(stderr, "init needs peer_ll\n");
    return 2;
  }
  int count = argc > 4 ? atoi(argv[4]) : 20;
  struct sockaddr_in6 peer = {0};
  peer.sin6_family = AF_INET6;
  peer.sin6_port = htons(PORT);
  peer.sin6_scope_id = if_nametoindex(iface);
  if (inet_pton(AF_INET6, argv[3], &peer.sin6_addr) != 1) {
    fprintf(stderr, "bad peer\n");
    return 2;
  }

  double *xs = calloc(count, sizeof(double)), *ys = calloc(count, sizeof(double));
  int n = 0;
  uint64_t t0 = 0;
  for (int s = 0; s < count; s++) {
    drain_stale(fd, 0);  // clear any backlog so this round's timestamps are fresh
    struct msg_t req = {.magic = MAGIC, .seq = s, .type = T_REQ};
    sendto(fd, &req, sizeof(req), 0, (struct sockaddr*)&peer, sizeof(peer));
    uint64_t ta_s = get_tx_ts(fd);  // A send hw ts
    struct msg_t r;
    uint64_t ta_r = 0, tb_r = 0, tb_s = 0;
    for (int got = 0; got < 3;) {  // expect RESP (bit 1) then FUP (bit 2)
      struct pollfd p = {.fd = fd, .events = POLLIN};
      if (poll(&p, 1, 500) <= 0) break;
      uint64_t rx = recv_msg(fd, &r, NULL);
      if (r.magic != MAGIC || r.seq != (uint32_t)s) continue;
      if (r.type == T_RESP) {
        ta_r = rx;
        got |= 1;
      } else if (r.type == T_FUP) {
        tb_r = r.t_rx;
        tb_s = r.t_tx;
        got |= 2;
      }
    }
    if (!ta_s || !ta_r || !tb_r || !tb_s) {
      fprintf(stderr, "seq %d incomplete (as=%llu ar=%llu br=%llu bs=%llu)\n", s,
              (unsigned long long)ta_s, (unsigned long long)ta_r, (unsigned long long)tb_r,
              (unsigned long long)tb_s);
      usleep(200000);
      continue;
    }
    // PTP offset/delay from the four hw timestamps. The two PHCs free-run with a
    // large (tens-of-seconds) offset, so tb_r-ta_s can be hugely negative -> must
    // subtract as signed int64, not wrap as uint64.
    int64_t fwd = (int64_t)(tb_r - ta_s);  // A->B transit in mixed clock domains
    int64_t rev = (int64_t)(ta_r - tb_s);  // B->A transit
    double offset = ((double)fwd - (double)rev) / 2.0;
    double delay = ((double)fwd + (double)rev) / 2.0;
    if (n == 0)
      printf("# raw seq0: ta_s=%llu tb_r=%llu tb_s=%llu ta_r=%llu\n", (unsigned long long)ta_s,
             (unsigned long long)tb_r, (unsigned long long)tb_s, (unsigned long long)ta_r);
    printf("seq=%2d offset=%.0f ns  delay=%.0f ns\n", s, offset, delay);
    if (s == 0) {
      usleep(500000);
      continue;
    }  // discard cold-start warm-up exchange
    if (!t0) t0 = ta_s;
    xs[n] = (double)(ta_s - t0) / 1e9;  // seconds since start
    ys[n] = offset;
    n++;
    usleep(500000);  // ~2 Hz self-test (daemon cadence is ~1 Hz; slow enough to avoid backlog)
  }
  // linear fit offset(t) = a + b*t  -> b is the skew (ns/s = ppb)
  if (n >= 2) {
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    for (int i = 0; i < n; i++) {
      sx += xs[i];
      sy += ys[i];
      sxx += xs[i] * xs[i];
      sxy += xs[i] * ys[i];
    }
    double b = (n * sxy - sx * sy) / (n * sxx - sx * sx);
    double a = (sy - b * sx) / n;
    double var = 0;
    for (int i = 0; i < n; i++) {
      double e = ys[i] - (a + b * xs[i]);
      var += e * e;
    }
    printf("\n# FIT  offset0=%.0f ns  skew=%.1f ppb (ns/s)  residual_rms=%.0f ns  n=%d\n", a, b,
           (var > 0 ? __builtin_sqrt(var / n) : 0), n);
  }
  return 0;
}
