// RDMA hardware-timestamp capture (LD_PRELOAD, DC_HWTS=1). RDMA poll is kernel-bypass and inlined,
// so neither eBPF nor plain interposition can time the wire; we upgrade each ibv_create_cq CQ to a
// timestamped extended CQ, hijack context->ops.poll_cq, and per completion write a COMPLETE .pfw
// record with the NIC hw ts remapped onto the dc_timesync global epoch (merges with the server trace).
//
// Only the proven-safe legacy ibv_create_cq path is ported. The inline ibv_create_cq_ex ops-table
// hook is deliberately omitted (it segfaulted apps in ibv_modify_qp), as are the opt-in
// post/doorbell/uprobe/CSV paths; an app building its CQ only via ibv_create_cq_ex is uncaptured.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <dirent.h>
#include <dlfcn.h>
#include <infiniband/verbs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {

bool hwts_on() {
  static int v = -1;
  if (v < 0) {
    const char* e = std::getenv("DC_HWTS");
    v = (e != nullptr && *e != '\0' && e[0] != '0') ? 1 : 0;
  }
  return v;
}

long tid() {
  static thread_local long t = 0;
  if (t == 0) t = static_cast<long>(syscall(SYS_gettid));
  return t;
}

// Per-process .pfw sink: global-epoch COMPLETE records written as multi-member gzip.
struct Sink {
  datacrumbs::timesync::Reader reader;
  std::string hhash;
  std::mutex mu;
  std::string buf;
  std::FILE* file = nullptr;
  std::atomic<uint64_t> id{0};

  void flush_locked() {
    if (buf.empty() || file == nullptr) return;
    const std::vector<uint8_t> member = datacrumbs::pfw::gzip_block(buf);
    std::fwrite(member.data(), 1, member.size(), file);
    std::fflush(file);
    buf.clear();
  }
};
Sink* g_sink = nullptr;
std::once_flag g_once;

void sink_init() {
  auto* s = new Sink();
  s->reader.map();
  char host[256] = {0};
  gethostname(host, sizeof(host) - 1);
  s->hhash = datacrumbs::pfw::hhash(host);
  const char* dir = std::getenv("DC_HWTS_OUT");
  if (dir == nullptr || *dir == '\0') dir = std::getenv("DATACRUMBS_LOG_DIR");
  if (dir == nullptr || *dir == '\0') dir = "/tmp";
  char path[1024];
  std::snprintf(path, sizeof(path), "%s/trace-rdma-%d-%s.pfw.gz", dir, getpid(), host);
  s->file = std::fopen(path, "wb");
  char hh[512];
  const int n = std::snprintf(
      hh, sizeof(hh),
      R"({"name":"HH","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
      "\n",
      s->hhash.c_str(), host, s->hhash.c_str());
  s->buf.append(hh, static_cast<std::size_t>(n));
  g_sink = s;
}

const char* opcode_name(uint32_t op) {
  switch (op) {
    case IBV_WC_SEND: return "rdma_send";
    case IBV_WC_RECV: return "rdma_recv";
    case IBV_WC_RECV_RDMA_WITH_IMM: return "rdma_recv_imm";
    case IBV_WC_RDMA_WRITE: return "rdma_write";
    case IBV_WC_RDMA_READ: return "rdma_read";
    case 250: return "rdma_post";  // our WITH_IMM send marker
    default: return "rdma_completion";
  }
}

// Emit one completion. hw==0 => cpu-tier marker (post); phc<0 => not a NIC ts. ts is the global epoch
// in us; raw_ns/phc/aligned stay in args so the mapping is auditable and reversible.
void emit(uint64_t hw_ns, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp, int phc) {
  Sink* s = g_sink;
  if (s == nullptr) return;
  const uint64_t ref_ns = hw_ns != 0 ? s->reader.remap_hw(hw_ns, phc) : 0;
  char line[640];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"rdma_hwts","type":"rdma","pid":%ld,"tid":%d,"ts":%llu,"dur":0,"ph":1,"args":{"hhash":"%s","aligned":%d,"raw_ns":%llu,"phc":%d,"wr_id":%llu,"opcode":%u,"imm":%u,"qp":%u}})"
      "\n",
      static_cast<unsigned long long>(s->id.fetch_add(1)), opcode_name(op), tid(), getpid(),
      static_cast<unsigned long long>(ref_ns / 1000), s->hhash.c_str(), ref_ns != 0 ? 1 : 0,
      static_cast<unsigned long long>(hw_ns), phc, static_cast<unsigned long long>(wr_id), op, imm,
      qp);
  if (n <= 0) return;
  std::lock_guard<std::mutex> lock(s->mu);
  s->buf.append(line, static_cast<std::size_t>(n));
  if (s->buf.size() >= 256 * 1024) s->flush_locked();
}

// Which PHC hardware-stamps this context's completions (the clock_id dc_timesync keys its remap on).
// Resolved once per CQ via sysfs + one ethtool ioctl, never on the poll path. -1 if unknown.
int phc_of_context(struct ibv_context* ctx) {
  if (ctx == nullptr || ctx->device == nullptr) return -1;
  static const char* (*real_name)(struct ibv_device*) = nullptr;
  if (real_name == nullptr) {
    real_name = (const char* (*)(struct ibv_device*))dlvsym(RTLD_NEXT, "ibv_get_device_name",
                                                            "IBVERBS_1.1");
    if (real_name == nullptr)
      real_name = (const char* (*)(struct ibv_device*))dlsym(RTLD_NEXT, "ibv_get_device_name");
  }
  if (real_name == nullptr) return -1;
  const char* dev = real_name(ctx->device);
  if (dev == nullptr) return -1;
  char dir[256];
  std::snprintf(dir, sizeof(dir), "/sys/class/infiniband/%s/device/net", dev);
  DIR* d = opendir(dir);
  if (d == nullptr) return -1;
  int phc = -1;
  for (struct dirent* e; (e = readdir(d)) != nullptr;) {
    if (e->d_name[0] == '.') continue;
    struct ethtool_ts_info info = {};
    info.cmd = ETHTOOL_GET_TS_INFO;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, e->d_name, IFNAMSIZ - 1);
    ifr.ifr_data = reinterpret_cast<char*>(&info);
    const int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) continue;
    const int rc = ioctl(sock, SIOCETHTOOL, &ifr);
    close(sock);
    if (rc == 0 && info.phc_index >= 0) {
      phc = info.phc_index;
      break;
    }
  }
  closedir(d);
  return phc;
}

struct CqInfo {
  int phc = -1;
  int wallclock = 0;  // 1 = read completion wallclock ns, 0 = raw device tick
};
std::unordered_map<struct ibv_cq*, CqInfo> g_cqs;
std::mutex g_cqs_mu;
thread_local int g_in_bridge = 0;

int (*g_orig_poll_cq)(struct ibv_cq*, int, struct ibv_wc*) = nullptr;
int (*g_orig_post_send)(struct ibv_qp*, struct ibv_send_wr*, struct ibv_send_wr**) = nullptr;

// Bridge for the app's inlined ibv_poll_cq: run the extended poll, read the hw ts, fill the legacy wc.
int poll_cq_bridge(struct ibv_cq* cq, int ne, struct ibv_wc* wc) {
  CqInfo ci;
  {
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    auto it = g_cqs.find(cq);
    if (it == g_cqs.end()) return g_orig_poll_cq != nullptr ? g_orig_poll_cq(cq, ne, wc) : 0;
    ci = it->second;
  }
  struct ibv_cq_ex* cqx = reinterpret_cast<struct ibv_cq_ex*>(cq);  // ibv_cq_ex_to_cq is a cast
  struct ibv_poll_cq_attr attr = {};
  g_in_bridge = 1;
  if (ibv_start_poll(cqx, &attr)) {
    g_in_bridge = 0;
    return 0;
  }
  int i = 0;
  do {
    wc[i].wr_id = cqx->wr_id;
    wc[i].status = cqx->status;
    wc[i].opcode = ibv_wc_read_opcode(cqx);
    wc[i].wc_flags = ibv_wc_read_wc_flags(cqx);
    wc[i].byte_len = ibv_wc_read_byte_len(cqx);
    wc[i].qp_num = ibv_wc_read_qp_num(cqx);
    if (wc[i].wc_flags & IBV_WC_WITH_IMM) wc[i].imm_data = ibv_wc_read_imm_data(cqx);
    const uint64_t hw =
        ci.wallclock ? ibv_wc_read_completion_wallclock_ns(cqx) : ibv_wc_read_completion_ts(cqx);
    const uint32_t imm = (wc[i].wc_flags & IBV_WC_WITH_IMM) ? wc[i].imm_data : 0;
    emit(hw, cqx->wr_id, static_cast<uint32_t>(wc[i].opcode), imm, wc[i].qp_num, ci.phc);
    ++i;
    // Break BEFORE ibv_next_poll: it consumes the next completion, so breaking after would drop it.
    if (i >= ne) break;
  } while (ibv_next_poll(cqx) == 0);
  ibv_end_poll(cqx);
  g_in_bridge = 0;
  return i;
}

// WITH_IMM send marker: a send completion carries no immediate, so emit the wire join key at post
// time (opcode 250) for every *_WITH_IMM WR. Cheap: one opcode check per WR on the post path.
int post_send_hook(struct ibv_qp* qp, struct ibv_send_wr* wr, struct ibv_send_wr** bad) {
  for (struct ibv_send_wr* w = wr; w != nullptr; w = w->next) {
    if (w->opcode == IBV_WR_RDMA_WRITE_WITH_IMM || w->opcode == IBV_WR_SEND_WITH_IMM)
      emit(0, w->wr_id, 250, ntohl(w->imm_data), qp->qp_num, -1);
  }
  return g_orig_post_send != nullptr ? g_orig_post_send(qp, wr, bad) : -1;
}

}  // namespace

// Legacy (versioned, exported) ibv_create_cq -> timestamped extended CQ + poll hijack. The safe path.
extern "C" __attribute__((visibility("default"))) struct ibv_cq* ibv_create_cq(
    struct ibv_context* context, int cqe, void* cq_context, struct ibv_comp_channel* channel,
    int comp_vector) {
  static struct ibv_cq* (*real)(struct ibv_context*, int, void*, struct ibv_comp_channel*, int) =
      nullptr;
  if (real == nullptr)
    real = (struct ibv_cq * (*)(struct ibv_context*, int, void*, struct ibv_comp_channel*, int))
        dlvsym(RTLD_NEXT, "ibv_create_cq", "IBVERBS_1.1");
  if (!hwts_on())
    return real != nullptr ? real(context, cqe, cq_context, channel, comp_vector) : nullptr;
  std::call_once(g_once, sink_init);

  struct ibv_cq_init_attr_ex attr = {};
  attr.cqe = cqe;
  attr.cq_context = cq_context;
  attr.channel = channel;
  attr.comp_vector = comp_vector;
  attr.wc_flags = IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK;

  int wallclock = 1;
  struct ibv_cq_ex* cqx = ibv_create_cq_ex(context, &attr);
  if (cqx == nullptr) {  // no wallclock support -> raw device tick still gives exact same-CQ deltas
    attr.wc_flags = IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;
    cqx = ibv_create_cq_ex(context, &attr);
    wallclock = 0;
  }
  if (cqx == nullptr) {  // device refuses timestamps -> plain CQ, do NOT hijack poll (capture empty)
    fprintf(stderr, "[dc-hwts] WARNING: timestamped CQ upgrade failed; this CQ is not captured\n");
    return real != nullptr ? real(context, cqe, cq_context, channel, comp_vector) : nullptr;
  }

  if (g_orig_poll_cq == nullptr) g_orig_poll_cq = context->ops.poll_cq;
  context->ops.poll_cq = poll_cq_bridge;
  if (g_orig_post_send == nullptr) g_orig_post_send = context->ops.post_send;
  context->ops.post_send = post_send_hook;

  struct ibv_cq* cq = ibv_cq_ex_to_cq(cqx);
  {
    CqInfo ci;
    ci.phc = phc_of_context(context);
    ci.wallclock = wallclock;
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    g_cqs.emplace(cq, ci);
  }
  return cq;
}

// dc_our_cqs is a static destroyed before any library destructor, so drop entries here at teardown.
extern "C" __attribute__((visibility("default"))) int ibv_destroy_cq(struct ibv_cq* cq) {
  static int (*real)(struct ibv_cq*) = nullptr;
  if (real == nullptr) {
    real = (int (*)(struct ibv_cq*))dlvsym(RTLD_NEXT, "ibv_destroy_cq", "IBVERBS_1.1");
    if (real == nullptr) real = (int (*)(struct ibv_cq*))dlsym(RTLD_NEXT, "ibv_destroy_cq");
  }
  {
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    g_cqs.erase(cq);
  }
  return real != nullptr ? real(cq) : -1;
}

namespace {
__attribute__((destructor)) void rdma_hwts_fini() {
  Sink* s = g_sink;
  if (s == nullptr) return;
  std::lock_guard<std::mutex> lock(s->mu);
  s->flush_locked();
  if (s->file != nullptr) std::fclose(s->file);
}
}  // namespace
