// RDMA hardware-timestamp capture (LD_PRELOAD, DC_HWTS=1). RDMA poll is kernel-bypass and inlined,
// so neither eBPF nor plain interposition can time the wire; we upgrade each ibv_create_cq CQ to a
// timestamped extended CQ, hijack context->ops.poll_cq, and per completion write a COMPLETE .pfw
// record with the NIC hw ts remapped onto the dc_timesync global epoch (merges with the server
// trace).
//
// The inline ibv_create_cq_ex ops-table hook is deliberately omitted (it segfaulted apps in
// ibv_modify_qp by substituting the CQ), so an app building its CQ only via ibv_create_cq_ex is
// uncaptured. Send posts are marked opcode 250 (legacy ibv_post_send via post_send_hook; modern
// ibv_wr_send via the guarded create_qp_ex ops hook, opt-in DC_HWTS_POSTHOOK), and the ibv_wr
// doorbell is marked opcode 251 (DC_HWTS_DOORBELL). DC_HWTS_SAMPLE=N thins data-plane completions
// (markers exempt) so .pfw stays the one format; DC_HWTS_UPROBE adds the per-completion uprobe
// path.

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

#ifdef DATACRUMBS_DOCA_HWTS
#include "frida-gum.h"  // DOCA fabric CQE hw-ts via inline hook; DOCA-only build (see block at end)
#endif

// Server-uprobe target (opt-in DC_HWTS_UPROBE); defined below, called from the poll bridge.
extern "C" void datacrumbs_rdma_completion(uint64_t, uint64_t, uint32_t, uint32_t, uint32_t);

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

uint64_t mono_ns() {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
}

bool env_flag(const char* name) {
  const char* e = std::getenv(name);
  return e != nullptr && *e != '\0' && e[0] != '0';
}
bool uprobe_on() {
  static const bool v = env_flag("DC_HWTS_UPROBE");
  return v;
}
bool posthook_on() {
  static const bool v = env_flag("DC_HWTS_POSTHOOK");
  return v;
}
bool doorbell_on() {
  static const bool v = env_flag("DC_HWTS_DOORBELL");
  return v;
}

// DC_HWTS_SAMPLE=N emits 1-in-N data-plane completions so .pfw stays cheap and viewable on a
// firehose (millions/s); markers (opcode 250/251) are join keys and are never sampled out. 1 =
// every event.
int sample_n() {
  static const int v = [] {
    const char* e = std::getenv("DC_HWTS_SAMPLE");
    const int n = (e != nullptr && *e != '\0') ? std::atoi(e) : 1;
    return n < 1 ? 1 : n;
  }();
  return v;
}
thread_local unsigned long long g_sample_ctr = 0;

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
    case IBV_WC_SEND:
      return "rdma_send";
    case IBV_WC_RECV:
      return "rdma_recv";
    case IBV_WC_RECV_RDMA_WITH_IMM:
      return "rdma_recv_imm";
    case IBV_WC_RDMA_WRITE:
      return "rdma_write";
    case IBV_WC_RDMA_READ:
      return "rdma_read";
    case 250:
      return "rdma_post";  // send-post marker (cpu time)
    case 251:
      return "rdma_doorbell";  // ibv_wr_complete doorbell marker (cpu time)
    case 260:
      return "doca_send";  // DOCA CQE (mlx5 op 0)
    case 261:
      return "doca_recv";  // DOCA CQE (mlx5 op 2/3)
    default:
      return "rdma_completion";
  }
}

// Write one completion record. ref_ns = global-epoch ns (0 if unaligned); raw_ns = the original
// device timestamp, kept in args so the mapping is auditable/reversible. phc is recorded for
// context.
void emit_record(uint64_t ref_ns, uint64_t raw_ns, uint64_t wr_id, uint32_t op, uint32_t imm,
                 uint32_t qp, int phc) {
  Sink* s = g_sink;
  if (s == nullptr) return;
  if (op != 250 && op != 251) {  // markers are join keys, never sampled out
    const int nth = sample_n();
    if (nth > 1 && (g_sample_ctr++ % static_cast<unsigned>(nth)) != 0) return;
  }
  char line[640];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"rdma_hwts","type":"rdma","pid":%ld,"tid":%d,"ts":%llu,"dur":0,"ph":1,"args":{"hhash":"%s","aligned":%d,"raw_ns":%llu,"phc":%d,"wr_id":%llu,"opcode":%u,"imm":%u,"qp":%u}})"
      "\n",
      static_cast<unsigned long long>(s->id.fetch_add(1)), opcode_name(op), tid(), getpid(),
      static_cast<unsigned long long>(ref_ns / 1000), s->hhash.c_str(), ref_ns != 0 ? 1 : 0,
      static_cast<unsigned long long>(raw_ns), phc, static_cast<unsigned long long>(wr_id), op, imm,
      qp);
  if (n <= 0) return;
  std::lock_guard<std::mutex> lock(s->mu);
  s->buf.append(line, static_cast<std::size_t>(n));
  if (s->buf.size() >= 256 * 1024) s->flush_locked();
}

// ibverbs completion: hw is a PHC-domain ns; remap through the per-PHC dc_timesync fit. hw==0 is a
// CPU-time marker (post/doorbell) -> stamp it now on CLOCK_MONOTONIC remapped to the global epoch,
// not ts=0, so the marker lands at the post instant on the shared timeline.
void emit(uint64_t hw_ns, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp, int phc) {
  Sink* s = g_sink;
  if (s == nullptr) return;
  const uint64_t ref = hw_ns != 0 ? s->reader.remap_hw(hw_ns, phc) : s->reader.remap(mono_ns());
  emit_record(ref, hw_ns, wr_id, op, imm, qp, phc);
}

// The PHC that hardware-stamps this ibverbs device's completions (the clock_id dc_timesync keys its
// remap on): the first netdev under the device that reports a phc_index. -1 if unknown.
int phc_of_ibdev(const char* dev) {
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

// Same, resolved once per CQ via the ibv_context's device name (off the poll path).
int phc_of_context(struct ibv_context* ctx) {
  if (ctx == nullptr || ctx->device == nullptr) return -1;
  static const char* (*real_name)(struct ibv_device*) = nullptr;
  if (real_name == nullptr) {
    real_name = (const char* (*)(struct ibv_device*))dlvsym(RTLD_NEXT, "ibv_get_device_name",
                                                            "IBVERBS_1.1");
    if (real_name == nullptr)
      real_name = (const char* (*)(struct ibv_device*))dlsym(RTLD_NEXT, "ibv_get_device_name");
  }
  return real_name != nullptr ? phc_of_ibdev(real_name(ctx->device)) : -1;
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

// Bridge for the app's inlined ibv_poll_cq: run the extended poll, read the hw ts, fill the legacy
// wc.
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
    if (uprobe_on())  // opt-in hot path: a kernel trap per completion, unsafe on bulk data planes
      datacrumbs_rdma_completion(hw, cqx->wr_id, static_cast<uint32_t>(wc[i].opcode), imm,
                                 wc[i].qp_num);
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

// Modern ibv_wr API markers (parallel to post_send_hook, which covers the legacy ibv_post_send).
// wr_id is set on the qp before ibv_wr_send, so it matches the completion's join key; emitted after
// the provider builds the WQE (the app's handoff instant).
void (*g_orig_wr_send)(struct ibv_qp_ex*) = nullptr;
void (*g_orig_wr_send_imm)(struct ibv_qp_ex*, __be32) = nullptr;
int (*g_orig_wr_complete)(struct ibv_qp_ex*) = nullptr;
void (*g_orig_wr_start)(struct ibv_qp_ex*) = nullptr;
struct ibv_qp* (*g_orig_create_qp_ex)(struct ibv_context*, struct ibv_qp_init_attr_ex*) = nullptr;

int wr_complete_hook(struct ibv_qp_ex* qpx);

// mlx5 refills wr_complete during ibv_modify_qp (QP->RTS), clobbering the wrapper we set at qp
// creation, so wr_send fires but wr_complete would not. wr_start runs every transaction after that
// refill, so re-wrap here. All same-config mlx5 QPs share one handler pointer, so the global orig
// is safe. Idempotent: skip if already ours.
void wr_start_hook(struct ibv_qp_ex* qpx) {
  g_orig_wr_start(qpx);
  if (qpx->wr_complete != nullptr && qpx->wr_complete != wr_complete_hook) {
    g_orig_wr_complete = qpx->wr_complete;
    qpx->wr_complete = wr_complete_hook;
  }
}

void wr_send_hook(struct ibv_qp_ex* qpx) {
  g_orig_wr_send(qpx);
  emit(0, qpx->wr_id, 250, 0, qpx->qp_base.qp_num, -1);
}
void wr_send_imm_hook(struct ibv_qp_ex* qpx, __be32 imm) {
  g_orig_wr_send_imm(qpx, imm);
  emit(0, qpx->wr_id, 250, ntohl(imm), qpx->qp_base.qp_num, -1);
}
// Doorbell split (opcode 251): wr_complete rings the doorbell, so this marks the hardware-post
// instant. Emitted BEFORE the ring so the marker precedes the wire. ibv_wr_complete returns void in
// this ABI it returns the batch's status, which we pass through unchanged.
int wr_complete_hook(struct ibv_qp_ex* qpx) {
  emit(0, qpx->wr_id, 251, 0, qpx->qp_base.qp_num, -1);
  return g_orig_wr_complete(qpx);
}

// Provider create_qp_ex, returned unmodified; we only wrap the qp_ex wr_* pointers. Unlike the
// create_cq_ex hook the rewrite dropped, this substitutes nothing, so it cannot corrupt provider
// state (that hook crashed later ibv_modify_qp calls).
struct ibv_qp* create_qp_ex_hook(struct ibv_context* context, struct ibv_qp_init_attr_ex* attr) {
  struct ibv_qp* qp = g_orig_create_qp_ex != nullptr ? g_orig_create_qp_ex(context, attr) : nullptr;
  if (qp == nullptr || attr == nullptr ||
      !(attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS))  // only these carry wr_* pointers
    return qp;
  struct ibv_qp_ex* qpx = ibv_qp_to_qp_ex(qp);
  if (qpx == nullptr) return qp;
  if (posthook_on() && qpx->wr_send != nullptr &&
      (g_orig_wr_send == nullptr || qpx->wr_send == g_orig_wr_send)) {
    if (g_orig_wr_send == nullptr) g_orig_wr_send = qpx->wr_send;
    qpx->wr_send = wr_send_hook;
  }
  if (posthook_on() && qpx->wr_send_imm != nullptr &&
      (g_orig_wr_send_imm == nullptr || qpx->wr_send_imm == g_orig_wr_send_imm)) {
    if (g_orig_wr_send_imm == nullptr) g_orig_wr_send_imm = qpx->wr_send_imm;
    qpx->wr_send_imm = wr_send_imm_hook;
  }
  if (doorbell_on() && qpx->wr_complete != nullptr &&
      (g_orig_wr_complete == nullptr || qpx->wr_complete == g_orig_wr_complete)) {
    if (g_orig_wr_complete == nullptr) g_orig_wr_complete = qpx->wr_complete;
    qpx->wr_complete = wr_complete_hook;
  }
  if (doorbell_on() && qpx->wr_start != nullptr &&
      (g_orig_wr_start == nullptr || qpx->wr_start == g_orig_wr_start)) {
    if (g_orig_wr_start == nullptr) g_orig_wr_start = qpx->wr_start;
    qpx->wr_start = wr_start_hook;
  }
  return qp;
}

// Install the modern-API hooks on this context's ops table. verbs_get_ctx_op validates the
// provider's verbs_context is large enough and the op is set before we touch it, so the write is
// guarded. Called from ibv_create_cq (a context is in hand there and CQ-before-QP is the standard
// order).
void hook_modern_wr_api(struct ibv_context* context) {
  if (!posthook_on() && !doorbell_on()) return;
  struct verbs_context* vctx = verbs_get_ctx_op(context, create_qp_ex);
  if (vctx == nullptr) return;
  if (g_orig_create_qp_ex == nullptr) g_orig_create_qp_ex = vctx->create_qp_ex;
  if (vctx->create_qp_ex == g_orig_create_qp_ex) vctx->create_qp_ex = create_qp_ex_hook;
}

}  // namespace

// Legacy (versioned, exported) ibv_create_cq -> timestamped extended CQ + poll hijack. The safe
// path.
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
  if (cqx ==
      nullptr) {  // device refuses timestamps -> plain CQ, do NOT hijack poll (capture empty)
    fprintf(stderr, "[dc-hwts] WARNING: timestamped CQ upgrade failed; this CQ is not captured\n");
    return real != nullptr ? real(context, cqe, cq_context, channel, comp_vector) : nullptr;
  }

  if (g_orig_poll_cq == nullptr) g_orig_poll_cq = context->ops.poll_cq;
  context->ops.poll_cq = poll_cq_bridge;
  if (g_orig_post_send == nullptr) g_orig_post_send = context->ops.post_send;
  context->ops.post_send = post_send_hook;
  hook_modern_wr_api(context);  // opt-in modern ibv_wr markers + doorbell (no-op unless enabled)

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

// Install the modern ibv_wr markers on every opened device, independent of how the app builds its
// CQ: an app that builds its CQ via the inline ibv_create_cq_ex we cannot hook would be missed if
// we keyed this off ibv_create_cq. Completion capture still needs the legacy ibv_create_cq upgrade;
// these CPU-time send markers do not.
extern "C" __attribute__((visibility("default"))) struct ibv_context* ibv_open_device(
    struct ibv_device* device) {
  static struct ibv_context* (*real)(struct ibv_device*) = nullptr;
  if (real == nullptr) {
    real = (struct ibv_context * (*)(struct ibv_device*))
        dlvsym(RTLD_NEXT, "ibv_open_device", "IBVERBS_1.1");
    if (real == nullptr)
      real = (struct ibv_context * (*)(struct ibv_device*)) dlsym(RTLD_NEXT, "ibv_open_device");
  }
  struct ibv_context* ctx = real != nullptr ? real(device) : nullptr;
  if (ctx != nullptr && hwts_on() && (posthook_on() || doorbell_on())) {
    std::call_once(g_once, sink_init);
    hook_modern_wr_api(ctx);
  }
  return ctx;
}

// Per-completion server-uprobe target (opt-in DC_HWTS_UPROBE): a noinline no-op the server uprobes
// to land each completion in the kernel trace. Hot (a kernel trap per completion); the direct .pfw
// write is the default. The asm keeps the args live so they are readable at the probe site.
extern "C" __attribute__((noinline, visibility("default"))) void datacrumbs_rdma_completion(
    uint64_t hw_ns, uint64_t wr_id, uint32_t opcode, uint32_t imm, uint32_t qp_num) {
  __asm__ __volatile__("" ::"r"(hw_ns), "r"(wr_id), "r"(opcode), "r"(imm), "r"(qp_num) : "memory");
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

#ifdef DATACRUMBS_DOCA_HWTS
// DOCA fabric CQE capture. The DPU<->DPU data fabric is DOCA-RDMA (mlx5 DevX, kernel-bypass) with
// its own hidden CQ, invisible to the ibv_create_cq path above and to any DOCA API. But
// priv_doca_cq_poll_one(cq, out_cqe) copies the raw mlx5 CQE into arg1 and returns 0 on a hit: the
// NIC hw timestamp is at out_cqe+48 (__be64), opcode in the high nibble of byte 63, imm at +36. We
// inline-hook it via frida-gum and feed each completion into the same emit() path (opcode 260/261
// -> doca_send/doca_recv). Opt-in: DC_HWTS=1 + DC_HWTS_DOCA=1. Built only in the DOCA-native
// target.
namespace {

// raw(HCA free-running ns) <-> CLOCK_MONOTONIC anchor for the DOCA device. The CQE ts is the HCA
// free-running clock (hca_core_clock 1GHz -> 1ns/tick), NOT PHC-realtime and NOT readable via
// /dev/ptp unprivileged; but raw and MONOTONIC differ by a near-constant, so raw->mono->global (the
// existing mono remap) aligns it. Re-sampled periodically to bound HCA<->CPU oscillator drift.
struct DocaAnchor {
  struct ibv_context* ctx = nullptr;
  std::atomic<int64_t> raw_minus_mono{0};
  std::atomic<int64_t> at_mono{
      0};  // MONOTONIC ns when raw_minus_mono was sampled (re-anchor timer)
  std::atomic<bool> valid{false};
};
DocaAnchor g_anchor;

// Resolve verbs symbols by DEFAULT version (dlsym RTLD_DEFAULT), never an unversioned link ref,
// which mis-binds against the versioned symbol.
void doca_open_anchor_ctx(const char* dev) {
  auto get_list = (struct ibv_device * *(*)(int*)) dlsym(RTLD_DEFAULT, "ibv_get_device_list");
  auto get_name = (const char* (*)(struct ibv_device*))dlsym(RTLD_DEFAULT, "ibv_get_device_name");
  auto open_dev =
      (struct ibv_context * (*)(struct ibv_device*)) dlsym(RTLD_DEFAULT, "ibv_open_device");
  if (get_list == nullptr || get_name == nullptr || open_dev == nullptr) return;
  int n = 0;
  struct ibv_device** list = get_list(&n);
  if (list == nullptr) return;
  for (int i = 0; i < n; ++i) {
    const char* nm = get_name(list[i]);
    if (nm != nullptr && std::strcmp(nm, dev) == 0) {
      g_anchor.ctx = open_dev(list[i]);
      break;
    }
  }
}

void doca_sample_anchor() {
  if (g_anchor.ctx == nullptr) return;
  struct ibv_values_ex v;
  std::memset(&v, 0, sizeof(v));
  v.comp_mask = IBV_VALUES_MASK_RAW_CLOCK;
  // Bracket the raw read between two MONOTONIC reads and use the midpoint, so the anchor offset is
  // free of the read-latency skew (sub-us). ibv_query_rt_values_ex is a static inline (dispatches
  // through the ctx), so there is no exported symbol to dlsym; the ctx came from the real ibv_open.
  const int64_t m1 = static_cast<int64_t>(mono_ns());
  if (ibv_query_rt_values_ex(g_anchor.ctx, &v) != 0) return;
  const int64_t m2 = static_cast<int64_t>(mono_ns());
  const int64_t raw = static_cast<int64_t>(v.raw_clock.tv_sec) * 1000000000LL + v.raw_clock.tv_nsec;
  g_anchor.raw_minus_mono.store(raw - (m1 + m2) / 2, std::memory_order_relaxed);
  g_anchor.at_mono.store(m2, std::memory_order_relaxed);
  g_anchor.valid.store(true, std::memory_order_relaxed);
}

struct DcDocaCall {
  gpointer cqe;
};
struct _DcDocaListener {
  GObject parent;
};
G_DECLARE_FINAL_TYPE(DcDocaListener, dc_doca_listener, DC, DOCA_LISTENER, GObject)
void dc_doca_listener_iface_init(gpointer g_iface, gpointer data);
G_DEFINE_TYPE_EXTENDED(DcDocaListener, dc_doca_listener, G_TYPE_OBJECT, 0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             dc_doca_listener_iface_init))

void dc_doca_on_enter(GumInvocationListener*, GumInvocationContext* ic) {
  DcDocaCall* d = GUM_IC_GET_INVOCATION_DATA(ic, DcDocaCall);
  d->cqe = gum_invocation_context_get_nth_argument(ic, 1);  // arg1 = out_cqe
}
void dc_doca_on_leave(GumInvocationListener*, GumInvocationContext* ic) {
  if (reinterpret_cast<intptr_t>(gum_invocation_context_get_return_value(ic)) != 0) return;
  DcDocaCall* d = GUM_IC_GET_INVOCATION_DATA(ic, DcDocaCall);
  if (d->cqe == nullptr) return;
  const unsigned char* c = static_cast<const unsigned char*>(d->cqe);
  const uint64_t hw = __builtin_bswap64(*reinterpret_cast<const volatile uint64_t*>(c + 48));
  const uint32_t op = c[63] >> 4;  // 0 = send, 2/3 = recv
  const uint32_t imm = __builtin_bswap32(*reinterpret_cast<const volatile uint32_t*>(c + 36));
  // Prefer the daemon's raw->global fit (drift-free, no local clock work). Fall back to the local
  // raw->mono anchor when the daemon publishes no raw fit (DC_TIMESYNC_RAW_DEV unset). ref=0 when
  // neither is available -> raw_ns is kept unaligned.
  uint64_t ref = 0;
  Sink* s = g_sink;
  if (s != nullptr) {
    ref = s->reader.remap_raw(hw);
    if (ref == 0 && g_anchor.valid.load(std::memory_order_relaxed)) {
      // Time-based re-anchor (not count-based: low-rate DOCA would never re-fire): >50ms bounds the
      // ~1ppm HCA<->CPU drift to <=50ns, so the fallback mapping stays sub-us.
      if (static_cast<int64_t>(mono_ns()) - g_anchor.at_mono.load(std::memory_order_relaxed) >
          50000000LL)
        doca_sample_anchor();
      const int64_t mono =
          static_cast<int64_t>(hw) - g_anchor.raw_minus_mono.load(std::memory_order_relaxed);
      if (mono > 0) ref = s->reader.remap(static_cast<uint64_t>(mono));
    }
  }
  emit_record(ref, hw, 0, op == 0 ? 260 : 261, imm, 0, -1);
}
void dc_doca_listener_iface_init(gpointer g_iface, gpointer) {
  auto* i = static_cast<GumInvocationListenerInterface*>(g_iface);
  i->on_enter = dc_doca_on_enter;
  i->on_leave = dc_doca_on_leave;
}
void dc_doca_listener_class_init(DcDocaListenerClass*) {}
void dc_doca_listener_init(DcDocaListener*) {}

// LD_PRELOAD ctors run after NEEDED libs map, so libdoca_common is present. No-op unless enabled.
__attribute__((constructor)) void dc_doca_install() {
  if (!hwts_on()) return;
  const char* e = std::getenv("DC_HWTS_DOCA");
  if (e == nullptr || *e == '\0' || e[0] == '0') return;
  std::call_once(g_once, sink_init);
  const char* dev = std::getenv("DC_HWTS_DOCA_DEV");  // e.g. mlx5_2; enables global-epoch alignment
  if (dev != nullptr && *dev != '\0') {
    doca_open_anchor_ctx(dev);
    doca_sample_anchor();
  }
  gum_init_embedded();
  gpointer target = reinterpret_cast<gpointer>(
      gum_module_find_export_by_name("libdoca_common.so", "priv_doca_cq_poll_one"));
  if (target == nullptr) {  // internal symbol may not export -> known offset for this build
    GumAddress base = gum_module_find_base_address("libdoca_common.so");
    if (base != 0) target = GSIZE_TO_POINTER(base + 0x57934);
  }
  if (target == nullptr) {
    fprintf(stderr, "[dc-hwts] DC_HWTS_DOCA: priv_doca_cq_poll_one not found\n");
    return;
  }
  GumInterceptor* it = gum_interceptor_obtain();
  GObject* lis = static_cast<GObject*>(g_object_new(dc_doca_listener_get_type(), nullptr));
  gum_interceptor_begin_transaction(it);
  gum_interceptor_attach(it, target, GUM_INVOCATION_LISTENER(lis), nullptr);
  gum_interceptor_end_transaction(it);
}
}  // namespace
#endif  // DATACRUMBS_DOCA_HWTS
