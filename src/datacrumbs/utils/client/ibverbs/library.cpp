// RDMA hardware-timestamp capture (LD_PRELOAD, DC_HWTS=1). RDMA poll is inlined kernel-bypass, so
// this hijacks poll_cq and reads the hardware timestamp already in each completion queue entry,
// remapped onto the global epoch. ibv_create_cq_ex apps get a timestamp flag added to their own
// attributes instead of a substituted CQ; substituting a CQ crashes apps inside ibv_modify_qp.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/ibverbs/library.h>
#include <datacrumbs/utils/client/mlx5_ops.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dirent.h>
#include <dlfcn.h>
#include <infiniband/mlx5dv.h>
#include <infiniband/verbs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/// The real libibverbs entry, resolved by version through its own handle. GOTCHA interposes
/// dlsym and answers a wrapped name with its wrapper, whose wrappee is this interposer: an
/// endless loop when libibverbs loads after the wrap, as it does behind an HDF5 plugin.
template <typename F>
F real_verbs(const char* name) {
  static void* lib = dlopen("libibverbs.so.1", RTLD_LAZY | RTLD_NOLOAD);
  void* p = lib != nullptr ? dlvsym(lib, name, "IBVERBS_1.1") : nullptr;
  if (p == nullptr) p = dlvsym(RTLD_NEXT, name, "IBVERBS_1.1");
  if (p == nullptr) p = dlsym(RTLD_NEXT, name);
  Dl_info info;
  if (p != nullptr && dladdr(p, &info) != 0 && info.dli_fname != nullptr &&
      std::strstr(info.dli_fname, "libdatacrumbs") != nullptr) {
    DC_LOG_ERROR("[ibverbs] %s resolves into %s, not libibverbs; interposer disabled", name,
                 info.dli_fname);
    return nullptr;
  }
  return reinterpret_cast<F>(p);
}

}  // namespace

#ifdef DATACRUMBS_DOCA_HWTS
#include "frida-gum.h"  // DOCA fabric CQE hw-ts via inline hook; DOCA-only build (see block at end)
#endif

// Server-uprobe target (opt-in DC_HWTS_UPROBE). Defined below, called from the poll bridge.
extern "C" void datacrumbs_rdma_completion(uint64_t, uint64_t, uint32_t, uint32_t, uint32_t);

namespace {
// cat groups by library surface, and type names the instrumentation. Declared per-module so each
// module owns its own. Macros, not constants: folded into the format string at compile time,
// avoiding a strlen and copy per record.
#define DC_CAT "IBVERBS"
#define DC_TYPE "ibverbs"
// The task-completion record below is a DOCA one, written here because this is where the
// completion is seen. It must not inherit this module's surface.
constexpr const char* kDocaCategory = "DOCA";
constexpr const char* kDocaTraceType = "doca";

using datacrumbs::client::mono_ns;

bool hwts_on() {
  return datacrumbs::ConfigurationManager::runtime().hwts_enabled;
}

long tid() {
  return datacrumbs::client::self_tid();
}

bool uprobe_on() {
  return datacrumbs::ConfigurationManager::runtime().hwts_uprobe;
}
bool posthook_on() {
  return datacrumbs::ConfigurationManager::runtime().hwts_posthook;
}
bool doorbell_on() {
  return datacrumbs::ConfigurationManager::runtime().hwts_doorbell;
}

// DC_HWTS_SAMPLE=N emits 1-in-N data-plane completions so .pfw stays cheap on a firehose
// (millions/s). Markers (opcode 250/251) are join keys and are never sampled out. 1 = every event.
int sample_n() {
  return datacrumbs::ConfigurationManager::runtime().hwts_sample;
}
thread_local unsigned long long g_sample_ctr = 0;
// Sampled per poll, not per record: a poll writes its drain marker before its completions. A
// per-record counter with an even N would always land on the drain and never on a completion.
thread_local bool g_poll_batch = false;
thread_local bool g_poll_take = true;
// One clock read per poll, shared by its drain marker and its completions' durations. A clock
// read costs about 200 ns on the BlueField cores, so reading it per record would double the
// shim's cost.
thread_local uint64_t g_poll_now = 0;

/// The module's sink, held by the singleton. A type of its own because Singleton keys on the type
/// and every module has a sink of its own, which must not be shared.
struct RdmaSink {
  datacrumbs::client::PfwSink sink{"rdma", DATACRUMBS_ENV_HWTS_OUT};
};

/// Borrowed, so a completion pays no reference counting.
inline datacrumbs::client::PfwSink* sink() {
  RdmaSink* s = datacrumbs::Singleton<RdmaSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}
std::once_flag g_once;

// Defined below. Forward declared here so the table can name each opcode at sink init, ahead of
// where the poll path itself needs it.
const char* opcode_name(uint32_t op);

// Whether a given mlx5 CQE opcode aggregates rather than records, resolved once at sink init into
// a table indexed by op, so the poll path avoids matching a glob per completion. An op beyond the
// table falls back to the module's own mode.
bool g_agg_op[256] = {};

void init_agg_table() {
  const auto& rt = datacrumbs::ConfigurationManager::runtime();
  for (int i = 0; i < 256; ++i) {
    const char* name = opcode_name(static_cast<uint32_t>(i));
    g_agg_op[i] = datacrumbs::ConfigurationManager::mode_for(rt.hwts_mode, rt.hwts_select, name) ==
                  datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE;
  }
}

void sink_init() {
  datacrumbs::Singleton<RdmaSink>::get_instance();
  init_agg_table();
}

/// The work queue entry opcode, distinguishing a send from a write or a read. Generated from the
/// kernel headers into mlx5_ops.h rather than hand written, so an entry cannot silently be
/// mislabeled with the wrong value. Returns nullptr for a value the table does not name.
const char* wqe_opcode_name(uint8_t op) {
  return dc_enum_MLX5_OPCODE(op);
}

// The mlx5 completion-queue-entry opcode nibble is not an ibverbs work-completion opcode: the two
// namespaces both start at 0. Matching against IBV_WC_RECV (1 << 7) here would never fire. Values
// from mlx5dv.h.
const char* opcode_name(uint32_t op) {
  switch (op) {
    case MLX5_CQE_REQ:
      return "rdma_send";
    case MLX5_CQE_RESP_WR_IMM:
      return "rdma_recv_write_imm";
    case MLX5_CQE_RESP_SEND:
      return "rdma_recv";
    case MLX5_CQE_RESP_SEND_IMM:
      return "rdma_recv_imm";
    case MLX5_CQE_RESP_SEND_INV:
      return "rdma_recv_inv";
    case MLX5_CQE_RESIZE_CQ:
      return "cq_resized";
    case MLX5_CQE_NO_PACKET:
      return "rdma_no_packet";
    case MLX5_CQE_SIG_ERR:
      return "rdma_signature_error";
    case MLX5_CQE_REQ_ERR:
      return "rdma_send_error";
    case MLX5_CQE_RESP_ERR:
      return "rdma_recv_error";
    case MLX5_CQE_INVALID:
      return "rdma_invalid_cqe";
    case 250:
      return "rdma_post";  // send-post marker (cpu time)
    case 251:
      return "rdma_doorbell";  // ibv_wr_complete doorbell marker (cpu time)
    case 253:
      return "cq_arm";  // req_notify_cq (cpu time)
    case 254:
      return "cq_wake";  // get_cq_event (cpu time)
    case 255:
      return "cq_drain";  // poll_cq returning >0 (cpu time)
    case 260:
      return "doca_send";  // DOCA CQE (mlx5 op 0)
    case 261:
      return "doca_recv";  // DOCA CQE (mlx5 op 2/3)
    default:
      return "rdma_completion";
  }
}

// `wqe` (the CQE's per-queue sequence number) is the only per-message identity a CQE
// carries: wr_id lives in the WQE, not the completion, so the DOCA path has none.
// Posts are keyed by queue pair plus wr_id, since two queue pairs commonly reuse the
// same wr_id. Bounded and self-evicting: an unbounded map in someone else's process is worse.
constexpr std::size_t kMaxPending = 4096;
std::unordered_map<uint64_t, uint64_t> g_posted;  // (qp << 32 | wr_id low) -> monotonic ns
std::mutex g_posted_mu;

inline uint64_t post_key(uint32_t qp, uint64_t wr_id) {
  return (static_cast<uint64_t>(qp) << 32) ^ (wr_id & 0xffffffffULL);
}

void note_post(uint32_t qp, uint64_t wr_id) {
  std::lock_guard<std::mutex> lock(g_posted_mu);
  if (g_posted.size() >= kMaxPending) g_posted.clear();  // cheaper than an LRU, and bounded
  g_posted[post_key(qp, wr_id)] = mono_ns();
}

// Returns the post time and forgets it, so a repeated wr_id cannot match an old post.
uint64_t take_post(uint32_t qp, uint64_t wr_id) {
  std::lock_guard<std::mutex> lock(g_posted_mu);
  auto it = g_posted.find(post_key(qp, wr_id));
  if (it == g_posted.end()) return 0;
  const uint64_t t = it->second;
  g_posted.erase(it);
  return t;
}

void emit_record(uint64_t ref_ns, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp, int phc,
                 uint32_t wqe = 0, uint32_t count = 0, uint32_t sq_pi = 0, uint32_t bytes = 0,
                 const char* wqe_op = "", uint8_t wqe_opcode_raw = 0xff) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  const bool is_marker = (op == 250 || op == 251 || op == 252);
  const bool is_poll = (op >= 253 && op <= 255);
  if (!is_marker && op != 253 && op != 254) {
    if (g_poll_batch) {
      if (!g_poll_take) return;
    } else {
      const int nth = sample_n();
      if (nth > 1 && (g_sample_ctr++ % static_cast<unsigned>(nth)) != 0) return;
    }
  }

  // A completed post becomes an interval; anything else stays a point, since a zero-duration
  // COMPLETE record would be indistinguishable from "duration unknown".
  // Only requester completions get one: a receive's post-to-completion span measures idle
  // wait, not service time, and would corrupt latency if merged with sends.

  // mlx5dv.h: op 0 is a requester completion, 1 to 4 are the responder forms.
  const bool responder = (op >= 1 && op <= 4);
  uint64_t dur_ns = 0;
  unsigned char ph = 2;  // point
  if (!is_marker && !is_poll && !responder) {
    const uint64_t posted = take_post(qp, wr_id);
    if (posted != 0) {
      const uint64_t now = g_poll_batch && g_poll_now != 0 ? g_poll_now : mono_ns();
      dur_ns = now > posted ? now - posted : 0;
      ph = 1;  // COMPLETE, with a duration that was measured rather than assumed
    }
  }

  // cat is the role and type is the stack, matching the server's own convention. The tool that
  // wrote the record is provenance and lives in args. Argument keys are namespaced by the layer
  // that produced them so a record carrying fields from two layers cannot collide.
  const bool aggregate = op < 256 ? g_agg_op[op]
                                  : datacrumbs::ConfigurationManager::runtime().hwts_mode ==
                                        datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE;
  if (aggregate) {
    // bytes and count are the only quantities this record shape carries beyond duration: cqe.bytes
    // and ibv.count above. Everything else (wr_id, qp, opcode, wqe, sq_pi) is an identity, and
    // summing an identity is meaningless.
    datacrumbs::client::NumArg nums[2];
    nums[0].key = "cqe.bytes";
    nums[0].kind = datacrumbs::client::NumKind::UINT;
    nums[0].u = bytes;
    nums[1].key = "ibv.count";
    nums[1].kind = datacrumbs::client::NumKind::UINT;
    nums[1].u = count;
    const datacrumbs::client::CatArg cats[1] = {{"cqe.clock", ref_ns != 0 ? "global" : "software"}};
    // Bucketed by when the completion was observed, not by ref_ns: ref_ns is already on the global
    // timeline and may be a hardware time from before this poll, and the sink remaps what it is
    // given. At millisecond buckets the two agree except across a poll that spans a boundary.
    s->aggregate(opcode_name(op), DC_CAT, DC_TYPE, mono_ns(), dur_ns, nums, 2, cats, 1);
    return;
  }

  // A fixed-size copy into the thread's ring; the write worker formats it, keeping formatting off
  // the app's own thread. ref_ns is already on the global axis, so the record is marked as such
  // and the writer leaves it alone.
  datacrumbs::client::AggSite* site = s->site_cached(opcode_name(op), DC_CAT, DC_TYPE, "rdma_hwts");
  if (site == nullptr) return;
  datacrumbs::client::NumArg a[12]{};
  int n = 0;
  auto put_u = [&](const char* key, unsigned long long v) {
    a[n].key = key;
    a[n].kind = datacrumbs::client::NumKind::UINT;
    a[n].u = v;
    ++n;
  };
  put_u("ibv.aligned", ref_ns != 0 ? 1 : 0);
  a[n].key = "cqe.phc";
  a[n].kind = datacrumbs::client::NumKind::INT;
  a[n].i = phc;
  ++n;
  put_u("ibv.wr_id", wr_id);
  put_u("ibv.opcode", op);
  put_u("ibv.imm", imm);
  put_u("ibv.qp", qp);
  put_u("mlx5.wqe", wqe);
  if (ph == 2) put_u("ibv.count", count);
  put_u("mlx5.sq_pi", sq_pi);
  put_u("cqe.bytes", bytes);
  a[n].key = "mlx5.op";
  a[n].kind = datacrumbs::client::NumKind::STR;
  std::strncpy(a[n].s, wqe_op != nullptr ? wqe_op : "", sizeof(a[n].s) - 1);
  ++n;
  put_u("mlx5.op_raw", wqe_opcode_raw);
  s->record_ex(site, ref_ns, dur_ns, a, n, ph, true);
}

// hw is the CQE's raw HCA cycle counter, not a PHC-domain reading. remap_hw expects a PHC-domain
// reading and gives wrong results on a raw counter, so use remap_raw here. hw==0 means a CPU-time
// marker (post/doorbell), stamped via CLOCK_MONOTONIC remapped to the global epoch so it lands at
// the post instant, not ts=0.
uint8_t sq_wqe_opcode(uint32_t qp_num, uint32_t wqe_counter, uint32_t pi);

// Absent, as distinct from zero. Index 0 is the first entry of a send queue and a valid producer
// position after a wrap, so using 0 to mean "not supplied" drops the first completion of every
// queue pair: the opcode of the very first send silently never decodes.
constexpr uint32_t kNoWqe = UINT32_MAX;

// cpu_ns: the marker's own instant when the caller took it before the provider call, so the
// record write never sits inside the span the marker bounds. 0 means now.
void emit(uint64_t hw_ns, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp, int phc,
          uint32_t sq_pi = kNoWqe, uint32_t bytes = 0, uint32_t wqe = kNoWqe, uint64_t cpu_ns = 0) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  const uint64_t ref = hw_ns != 0 ? s->clock().remap_raw(hw_ns)
                                  : s->clock().remap(cpu_ns != 0 ? cpu_ns : mono_ns());
  const char* wqe_op = "";
  uint8_t wqe_opcode_raw = 0xff;
  // Only a requester completion retired a send-queue entry. A responder one did not.
  if (op == MLX5_CQE_REQ && wqe != kNoWqe && sq_pi != kNoWqe) {
    wqe_opcode_raw = sq_wqe_opcode(qp, wqe, sq_pi);
    const char* n = wqe_opcode_name(wqe_opcode_raw);
    if (n != nullptr) wqe_op = n;
  }
  emit_record(ref, wr_id, op, imm, qp, phc, wqe == kNoWqe ? 0 : wqe, 0, sq_pi == kNoWqe ? 0 : sq_pi,
              bytes, wqe_op, wqe_opcode_raw);
}

// The send queue opcode, recorded where the post happened rather than where it completed. Named
// for the op itself, not for "a post occurred," so one series is one operation and the role stays
// in cat. Carries the queue pair and work request id so it can be joined to the completion.
void emit_post_op(uint32_t qp, uint64_t wr_id, const char* op, unsigned wr_opcode) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  // op is a literal from the opcode table, so its address keys the site cache.
  datacrumbs::client::AggSite* site = s->site_cached(op, DC_CAT, DC_TYPE, "rdma_hwts");
  if (site == nullptr) return;
  datacrumbs::client::NumArg a[3]{};
  a[0].key = "ibv.qp";
  a[0].kind = datacrumbs::client::NumKind::UINT;
  a[0].u = qp;
  a[1].key = "ibv.wr_id";
  a[1].kind = datacrumbs::client::NumKind::UINT;
  a[1].u = wr_id;
  a[2].key = "ibv.wr_opcode";
  a[2].kind = datacrumbs::client::NumKind::UINT;
  a[2].u = wr_opcode;
  s->record_ex(site, s->clock().remap(mono_ns()), 0, a, 3, 2, true);
}

// The local-to-remote queue-pair mapping, taken where the app supplies it. This is the join key
// between two nodes' traces: a send on one side and its completion on the other carry only their
// own local qp numbers, so without this pairing they cannot be matched. Emitted once per connect,
// so it gets its own record shape rather than adding a field every completion would carry.
void emit_connect(uint32_t qp, uint32_t dest_qp) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"qp_connect","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"ph":2,"args":{"hhash":"%s","ibv.qp":%u,"ibv.dest_qp":%u,"tool":"rdma_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()),
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(s->clock().remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS),
      s->hhash().c_str(), qp, dest_qp);
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

// Poll-lifecycle point: arm, wake, or drain. All are CPU-time events, stamped now and remapped
// like any other marker. Separating them distinguishes a wakeup-per-completion loop from an
// amortised arm/drain/re-arm one, since otherwise both produce the same trace. @p count is the
// completions a drain returned, 0 for arm and wake.
void emit_poll(uint32_t op, uint32_t qp, uint32_t count, uint64_t cpu_ns = 0) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  emit_record(s->clock().remap(cpu_ns != 0 ? cpu_ns : mono_ns()), 0, op, 0, qp, -1, 0, count);
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
    // Skipped rather than truncated: a truncated name is a different, existing interface, so the
    // ioctl would answer about the wrong device instead of failing.
    const size_t name_len = strnlen(e->d_name, sizeof(ifr.ifr_name));
    if (name_len >= sizeof(ifr.ifr_name)) continue;
    memcpy(ifr.ifr_name, e->d_name, name_len + 1);
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
  if (real_name == nullptr)
    real_name = real_verbs<const char* (*)(struct ibv_device*)>("ibv_get_device_name");
  return real_name != nullptr ? phc_of_ibdev(real_name(ctx->device)) : -1;
}

struct CqInfo {
  int phc = -1;
  int wallclock = 0;  // 1 = read completion wallclock ns, 0 = raw device tick
  // The completion queue ring, taken through mlx5dv_init_obj. Hardware writes a timestamp into
  // every entry whether or not anything asked for one, so reading the ring needs no substituted CQ
  // and no added flags on the caller's attributes.
  const unsigned char* ring = nullptr;
  unsigned cqe_cnt = 0;
  unsigned cqe_size = 0;
  unsigned long long read_ci = 0;  // our own cursor, advanced by what the provider consumed
};

// The hardware timestamp inside a completion queue entry, at byte 0x30, big endian.
inline uint64_t cqe_timestamp(const unsigned char* e) {
  return __builtin_bswap64(*reinterpret_cast<const volatile uint64_t*>(e + 0x30));
}

// Send-queue index of the retired work queue entry, at 0x3c, big endian. This is the consumer side
// of the doorbell producer counter; without it, sq_pi has nothing to subtract from and queue depth
// stays uncomputable.
inline uint32_t cqe_wqe(const unsigned char* e) {
  return (static_cast<uint32_t>(e[0x3c]) << 8) | static_cast<uint32_t>(e[0x3d]);
}

// Bytes transferred, at 0x2c, big endian. Latency without size is uninterpretable: a slow
// completion and a large one look the same. Read bytewise because the field is not 4-byte aligned
// in the entry.
inline uint32_t cqe_bytes(const unsigned char* e) {
  return (static_cast<uint32_t>(e[0x2c]) << 24) | (static_cast<uint32_t>(e[0x2d]) << 16) |
         (static_cast<uint32_t>(e[0x2e]) << 8) | static_cast<uint32_t>(e[0x2f]);
}

// mlx5dv.h defines opcodes 0-6 and 12-14. 15 is MLX5_CQE_INVALID, and 7-11 are reserved. Bit n set
// means n is a real completion.
constexpr uint16_t kCqeOpcodeSet = 0x707f;

// Validity is checked with the owner bit against the consumer index, never a count: assuming the
// provider consumed exactly what it last returned can drift, producing duplicate records and
// reading zeroed slots. The owner bit is hardware-written and independent of consumption, so a
// passive reader can track it alone.
int collect_cqes(CqInfo& info, const unsigned char** out, int want) {
  const unsigned mask = info.cqe_cnt - 1;
  int found = 0;
  while (found < want) {
    const unsigned char* e = info.ring + (info.read_ci & mask) * info.cqe_size;
    const uint8_t op_own = e[info.cqe_size - 1];
    const uint8_t op = static_cast<uint8_t>(op_own >> 4);
    if (((kCqeOpcodeSet >> op) & 1u) == 0) break;  // unwritten or reserved
    const uint8_t phase = (info.read_ci & info.cqe_cnt) != 0 ? 1 : 0;
    if ((op_own & 1u) != phase) break;  // not yet this lap
    out[found++] = e;
    ++info.read_ci;
  }
  return found;
}

std::unordered_map<struct ibv_cq*, CqInfo> g_cqs;
std::mutex g_cqs_mu;

// mlx5dv_init_obj cannot be linked here: the cross sysroot carries no rdma-core libraries, so this
// shim resolves it at run time. It also cannot be reached via RTLD_NEXT or RTLD_DEFAULT, because
// libibverbs dlopens the provider privately and its symbols never enter the global scope. Opening
// the provider by name reaches the copy already mapped, with no added build dependency.
int (*resolve_init_obj())(struct mlx5dv_obj*, uint64_t) {
  static int (*init_obj)(struct mlx5dv_obj*, uint64_t) = nullptr;
  static bool resolved = false;
  if (!resolved) {
    resolved = true;
    void* h = dlopen("libmlx5.so.1", RTLD_LAZY | RTLD_NOLOAD);
    if (h == nullptr) h = dlopen("libmlx5.so.1", RTLD_LAZY);
    if (h != nullptr) init_obj = (int (*)(struct mlx5dv_obj*, uint64_t))dlsym(h, "mlx5dv_init_obj");
    if (init_obj == nullptr) DC_LOG_WARN("[hwts] mlx5dv_init_obj unavailable; rings not read");
  }
  return init_obj;
}

// Register a queue without changing it. Both create hooks land here, so there is one decoder rather
// than one per entry point.
void register_cq(struct ibv_context* context, struct ibv_cq* cq, int wallclock) {
  if (cq == nullptr) return;
  // No thread of datacrumbs or its client may appear in a trace: checked once, here, at creation,
  // so a CQ a tracer thread makes for its own bookkeeping is never registered and never scanned.
  if (datacrumbs::client::tracer_thread_active()) return;
  CqInfo info{phc_of_context(context), wallclock, nullptr, 0, 0};
  struct mlx5dv_cq dv = {};
  struct mlx5dv_obj obj = {};
  obj.cq.in = cq;
  obj.cq.out = &dv;
  auto* init_obj = resolve_init_obj();
  if (init_obj != nullptr && init_obj(&obj, MLX5DV_OBJ_CQ) == 0) {
    info.ring = static_cast<const unsigned char*>(dv.buf);
    info.cqe_cnt = dv.cqe_cnt;
    info.cqe_size = dv.cqe_size;
  }
  std::lock_guard<std::mutex> lock(g_cqs_mu);
  g_cqs[cq] = info;
}
// Send-queue ring, for queue occupancy. The doorbell record holds the producer counter the
// provider last rang. A completion carries the consumer side in its wqe_counter, and the pair is
// what makes depth observable: without it a backed-up queue and an idle one look the same. Read
// only, one load per post.
struct SqInfo {
  const volatile uint32_t* dbrec;
  const unsigned char* buf;
  uint32_t wqe_cnt;
  uint32_t stride;
};
std::unordered_map<uint32_t, SqInfo> g_qps;  // keyed by qp_num: that is all a CQE carries
std::mutex g_qps_mu;

// Bumped when a QP is destroyed, so the per-thread caches below re-resolve instead of dereferencing
// a doorbell record that has been freed and possibly reallocated at the same address.
std::atomic<uint32_t> g_qp_gen{0};

// Lazily registered on first post: the legacy create path is not hooked, and a QP that never
// posts needs no ring. Register happens on post, where the ibv_qp* is in hand. Reads later are by
// qp number, because that is all a completion carries.
void register_sq(struct ibv_qp* qp) {
  if (qp == nullptr) return;
  std::lock_guard<std::mutex> lock(g_qps_mu);
  if (g_qps.count(qp->qp_num) != 0) return;
  SqInfo info{nullptr, nullptr, 0, 0};
  struct mlx5dv_qp dv = {};
  struct mlx5dv_obj obj = {};
  obj.qp.in = qp;
  obj.qp.out = &dv;
  auto* init_obj = resolve_init_obj();
  if (init_obj != nullptr && init_obj(&obj, MLX5DV_OBJ_QP) == 0) {
    info.dbrec = dv.dbrec;
    info.buf = static_cast<const unsigned char*>(dv.sq.buf);
    info.wqe_cnt = dv.sq.wqe_cnt;
    info.stride = dv.sq.stride;
  }
  g_qps[qp->qp_num] = info;
}

// A CQE never carries the opcode; wqe_counter indexes the send queue, whose
// mlx5_wqe_ctrl_seg holds opmod_idx_opcode in its first big-endian word, low byte.
// Only sound while that entry is still the one that completed: the ring is reused,
// and an outstanding depth of a full ring or more means it already was. Returns 0xff then.
uint8_t sq_wqe_opcode(uint32_t qp_num, uint32_t wqe_counter, uint32_t pi) {
  SqInfo info{nullptr, nullptr, 0, 0};
  {
    std::lock_guard<std::mutex> lock(g_qps_mu);
    auto it = g_qps.find(qp_num);
    if (it == g_qps.end()) return 0xff;
    info = it->second;
  }
  if (info.buf == nullptr || info.wqe_cnt == 0 || info.stride == 0) return 0xff;
  if (((pi - wqe_counter) & 0xffff) >= info.wqe_cnt) return 0xff;
  const unsigned char* wqe = info.buf + (wqe_counter & (info.wqe_cnt - 1)) * info.stride;
  return static_cast<uint8_t>(__builtin_bswap32(*reinterpret_cast<const volatile uint32_t*>(wqe)) &
                              0xff);
}

// The producer counter for @p qp_num right now, or kNoWqe if that queue was never registered.
// Cached per thread instead of locking every post, which would serialise the send path being
// measured, since a thread mostly reposts to the same QP. Read at completion time so it pairs
// with the CQE's own wqe_counter.
uint32_t sq_producer(uint32_t qp_num) {
  static thread_local uint32_t cached_qp = 0;
  static thread_local const volatile uint32_t* cached_dbrec = nullptr;
  static thread_local uint32_t cached_gen = 0;
  const uint32_t gen = g_qp_gen.load(std::memory_order_relaxed);
  if (qp_num != cached_qp || gen != cached_gen) {
    const volatile uint32_t* dbrec = nullptr;
    {
      std::lock_guard<std::mutex> lock(g_qps_mu);
      auto it = g_qps.find(qp_num);
      if (it != g_qps.end()) dbrec = it->second.dbrec;
    }
    cached_qp = qp_num;
    cached_dbrec = dbrec;
    cached_gen = gen;
  }
  return cached_dbrec != nullptr ? ntohl(cached_dbrec[MLX5_SND_DBR]) : kNoWqe;
}

thread_local int g_in_bridge = 0;

int (*g_orig_poll_cq)(struct ibv_cq*, int, struct ibv_wc*) = nullptr;
int (*g_orig_req_notify_cq)(struct ibv_cq*, int) = nullptr;
int (*g_orig_post_send)(struct ibv_qp*, struct ibv_send_wr*, struct ibv_send_wr**) = nullptr;
int (*g_orig_post_recv)(struct ibv_qp*, struct ibv_recv_wr*, struct ibv_recv_wr**) = nullptr;
int (*g_orig_post_srq_recv)(struct ibv_srq*, struct ibv_recv_wr*, struct ibv_recv_wr**) = nullptr;

// Apps built with ibv_create_cq_ex poll through cqx->start_poll/next_poll/end_poll,
// which never reach ops.poll_cq, so bridging that alone misses this path.
// One completion is current between a successful start_poll or next_poll and the next
// call, so the record is emitted at exactly those two points.
int (*g_orig_start_poll)(struct ibv_cq_ex*, struct ibv_poll_cq_attr*) = nullptr;
int (*g_orig_next_poll)(struct ibv_cq_ex*) = nullptr;
void (*g_orig_end_poll)(struct ibv_cq_ex*) = nullptr;

void emit_current(struct ibv_cq_ex* cqx) {
  // The owner-bit scan finds the one newly-valid entry. The extended API supplies the fields it
  // already exposes, but only the timestamp comes from the entry itself, since the caller may
  // never have asked for one, and ibv_wc_read_completion_ts would then be invalid.
  const unsigned char* found[1];
  int got = 0;
  CqInfo info;
  {
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    auto it = g_cqs.find(reinterpret_cast<struct ibv_cq*>(cqx));
    if (it == g_cqs.end() || it->second.ring == nullptr) return;
    got = collect_cqes(it->second, found, 1);
    info = it->second;
  }
  if (got != 1) return;
  const uint32_t flags = ibv_wc_read_wc_flags(cqx);
  const uint32_t imm = (flags & IBV_WC_WITH_IMM) ? ibv_wc_read_imm_data(cqx) : 0;
  emit(cqe_timestamp(found[0]), cqx->wr_id, static_cast<uint32_t>(ibv_wc_read_opcode(cqx)), imm,
       ibv_wc_read_qp_num(cqx), info.phc, sq_producer(ibv_wc_read_qp_num(cqx)), cqe_bytes(found[0]),
       cqe_wqe(found[0]));
}

int start_poll_hook(struct ibv_cq_ex* cqx, struct ibv_poll_cq_attr* attr) {
  const int r = g_orig_start_poll != nullptr ? g_orig_start_poll(cqx, attr) : ENOENT;
  // Re-entrant when poll_cq_bridge drives the extended API itself. It emits on its own path.
  if (r == 0 && !g_in_bridge) emit_current(cqx);
  return r;
}

int next_poll_hook(struct ibv_cq_ex* cqx) {
  const int r = g_orig_next_poll != nullptr ? g_orig_next_poll(cqx) : ENOENT;
  if (r == 0 && !g_in_bridge) emit_current(cqx);
  return r;
}

void end_poll_hook(struct ibv_cq_ex* cqx) {
  if (g_orig_end_poll != nullptr) g_orig_end_poll(cqx);
}

// Bridge for the app's inlined ibv_poll_cq: run the extended poll, read the hw ts, fill the legacy
// wc.
int req_notify_cq_hook(struct ibv_cq* cq, int solicited_only) {
  if (g_orig_req_notify_cq == nullptr) return -1;
  emit_poll(253, 0, 0);
  return g_orig_req_notify_cq(cq, solicited_only);
}

// Bookkeeping for a poll is deferred rather than done where the poll returns, because doing it
// there adds latency between the poll and the app's answer. An empty poll is where the app waits
// on the NIC, so the work of the last non-empty poll and the markers since are done there. A loop
// that never polls empty still pays the same cost, one poll later. The completion queue is deep
// enough that its entries outlive one poll of deferral.
struct PendingPoll {
  struct ibv_cq* cq = nullptr;
  int n = 0;
  uint64_t now = 0;
  struct ibv_wc wc[64];
};
struct PendingMarker {
  uint64_t wr_id;
  uint64_t t;
  uint32_t qp;
  uint32_t imm;
  uint32_t op;
};
thread_local PendingPoll g_pending_poll;
thread_local PendingMarker g_pending_markers[64];
thread_local int g_pending_nmark = 0;

void process_poll(PendingPoll& p) {
  const int n = p.n;
  {
    const int nth = sample_n();
    g_poll_take = nth <= 1 || (g_sample_ctr++ % static_cast<unsigned>(nth)) == 0;
    g_poll_batch = true;
    g_poll_now = g_poll_take ? p.now : 0;
  }
  if (g_poll_take) emit_poll(255, 0, static_cast<uint32_t>(n), g_poll_now);

  const unsigned char* found[64];
  const int want = n < 64 ? n : 64;
  int got = 0;
  CqInfo info;
  {
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    auto it = g_cqs.find(p.cq);
    if (it == g_cqs.end() || it->second.ring == nullptr) {
      g_poll_batch = false;
      return;
    }
    // Always scanned, even for a poll that is sampled out: the scan is what keeps the reader's
    // cursor level with the provider's.
    got = collect_cqes(it->second, found, want);
    info = it->second;
  }
  if (!g_poll_take) {
    g_poll_batch = false;
    return;
  }
  // Position-matching the scan to the work completions only holds when both saw the same number.
  // When they disagree the timestamp is still right, since it comes from the entry itself. The
  // wr_id cannot be trusted then, so it is dropped rather than attached to the wrong record.
  const bool aligned = (got == want);
  const struct ibv_wc* wc = p.wc;
  for (int i = 0; i < got; ++i) {
    const uint32_t imm = aligned && (wc[i].wc_flags & IBV_WC_WITH_IMM) ? wc[i].imm_data : 0;
    const uint64_t id = aligned ? wc[i].wr_id : 0;
    const uint32_t op = static_cast<uint32_t>(found[i][info.cqe_size - 1] >> 4);
    const uint32_t qpn = aligned ? wc[i].qp_num : 0;
    emit(cqe_timestamp(found[i]), id, op, imm, qpn, info.phc, sq_producer(qpn), cqe_bytes(found[i]),
         cqe_wqe(found[i]));
    if (uprobe_on()) datacrumbs_rdma_completion(cqe_timestamp(found[i]), id, op, imm, qpn);
  }
  g_poll_batch = false;
}

// The poll first, then the markers: a marker stashed after a poll was posted after it.
void flush_pending() {
  if (g_pending_poll.n > 0) {
    process_poll(g_pending_poll);
    g_pending_poll.n = 0;
  }
  for (int i = 0; i < g_pending_nmark; ++i) {
    const PendingMarker& m = g_pending_markers[i];
    emit(0, m.wr_id, m.op, m.imm, m.qp, -1, kNoWqe, 0, kNoWqe, m.t);
  }
  g_pending_nmark = 0;
}

void defer_marker(uint32_t op, uint64_t wr_id, uint32_t imm, uint32_t qp, uint64_t t) {
  if (g_pending_nmark == 64) flush_pending();
  g_pending_markers[g_pending_nmark++] = PendingMarker{wr_id, t, qp, imm, op};
}

int poll_cq_bridge(struct ibv_cq* cq, int ne, struct ibv_wc* wc) {
  if (g_orig_poll_cq == nullptr) return 0;
  // The provider polls exactly as it would have. Nothing about the caller's queue or its work
  // completions is altered.
  const int n = g_orig_poll_cq(cq, ne, wc);
  flush_pending();
  if (n <= 0) return n;  // an empty poll is common in a busy loop, and recording it would firehose
  g_pending_poll.cq = cq;
  g_pending_poll.n = n < 64 ? n : 64;
  g_pending_poll.now = mono_ns();
  std::memcpy(g_pending_poll.wc, wc, sizeof(struct ibv_wc) * static_cast<size_t>(g_pending_poll.n));
  return n;
}

// WITH_IMM send marker: a send completion carries no immediate, so emit the wire join key at post
// time (opcode 250) for every *_WITH_IMM WR. Cheap: one opcode check per WR on the post path.
int post_send_hook(struct ibv_qp* qp, struct ibv_send_wr* wr, struct ibv_send_wr** bad) {
  // note_post before the real post: a completion can land the instant the doorbell rings, and a
  // completion that arrives before its post was recorded gets no duration.
  for (struct ibv_send_wr* w = wr; w != nullptr; w = w->next) note_post(qp->qp_num, w->wr_id);
  register_sq(qp);  // the ibv_qp* is only in hand here, and completions carry just a qp number
  // Where this post will start writing. Read before the real call, since the provider advances the
  // producer as it fills entries.
  const uint32_t pi_before = sq_producer(qp->qp_num);
  const uint64_t t = mono_ns();
  const int rc = g_orig_post_send != nullptr ? g_orig_post_send(qp, wr, bad) : -1;
  // The opcode is read here, while the entry is still the one this call wrote. At completion time
  // this is a race the queue can lose: under concurrent posting, the entry may already be
  // overwritten. ibv.wr_opcode is recorded too, from the caller's own race-free work request, so
  // the two can be cross-checked. DC_HWTS_POST_OP=0 disables this.
  const bool post_op = datacrumbs::ConfigurationManager::runtime().hwts_post_op;
  if (post_op && rc == 0 && pi_before != kNoWqe) {
    const char* op = wqe_opcode_name(sq_wqe_opcode(qp->qp_num, pi_before, pi_before + 1));
    emit_post_op(qp->qp_num, wr->wr_id, op != nullptr ? op : "", static_cast<unsigned>(wr->opcode));
  }
  for (struct ibv_send_wr* w = wr; w != nullptr; w = w->next) {
    if (w->opcode == IBV_WR_RDMA_WRITE_WITH_IMM || w->opcode == IBV_WR_SEND_WITH_IMM)
      defer_marker(250, w->wr_id, ntohl(w->imm_data), qp->qp_num, t);
  }
  return rc;
}

// Receive-post markers (opcode 252). Without this, a receive has a completion and no
// post, so its duration is unknowable and a starved receive queue is invisible.
// Both entry points are needed: an app that posts receives through an SRQ
// (ibv_create_srq) would show zero receives if only post_recv were hooked.
int post_recv_hook(struct ibv_qp* qp, struct ibv_recv_wr* wr, struct ibv_recv_wr** bad) {
  const uint64_t t = mono_ns();
  for (struct ibv_recv_wr* w = wr; w != nullptr; w = w->next) {
    note_post(qp->qp_num, w->wr_id);
    defer_marker(252, w->wr_id, 0, qp->qp_num, t);
  }
  return g_orig_post_recv != nullptr ? g_orig_post_recv(qp, wr, bad) : -1;
}

// The SRQ has no queue pair, so there is no qpn to attribute the post to. The completion carries
// one, and the wr_id joins the two.
int post_srq_recv_hook(struct ibv_srq* srq, struct ibv_recv_wr* wr, struct ibv_recv_wr** bad) {
  const uint64_t t = mono_ns();
  for (struct ibv_recv_wr* w = wr; w != nullptr; w = w->next) {
    note_post(0, w->wr_id);  // an SRQ has no queue pair; the completion supplies one, so key on 0
    defer_marker(252, w->wr_id, 0, 0, t);
  }
  return g_orig_post_srq_recv != nullptr ? g_orig_post_srq_recv(srq, wr, bad) : -1;
}

// Modern ibv_wr API markers (parallel to post_send_hook, which covers the legacy ibv_post_send).
// wr_id is set on the qp before ibv_wr_send, so it matches the completion's join key. Emitted
// after the provider builds the WQE, at the app's handoff instant.
void (*g_orig_wr_send)(struct ibv_qp_ex*) = nullptr;
void (*g_orig_wr_send_imm)(struct ibv_qp_ex*, __be32) = nullptr;
int (*g_orig_wr_complete)(struct ibv_qp_ex*) = nullptr;
void (*g_orig_wr_start)(struct ibv_qp_ex*) = nullptr;
struct ibv_qp* (*g_orig_create_qp_ex)(struct ibv_context*, struct ibv_qp_init_attr_ex*) = nullptr;
struct ibv_cq_ex* (*g_orig_create_cq_ex)(struct ibv_context*,
                                         struct ibv_cq_init_attr_ex*) = nullptr;

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
  const uint64_t t = mono_ns();
  g_orig_wr_send(qpx);
  defer_marker(250, qpx->wr_id, 0, qpx->qp_base.qp_num, t);
}
void wr_send_imm_hook(struct ibv_qp_ex* qpx, __be32 imm) {
  const uint64_t t = mono_ns();
  g_orig_wr_send_imm(qpx, imm);
  defer_marker(250, qpx->wr_id, ntohl(imm), qpx->qp_base.qp_num, t);
}
// Doorbell split (opcode 251): wr_complete rings the doorbell, so this marks the hardware-post
// instant. Stamped before the ring so the marker precedes the wire, written after it so the
// write is not inside the wire. ibv_wr_complete normally returns void, but in this ABI it
// returns the batch's status, which is passed through unchanged.
int wr_complete_hook(struct ibv_qp_ex* qpx) {
  register_sq(&qpx->qp_base);
  const uint64_t t = mono_ns();
  const int rc = g_orig_wr_complete(qpx);
  defer_marker(251, qpx->wr_id, 0, qpx->qp_base.qp_num, t);
  return rc;
}

// Provider create_qp_ex, returned unmodified. Only the qp_ex wr_* pointers are wrapped. This
// substitutes nothing, so it cannot corrupt provider state; substituting the CQ itself crashes
// later ibv_modify_qp calls.
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

// ibv_create_cq_ex is static inline with no symbol to interpose; reached via the
// public verbs_get_ctx_op instead, same as the modern WR hooks below.
struct ibv_cq_ex* create_cq_ex_hook(struct ibv_context* context, struct ibv_cq_init_attr_ex* attr) {
  if (g_orig_create_cq_ex == nullptr) return nullptr;
  // The caller's attributes are passed through untouched. Nothing is added to them because nothing
  // needs to be: the timestamp is in the completion queue entry either way.
  struct ibv_cq_ex* cqx = g_orig_create_cq_ex(context, attr);
  if (cqx == nullptr) return nullptr;

  register_cq(context, ibv_cq_ex_to_cq(cqx), 0);
  if (g_orig_poll_cq == nullptr) g_orig_poll_cq = context->ops.poll_cq;
  context->ops.poll_cq = poll_cq_bridge;  // an app polling this CQ the legacy way
  if (g_orig_req_notify_cq == nullptr) g_orig_req_notify_cq = context->ops.req_notify_cq;
  context->ops.req_notify_cq = req_notify_cq_hook;
  if (g_orig_start_poll == nullptr) {
    g_orig_start_poll = cqx->start_poll;
    g_orig_next_poll = cqx->next_poll;
    g_orig_end_poll = cqx->end_poll;
  }
  cqx->start_poll = start_poll_hook;  // and an app polling it the extended way
  cqx->next_poll = next_poll_hook;
  cqx->end_poll = end_poll_hook;
  return cqx;
}

// Install the modern-API hooks on this context's ops table. verbs_get_ctx_op validates the
// provider's verbs_context is large enough and the op is set before this touches it, so the write
// is guarded.

// Capturing extended CQs is ordinary capture, not an optional marker, so it is gated only on
// DC_HWTS and installed separately from the opt-in post/doorbell markers below.
// Hooking is per context, not once per process: the tracer's own DPA anchor opens a device of its
// own, and if that context opens first, the app's context would be left unhooked. Every mlx5
// context shares one provider function, so one saved original serves all.
void hook_cq_ex(struct ibv_context* context) {
  struct verbs_context* vctx = verbs_get_ctx_op(context, create_cq_ex);
  if (vctx == nullptr || vctx->create_cq_ex == create_cq_ex_hook) return;
  if (g_orig_create_cq_ex == nullptr) g_orig_create_cq_ex = vctx->create_cq_ex;
  if (vctx->create_cq_ex != g_orig_create_cq_ex) return;  // another provider's table
  vctx->create_cq_ex = create_cq_ex_hook;
}

void hook_modern_wr_api(struct ibv_context* context) {
  if (!posthook_on() && !doorbell_on()) return;
  struct verbs_context* vctx = verbs_get_ctx_op(context, create_qp_ex);
  if (vctx == nullptr) return;
  if (g_orig_create_qp_ex == nullptr) g_orig_create_qp_ex = vctx->create_qp_ex;
  if (vctx->create_qp_ex == g_orig_create_qp_ex) vctx->create_qp_ex = create_qp_ex_hook;
}

}  // namespace

// Legacy (versioned, exported) ibv_create_cq -> register the queue as built and hijack its poll
// ops. The safe path.
extern "C" __attribute__((visibility("default"))) struct ibv_cq* ibv_create_cq(
    struct ibv_context* context, int cqe, void* cq_context, struct ibv_comp_channel* channel,
    int comp_vector) {
  static struct ibv_cq* (*real)(struct ibv_context*, int, void*, struct ibv_comp_channel*, int) =
      nullptr;
  if (real == nullptr)
    real = real_verbs<struct ibv_cq* (*)(struct ibv_context*, int, void*,
                                         struct ibv_comp_channel*, int)>("ibv_create_cq");
  if (real == nullptr) return nullptr;

  // Register only: substituting an extended CQ for the legacy timestamp flag crashes
  // apps inside ibv_modify_qp, and is unnecessary. Hardware writes the timestamp into
  // every CQE regardless of the flags requested.
  struct ibv_cq* cq = real(context, cqe, cq_context, channel, comp_vector);
  if (cq == nullptr || !hwts_on()) return cq;

  std::call_once(g_once, sink_init);
  register_cq(context, cq, 0);
  if (g_orig_poll_cq == nullptr) g_orig_poll_cq = context->ops.poll_cq;
  context->ops.poll_cq = poll_cq_bridge;
  if (g_orig_req_notify_cq == nullptr) g_orig_req_notify_cq = context->ops.req_notify_cq;
  context->ops.req_notify_cq = req_notify_cq_hook;
  if (g_orig_post_send == nullptr) g_orig_post_send = context->ops.post_send;
  context->ops.post_send = post_send_hook;
  if (g_orig_post_recv == nullptr) g_orig_post_recv = context->ops.post_recv;
  if (context->ops.post_recv != nullptr) context->ops.post_recv = post_recv_hook;
  if (g_orig_post_srq_recv == nullptr) g_orig_post_srq_recv = context->ops.post_srq_recv;
  if (context->ops.post_srq_recv != nullptr) context->ops.post_srq_recv = post_srq_recv_hook;
  return cq;
}

// Wake. Only an event-driven app calls this, and it blocks until the channel fires, so the record
// marks the instant the thread was released rather than any work.
extern "C" __attribute__((visibility("default"))) int ibv_get_cq_event(
    struct ibv_comp_channel* channel, struct ibv_cq** cq, void** cq_context) {
  static int (*real)(struct ibv_comp_channel*, struct ibv_cq**, void**) = nullptr;
  if (real == nullptr)
    real = real_verbs<int (*)(struct ibv_comp_channel*, struct ibv_cq**, void**)>(
        "ibv_get_cq_event");
  if (real == nullptr) return -1;
  const int rc = real(channel, cq, cq_context);
  if (rc == 0) emit_poll(254, 0, 0);
  return rc;
}

// RTR is where the app names the remote queue pair, and it is the only place the pairing is visible
// without asking the device. Emitted before the transition so a failed modify still records what
// was attempted, which is what a connection bug looks like.
extern "C" __attribute__((visibility("default"))) int ibv_modify_qp(struct ibv_qp* qp,
                                                                    struct ibv_qp_attr* attr,
                                                                    int attr_mask) {
  static int (*real)(struct ibv_qp*, struct ibv_qp_attr*, int) = nullptr;
  if (real == nullptr)
    real = real_verbs<int (*)(struct ibv_qp*, struct ibv_qp_attr*, int)>("ibv_modify_qp");
  if (qp != nullptr && attr != nullptr && (attr_mask & IBV_QP_DEST_QPN) != 0)
    emit_connect(qp->qp_num, attr->dest_qp_num);
  return real != nullptr ? real(qp, attr, attr_mask) : -1;
}

// Destroying a QP frees its doorbell record, and the allocator can hand the same address to the
// next QP. Without this the cached pointer would be read after free, and a recycled ibv_qp* would
// look like a cache hit.
extern "C" __attribute__((visibility("default"))) int ibv_destroy_qp(struct ibv_qp* qp) {
  static int (*real)(struct ibv_qp*) = nullptr;
  if (real == nullptr) real = real_verbs<int (*)(struct ibv_qp*)>("ibv_destroy_qp");
  {
    std::lock_guard<std::mutex> lock(g_qps_mu);
    if (qp != nullptr) g_qps.erase(qp->qp_num);
  }
  g_qp_gen.fetch_add(1, std::memory_order_relaxed);
  return real != nullptr ? real(qp) : -1;
}

extern "C" __attribute__((visibility("default"))) int ibv_destroy_cq(struct ibv_cq* cq) {
  static int (*real)(struct ibv_cq*) = nullptr;
  if (real == nullptr) real = real_verbs<int (*)(struct ibv_cq*)>("ibv_destroy_cq");
  flush_pending();  // a deferred poll on this queue reads its ring
  {
    std::lock_guard<std::mutex> lock(g_cqs_mu);
    g_cqs.erase(cq);
  }
  return real != nullptr ? real(cq) : -1;
}

// Install the modern ibv_wr markers on every opened device, independent of how the app builds its
// CQ: an app using the inline ibv_create_cq_ex, which cannot be hooked, would be missed if this
// were keyed off ibv_create_cq instead. Completion capture still needs the legacy ibv_create_cq
// upgrade. These CPU-time send markers do not.
extern "C" __attribute__((visibility("default"))) struct ibv_context* ibv_open_device(
    struct ibv_device* device) {
  static struct ibv_context* (*real)(struct ibv_device*) = nullptr;
  if (real == nullptr) real = real_verbs<struct ibv_context* (*)(struct ibv_device*)>("ibv_open_device");
  struct ibv_context* ctx = real != nullptr ? real(device) : nullptr;
  if (ctx != nullptr && hwts_on()) {
    std::call_once(g_once, sink_init);
    hook_cq_ex(ctx);
    hook_modern_wr_api(ctx);  // no-op unless the post/doorbell markers are enabled
  }
  return ctx;
}

// Per-completion server-uprobe target (opt-in DC_HWTS_UPROBE): a noinline no-op the server uprobes
// to land each completion in the kernel trace. Hot, a kernel trap per completion, so the direct
// .pfw write is the default. The asm keeps the args live so they are readable at the probe site.
extern "C" __attribute__((noinline, visibility("default"))) void datacrumbs_rdma_completion(
    uint64_t hw_ns, uint64_t wr_id, uint32_t opcode, uint32_t imm, uint32_t qp_num) {
  __asm__ __volatile__("" ::"r"(hw_ns), "r"(wr_id), "r"(opcode), "r"(imm), "r"(qp_num) : "memory");
}

namespace {}  // namespace

void datacrumbs::client::ibverbs::fini() {
  datacrumbs::Singleton<RdmaSink>::finalize();  // destroys the sink, which flushes and closes
}

namespace {}  // namespace

#ifdef DATACRUMBS_DOCA_HWTS
// DOCA fabric CQE capture: the DPU<->DPU data fabric is DOCA-RDMA (mlx5 DevX) with its own hidden
// CQ, invisible above and to any DOCA API. priv_doca_cq_poll_one(cq, out_cqe) copies the raw mlx5
// CQE into arg1: hw timestamp at +48 (__be64), opcode in byte 63's high nibble, imm at +36. Hooked
// via frida-gum into the same emit() path (opcode 260/261). Opt-in: DC_HWTS=1 + DC_HWTS_DOCA=1.
namespace {

// raw (HCA free-running ns) <-> CLOCK_MONOTONIC anchor for the DOCA device. The CQE ts is the HCA
// free-running clock (hca_core_clock 1GHz -> 1ns/tick), not PHC-realtime and not readable via
// /dev/ptp unprivileged. raw and MONOTONIC differ by a near-constant, so raw->mono->global (the
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
  // free of the read-latency skew (sub-us). ibv_query_rt_values_ex is a static inline dispatching
  // through the ctx, so there is no exported symbol to dlsym. The ctx came from the real ibv_open.
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
  // mlx5_cqe64: sop_drop_qpn at 56 (QP in the low 24 bits), wqe_counter at 60. Together they give
  // "which queue, which position", so pairing a send with its receive is checkable rather than
  // assumed: a gap or a repeat in the counter shows the pairing slipped.
  const uint32_t qpn =
      __builtin_bswap32(*reinterpret_cast<const volatile uint32_t*>(c + 56)) & 0xffffff;
  const uint32_t wqe = __builtin_bswap16(*reinterpret_cast<const volatile uint16_t*>(c + 60));
  // Prefer the daemon's raw->global fit (drift-free, no local clock work). Fall back to the local
  // raw->mono anchor when the daemon publishes no raw fit (DC_TIMESYNC_RAW_DEV unset). ref=0 when
  // neither is available -> raw_ns is kept unaligned.
  uint64_t ref = 0;
  datacrumbs::client::PfwSink* s = sink();
  if (s != nullptr) {
    ref = s->clock().remap_raw(hw);
    if (ref == 0 && g_anchor.valid.load(std::memory_order_relaxed)) {
      // Time-based re-anchor (not count-based: low-rate DOCA would never re-fire): >50ms bounds the
      // ~1ppm HCA<->CPU drift to <=50ns, so the fallback mapping stays sub-us.
      if (static_cast<int64_t>(mono_ns()) - g_anchor.at_mono.load(std::memory_order_relaxed) >
          50000000LL)
        doca_sample_anchor();
      const int64_t mono =
          static_cast<int64_t>(hw) - g_anchor.raw_minus_mono.load(std::memory_order_relaxed);
      if (mono > 0) ref = s->clock().remap(static_cast<uint64_t>(mono));
    }
  }
  emit_record(ref, 0, op == 0 ? 260 : 261, imm, qpn, -1, wqe);
}
void dc_doca_listener_iface_init(gpointer g_iface, gpointer) {
  auto* i = static_cast<GumInvocationListenerInterface*>(g_iface);
  i->on_enter = dc_doca_on_enter;
  i->on_leave = dc_doca_on_leave;
}
void dc_doca_listener_class_init(DcDocaListenerClass*) {}
void dc_doca_listener_init(DcDocaListener*) {}

// LD_PRELOAD ctors run after NEEDED libs map, so libdoca_common is present. No-op unless enabled.
}  // namespace

void datacrumbs::client::ibverbs::init() {
  if (!hwts_on()) return;
  if (!datacrumbs::ConfigurationManager::runtime().hwts_doca) return;
  std::call_once(g_once, sink_init);
  // e.g. mlx5_2, enables global-epoch alignment
  const std::string& dev = datacrumbs::ConfigurationManager::runtime().hwts_doca_dev;
  if (!dev.empty()) {
    doca_open_anchor_ctx(dev.c_str());
    doca_sample_anchor();
  }
  gum_init_embedded();
  // Resolved through the loader by soname: the loaded library may be versioned (e.g.
  // libdoca_common.so.3.0.0058), so an exact "libdoca_common.so" lookup or dlsym(RTLD_DEFAULT)
  // can both miss it. There is no offset-based fallback: an offset guess could point mid-function
  // and emit confident garbage, worse than emitting nothing. dlopen on an already-mapped file just
  // adds a reference.
  gpointer target = nullptr;
  for (const char* name : {"libdoca_common.so.3", "libdoca_common.so.2", "libdoca_common.so"}) {
    void* h = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
    if (h == nullptr) h = dlopen(name, RTLD_NOW);
    if (h == nullptr) continue;
    target = dlsym(h, "priv_doca_cq_poll_one");
    if (target != nullptr) break;
  }
  if (target == nullptr) {
    // DC_HWTS_DOCA is explicit opt-in, so a miss means the requested capture cannot happen. Die
    // rather than let the run complete and be analysed as if the wire were simply invisible.
    DC_LOG_ERROR(
        "[hwts] DC_HWTS_DOCA=1 but priv_doca_cq_poll_one is unavailable (DOCA build changed?); "
        "refusing to run without the wire timestamps");
    _exit(1);
  }
  GumInterceptor* it = gum_interceptor_obtain();
  GObject* lis = static_cast<GObject*>(g_object_new(dc_doca_listener_get_type(), nullptr));
  gum_interceptor_begin_transaction(it);
  gum_interceptor_attach(it, target, GUM_INVOCATION_LISTENER(lis), nullptr);
  gum_interceptor_end_transaction(it);
}

namespace {}  // namespace

// The CQE carries no task pointer, only a qp and wqe_counter, so pairing a DOCA submit
// with its completion by FIFO order is only sound for one queue draining in order.
// doca_task_free runs with the same pointer that was submitted, giving a real per-task
// interval with no ordering assumption. Types stay opaque so the shim needs no DOCA headers.
namespace {

std::unordered_map<void*, uint64_t> g_tasks;
std::mutex g_tasks_mu;

void note_task(void* task) {
  if (task == nullptr) return;
  std::lock_guard<std::mutex> lock(g_tasks_mu);
  if (g_tasks.size() < 65536) g_tasks[task] = mono_ns();
}

// Duration in microseconds, or 0 if this task's submit was never seen.
uint64_t take_task(void* task) {
  std::lock_guard<std::mutex> lock(g_tasks_mu);
  auto it = g_tasks.find(task);
  if (it == g_tasks.end()) return 0;
  const uint64_t started = it->second;
  g_tasks.erase(it);
  const uint64_t now = mono_ns();
  return now > started ? (now - started) / DATACRUMBS_TIME_DIVISOR_NS : 0;
}

void emit_task(void* task, uint64_t dur_us, int status) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr || dur_us == 0) return;
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"doca_task","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s","doca.task":"%p","doca.status":%d,"tool":"rdma_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()),
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(s->clock().remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS -
                                      dur_us),
      static_cast<unsigned long long>(dur_us), s->hhash().c_str(), task, status);
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

int (*real_task_status)(void*) = nullptr;

}  // namespace

#define DC_DOCA_SUBMIT(fn)                                               \
  extern "C" __attribute__((visibility("default"))) int fn(void* task) { \
    static int (*real)(void*) = nullptr;                                 \
    if (real == nullptr) real = (int (*)(void*))dlsym(RTLD_NEXT, #fn);   \
    note_task(task);                                                     \
    return real != nullptr ? real(task) : -1;                            \
  }

DC_DOCA_SUBMIT(doca_task_submit)
DC_DOCA_SUBMIT(doca_task_try_submit)

#undef DC_DOCA_SUBMIT

// The completion side. Read the status before freeing: after the free the task memory is the
// library's again and reading it is a use-after-free.
extern "C" __attribute__((visibility("default"))) void doca_task_free(void* task) {
  static void (*real)(void*) = nullptr;
  if (real == nullptr) real = (void (*)(void*))dlsym(RTLD_NEXT, "doca_task_free");
  if (real_task_status == nullptr)
    real_task_status = (int (*)(void*))dlsym(RTLD_NEXT, "doca_task_get_status");
  const uint64_t dur = take_task(task);
  const int status = (dur != 0 && real_task_status != nullptr) ? real_task_status(task) : 0;
  emit_task(task, dur, status);
  if (real != nullptr) real(task);
}

#else

// The plain build sets nothing up: this module reads its switch and opens its sink on the first
// interposed call. The entry point still has to exist for the one client constructor to call.
void datacrumbs::client::ibverbs::init() {}

#endif  // DATACRUMBS_DOCA_HWTS
