// SPDX-License-Identifier: MIT

/**
 * @brief Per-op hardware timestamps for the BlueField fixed-function engines.
 * DOCA builds these CQs via mlx5dv_devx_obj_create, not ibv_create_cq, so this hooks CREATE_CQ's
 * buffer name at cq_umem_id (offset 0x58). Completion-only: pair with doca_task_submit for
 * duration.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // dlvsym, used to resolve ibv_get_device_name for the per-CQ PHC lookup
#endif

#include <ctype.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/doca/library.h>
#include <datacrumbs/utils/client/mlx5_ops.h>
#include <datacrumbs/utils/common/background.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dirent.h>
#include <dlfcn.h>
#include <gotcha/gotcha.h>
#include <infiniband/verbs.h>
#include <limits.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <thread>

namespace {
// cat groups by library surface, type names the instrumentation, matching dftracer's
// brahma/posix.cpp convention of a module owning its own labels.
// Macros, not constants: folded into the format string at compile time, they cost nothing where
// a %s argument would cost a strlen and a copy per record.
#define DC_CAT "DOCA"
#define DC_TYPE "doca"

using datacrumbs::client::mono_ns;
using datacrumbs::client::tracer_thread_active;

constexpr uint16_t kCreateCq = 0x0400;
constexpr size_t kCqeSize = 64;
constexpr size_t kTsOffset = 0x30;  // 64-bit hardware timestamp
constexpr size_t kImmOffset = 0x24;  // imm_inval_pkey of struct mlx5_cqe64
constexpr size_t kByteCntOffset = 0x2c;
constexpr size_t kSopDropQpnOffset = 0x38;  // queue number in the low 24 bits
constexpr size_t kWqeCounterOffset = 0x3c;  // index of the work-queue entry that produced this
constexpr size_t kOpOwnOffset = 0x3f;
constexpr uint8_t kCqeReqErr = 0xd;  // a failed op still completes, with no valid timestamp
constexpr uint8_t kCqeRespErr = 0xe;
constexpr uint8_t kCqeResize = 0x5;
// mlx5dv.h defines opcodes 0-6 and 12-14; 15 is MLX5_CQE_INVALID and 7-11 are reserved. Testing
// only for 15 wrongly accepts uninitialised queue memory as a completion. Bit n set means n is
// real.
constexpr uint16_t kCqeOpcodeSet = 0x707f;
constexpr uint8_t kCqeOwnerMask = 0x1;
// CREATE_CQ input layout: cq_umem_id is at 0x58, its valid bit at 0x5c.
// log_cq_size is the authoritative entry count, unlike inferring it from the registration size.
constexpr size_t kCqcLogSizeOffset = 0x1c;
constexpr uint8_t kCqcLogSizeMask = 0x1f;
// First byte of cq_context, holding cqe_sz and the compression enables. Zero means one 64-byte
// CQE per slot. A nonzero value means some other layout, most likely 128-byte CQEs or compressed
// mini-CQEs, which this reader cannot parse. Refuse those rather than emit nonsense.
constexpr size_t kCqcFormatOffset = 0x11;
// The CQ need not start at the registration's base: the command names a byte offset into it, used
// when a provider packs several queues into one registration. The queue may start at an offset
// into the registration; reading from the base runs past the end of the region.
constexpr size_t kCqUmemOffsetOffset = 0x50;
constexpr size_t kCqUmemIdOffset = 0x58;
constexpr size_t kCqUmemValidOffset = 0x5c;
constexpr uint8_t kCqUmemValidBit = 0x80;
constexpr int kMaxCq = 64;
constexpr int kMaxUmem = 256;

bool enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_enabled;
}

// DATACRUMBS_ENGINE_JOIN=0: keep the ring scan (byte counts and hardware timestamps still land,
// per completion) but skip the submit/completion join table, so a collection instrument that only
// needs device-work counts is not paying for per-op names it will not use.
bool join_enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_join_enabled;
}

// DATACRUMBS_ENGINE_SCAN_CACHE=0: re-parse every scanned control segment's data descriptors even
// when its bytes have not changed since the last scan. Diagnostic only, to isolate the rescan
// cache's own cost from the join table's; off by default would cost real throughput for no
// correctness gain, so this stays on unless asked otherwise.
bool scan_cache_enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_scan_cache_enabled;
}

long tid() {
  return datacrumbs::client::self_tid();
}

/// The module's sink, held by the singleton. A type of its own because Singleton keys on the type
/// and every module has a sink of its own, which must not be shared.
struct EngineSink {
  datacrumbs::client::PfwSink sink{"engine", DATACRUMBS_ENV_ENGINE_OUT};
};

/// Borrowed, so a wrapped call pays no reference counting. Null before init and after fini.
inline datacrumbs::client::PfwSink* sink() {
  EngineSink* s = datacrumbs::Singleton<EngineSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}

// GOTCHA rather than defining the symbols and chaining with dlsym: the API tracer wraps these same
// six symbols through GOTCHA, which rewrites the caller's got entry, while a preload definition
// claims the symbol at load. Each then resolved a "real" pointer the other had already redirected,
// and the pair segfaulted whichever order they loaded in.
gotcha_wrappee_handle_t g_h_umem_reg;
gotcha_wrappee_handle_t g_h_umem_reg_ex;
gotcha_wrappee_handle_t g_h_umem_dereg;
gotcha_wrappee_handle_t g_h_obj_create;
gotcha_wrappee_handle_t g_h_task_submit;
gotcha_wrappee_handle_t g_h_pe_progress;

// Slots are claimed and released rather than appended, so a long run reuses them instead of
// walking off the end. kState* is the publication protocol: a reader may only trust a slot's
// fields once it observes kStateReady, which the writer stores last.
constexpr int kStateFree = 0;
constexpr int kStateClaimed = 1;
constexpr int kStateReady = 2;

// Physical positions a 256 KB region (the cap scan_wqe enforces below) can hold, one 64-byte slot
// each. This is a byte-size bound, unrelated to the value a wqe_counter can carry: it sizes the
// per-region rescan cache, keyed by where a control segment sits, not by what it says.
constexpr size_t kMaxScanOffset = 256 * 1024 / 64;

struct Umem {
  std::atomic<int> state{kStateFree};
  /// The device context this registration belongs to. A umem id is unique per context, not per
  /// process, so two contexts each hand out an id 1 and only this tells them apart.
  void* ctx;
  void* obj;
  void* addr;
  size_t size;
  uint32_t id;
  // Consecutive scans that found no engine descriptor, and submits skipped since the last look.
  // Relaxed throughout: a race costs one extra scan of a region, never a wrong record.
  std::atomic<unsigned> empty_scans{0};
  std::atomic<unsigned> skipped{0};
  /// mono_ns() at the start of the last full walk of this region, for the gap diagnostic below.
  std::atomic<uint64_t> last_scan_ns{0};
  /// The control segment's first 8 bytes last seen at each 64-byte position, keyed by physical
  /// offset, not the entry's logical index. The ring is walked in full on every submit and a
  /// consumed entry is never cleared, so without this every rescan re-parses unchanged content.
  /// A position whose bytes have not moved needs nothing redone.
  uint64_t ctrl_sig[kMaxScanOffset] = {};
};
Umem g_umem[kMaxUmem];

struct Cq {
  std::atomic<int> state{kStateFree};
  unsigned char* buf;
  size_t entries;         // always a power of two, see cq_entries()
  size_t ci;              // monotonic consumer index; the lap count drives the owner bit
  // wqe_counter continuity for lap detection, per completion class: an RC queue pair completes
  // its send queue and receive queue on one CQ, and the two counters interleave. Tracking them as
  // one stream makes them look static and turns off lap detection.
  struct CtrTrack {
    uint16_t last = 0;
    // The counter is in work-queue blocks, so one completion advances it by the entry's size,
    // not by one. Two entries read in the same sweep are contiguous by construction; a seam
    // between sweeps is judged against that.
    uint16_t stride = 0;
    bool have = false;
    bool seen_this_sweep = false;
    bool is_static = false;  // host compress CQEs carry a wqe_counter that never advances
  };
  CtrTrack ctr[2];  // [0] requester (send queue), [1] responder (receive queue)
  uint32_t umem_id;
  /// The PHC this CQ's own device hardware-stamps its completions on, resolved from the
  /// mlx5dv_devx_obj_create ctx at creation time. -1 if unresolved.
  int phc = -1;
};
Cq g_cq[kMaxCq];

// What a submit asked the engine to do, from the work-queue entry it wrote. A completion cannot
// answer this: compress, DMA and AES all land as one requester completion. Work goes out as
// MLX5_OPCODE_MMO (0x2f, mlx5dv.h) and the opcode_mod beside it selects the engine: 0x01 DMA,
// 0x03 decompress deflate, 0x06 AES-GCM, 0x07 EC.
struct Wqe {
  /// The queue pair the entry was posted to, control segment bytes 4-6 big-endian (qpn_ds, high 24
  /// bits). The same field wqe_spy.c reads off the wire. A submit index is only unique within one
  /// send queue: two QPs commonly reuse the same wqe_counter, so the join key must carry this too.
  uint32_t qpn;
  uint8_t opcode_mod;
  /// The work request's own opcode, byte 3 of the control segment. A requester completion does not
  /// carry it, which is why an unjoined requester record can name a class but not a verb.
  uint8_t opcode;
  uint64_t src_len;
  uint64_t dst_len;
  /// When this entry was first seen, which is inside the doca_task_submit that posted it. The
  /// engine reports when an operation finished and never when it started, so this is the only
  /// available start, and it is early by the cost of the submit call rather than by the queue wait.
  uint64_t submit_ns;

  /// Deliberately excludes submit_ns: it is when the entry was seen, not part of what the entry
  /// says, and comparing it would make every rescan look like a new submit.
  bool operator==(const Wqe& o) const {
    return qpn == o.qpn && opcode_mod == o.opcode_mod && opcode == o.opcode &&
           src_len == o.src_len && dst_len == o.dst_len;
  }
};
/// Empty scans of one region before it stops being walked, and how often it is looked at again.
constexpr unsigned kEmptyScansBeforeSkip = 4;
constexpr unsigned kRecheckEverySubmits = 4096;

// wqe_counter is a 16-bit hardware producer count (mlx5 PRM), wrapping only at 65536, not bounded
// by the queue depth. The full domain must be trusted; real traffic climbs past a narrower range
// almost immediately, leaving submits unrecorded.
constexpr uint32_t kWqeCounterDomain = 1u << 16;

// Keyed by a hash of (qpn, idx): an index-only table lets two queue pairs collide on one slot,
// corrupting or dropping a join. A mutex-protected map keyed the same way costs too much
// throughput. This plain array, banded by kQpnBands (4), costs one atomic slot with no lock for
// the common case.
constexpr unsigned kQpnBands = 4;
constexpr std::size_t kPendMax = static_cast<std::size_t>(kWqeCounterDomain) * kQpnBands;

struct Pending {
  std::atomic<bool> live{false};
  uint32_t qpn{0};
  Wqe wqe;
};
Pending g_pend[kPendMax];

inline std::size_t pend_slot(uint32_t qpn, uint32_t idx) {
  // Knuth's multiplicative hash (public domain), top bits only: cheap, and it spreads a QP number
  // across the bands well enough that two queues share a band by coincidence, not by construction.
  const uint32_t band = (qpn * 2654435761u) >> 30;  // top 2 bits -> 0..3, matching kQpnBands
  return static_cast<std::size_t>(band) * kWqeCounterDomain + idx;
}

/// Record a submit against its queue pair and entry index, overwriting whatever was there. Returns
/// true if a still-unmatched submit was displaced, which is what @p overwrite counts.
bool put_pending(uint32_t qpn, uint32_t idx, const Wqe& w, bool* overwrite) {
  Pending& slot = g_pend[pend_slot(qpn, idx)];
  if (slot.live.load(std::memory_order_relaxed)) {
    if (slot.qpn == qpn && slot.wqe == w) {
      *overwrite = false;  // the same content at the same key is a rescan, not a new submit
      return false;
    }
    *overwrite = true;
  } else {
    *overwrite = false;
  }
  slot.qpn = qpn;
  slot.wqe = w;
  slot.live.store(true, std::memory_order_release);
  return *overwrite;
}

/// The submit that wrote entry (qpn, idx), if any, taken so a repeated index cannot match twice.
/// A band collision with a different, still-pending queue pair claims (and clears) that entry's
/// slot too; it reads back false here, the same loss an index-only table already accepted for
/// every queue rather than just the ones sharing a band.
bool take_pending(uint32_t qpn, uint32_t idx, Wqe* out) {
  Pending& slot = g_pend[pend_slot(qpn, idx)];
  if (!slot.live.exchange(false, std::memory_order_acquire)) return false;
  if (slot.qpn != qpn) return false;
  *out = slot.wqe;
  return true;
}

/// Slots we could not take, and queues whose layout this reader does not handle. Reported at exit:
/// silently stopping would look identical to a workload that simply made no more queues.
/// Completions whose entry index matched no outstanding submit, and submits that overwrote an
/// index still waiting for one. Both mean a joined record named the wrong operation.
std::atomic<uint64_t> g_join_miss{0};
std::atomic<uint64_t> g_join_overwrite{0};
/// Longest gap seen between two full walks of the same region. Reported at exit so a run with a
/// high miss rate can be checked against whether the scanner was ever scheduled out for long enough
/// to plausibly explain it.
std::atomic<uint64_t> g_max_scan_gap_ns{0};

std::atomic<uint64_t> g_dropped_umem{0};
std::atomic<uint64_t> g_dropped_cq{0};
std::atomic<uint64_t> g_unsupported_cq{0};
std::atomic<uint64_t> g_cq_offset{0};  // CQs that did not start at the registration base
/// RawCqeRing is single-consumer, and more than one thread reaches pop(). Without this guard,
/// completions are emitted twice.
std::atomic_flag g_ring_draining = ATOMIC_FLAG_INIT;
/// The producer side of the same ring. The sweep thread holds it for a whole sweep; the dereg
/// hook on the app thread drains a dying CQ and would otherwise push concurrently. Held per
/// sweep, not per push, so the hot path pays nothing.
std::atomic_flag g_ring_pushing = ATOMIC_FLAG_INIT;

/// Whether any submit has been joined yet. Until one has, the scanner has not synchronised with
/// the queue, so a completion without a submit is for work posted before this process attached
/// rather than work the reader lost. A trace has to say which, or an analysis cannot tell a
/// harmless startup gap from a broken join.
std::atomic<bool> g_joined_any{false};

/// Drain self-timing, behind DC_ENGINE_HWTS_STATS, so the cost of sitting in doca_pe_progress can
/// be quoted rather than assumed.
std::atomic<uint64_t> g_drain_calls{0};
std::atomic<uint64_t> g_drain_ns{0};
std::atomic<uint64_t> g_emitted{0};
// Counted apart from the sweep: writing a record compresses it, so a sweep that emitted looks
// much slower than an empty one for reasons that have nothing to do with a regression.
std::atomic<uint64_t> g_emit_ns{0};

bool stats_enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_stats;
}

/// The PHC dc_timesync keys its remap on: the first netdev under this device that
/// answers ETHTOOL_GET_TS_INFO with a real phc_index.
/// A hardcoded list of device names risks silently naming the wrong device's clock
/// on a host with more than one HCA or a device outside the list.
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

// Resolved once per ibv_context, cached by pointer, at CQ-creation time off the completion path.
// mlx5dv_devx_obj_create's first argument is the same struct ibv_context* the ibverbs API uses.
// The sysroot carries no rdma-core libraries to link against, so the name is read through the
// versioned symbol via dlvsym.
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

/// Name for the engine an MMO work-queue entry selects. No public header defines these values.
/// Work-request opcodes, from the MLX5_OPCODE enum in mlx5dv.h. The control segment packs them as
/// htonl((opmod << 24) | (index << 8) | opcode), so the opcode is byte 3 and the index bytes 1-2.
constexpr uint8_t kOpRdmaWrite = 0x08;
constexpr uint8_t kOpRdmaWriteImm = 0x09;
constexpr uint8_t kOpRdmaRead = 0x10;
constexpr uint8_t kOpAtomicCs = 0x11;
constexpr uint8_t kOpAtomicFa = 0x12;
constexpr uint8_t kOpMmo = 0x2f;

// The kernel's own MLX5_OPCODE_* name, generated from device.h into mlx5_ops.h: the same table
// the ibverbs shim uses, avoiding a hand-written switch that can drift out of sync.
// Names are lowercase, dropping the MLX5_OPCODE_ prefix, matching the engine/cqe names beside them.
// Returns false when the table has no name for @p op.
bool wqe_opcode_name(uint8_t op, char* out, std::size_t n) {
  const char* generated = dc_enum_MLX5_OPCODE(op);
  if (generated == nullptr) return false;
  const char* p = generated;
  if (strncmp(p, "MLX5_OPCODE_", 12) == 0) p += 12;
  std::size_t i = 0;
  for (; p[i] != '\0' && i + 1 < n; ++i)
    out[i] = static_cast<char>(tolower(static_cast<unsigned char>(p[i])));
  out[i] = '\0';
  return true;
}

/// Same table, membership only. scan_wqe calls this on every 64-byte position of a registered
/// region, on every submit, to check if a position merely looks like a control segment. Checking
/// membership first avoids building the name string for a match that turns out false.
bool wqe_opcode_known(uint8_t op) {
  return dc_enum_MLX5_OPCODE(op) != nullptr;
}

/// Which 16-byte segment the data descriptors start at. A remote-address operation puts an raddr
/// segment between the control segment and the data, and an atomic puts an atomic segment after
/// that; reading the data at a fixed offset would take the remote address for a byte count.
unsigned first_data_seg(uint8_t op) {
  switch (op) {
    case kOpRdmaWrite:
    case kOpRdmaWriteImm:
    case kOpRdmaRead:
      return 2;
    case kOpAtomicCs:
    case kOpAtomicFa:
      return 3;
    default:
      return 1;
  }
}

const char* mmo_engine_name(uint8_t opcode_mod) {
  switch (opcode_mod) {
    case 0x01:
      return "dma_memcpy";
    case 0x03:
      return "decompress_deflate";
    case 0x06:
      return "aes_gcm";
    case 0x07:
      return "ec_recover";
    default:
      return nullptr;
  }
}

// Whether a given opcode_mod aggregates, resolved once at sink-open so the completion path reads
// a table instead of matching a glob per completion. Keyed the same way emit() names the record:
// "engine.<name>", or the module's own default mode when the submit was never seen and the name
// cannot be predicted ahead of time.
bool g_agg_engine[256] = {};  // engine.<mmo>, by opcode_mod
bool g_agg_rdma[256] = {};    // rdma.<verb>, by work-request opcode
bool g_agg_cqe[16] = {};      // cqe.<class>, by CQE opcode nibble

const char* cqe_op_name(uint8_t op);  // defined below, beside the other name tables

/// Name a record from what produced it, never from a word meaning "not looked up".
/// An unnamed opcode still identifies the operation: a reader can look 0x14 up in the
/// PRM, and can do nothing with "unknown". Falling back to the completion class was
/// worse: a joined request then read as an unjoined one.
void record_name_for(char* out, std::size_t n, bool joined, const Wqe& w, uint8_t cqe_op) {
  if (joined && w.opcode == kOpMmo) {
    const char* nm = mmo_engine_name(w.opcode_mod);
    if (nm != nullptr)
      std::snprintf(out, n, "engine.%s", nm);
    else
      std::snprintf(out, n, "engine.mod_0x%02x", w.opcode_mod);
    return;
  }
  if (joined) {
    char verb[48];
    if (wqe_opcode_name(w.opcode, verb, sizeof(verb)))
      std::snprintf(out, n, "rdma.%s", verb);
    else
      std::snprintf(out, n, "rdma.op_0x%02x", w.opcode);
    return;
  }
  const char* klass = cqe_op_name(cqe_op);
  if (klass != nullptr)
    std::snprintf(out, n, "cqe.%s", klass);
  else
    std::snprintf(out, n, "cqe.op_0x%x", cqe_op & 0xf);
}

/// Resolve the capture mode for every name this module can emit, keyed the same way the record is
/// named, so a selection can say `rdma.*` or `engine.dma_memcpy` and mean it. Keying only on the
/// engine table would make every RDMA record resolve as engine.unknown, breaking selective
/// aggregation. Resolved once at startup, not matched per record, since the match is a glob.
void init_agg_table() {
  const auto& rt = datacrumbs::ConfigurationManager::runtime();
  auto aggregated = [&rt](const char* name) {
    return datacrumbs::ConfigurationManager::mode_for(rt.engine_mode, rt.engine_select, name) ==
           datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE;
  };
  char namebuf[64];
  Wqe probe{};
  for (int i = 0; i < 256; ++i) {
    probe.opcode = kOpMmo;
    probe.opcode_mod = static_cast<uint8_t>(i);
    record_name_for(namebuf, sizeof(namebuf), true, probe, 0);
    g_agg_engine[i] = aggregated(namebuf);
    probe.opcode = static_cast<uint8_t>(i);
    probe.opcode_mod = 0;
    record_name_for(namebuf, sizeof(namebuf), true, probe, 0);
    g_agg_rdma[i] = aggregated(namebuf);
  }
  for (int i = 0; i < 16; ++i) {
    record_name_for(namebuf, sizeof(namebuf), false, probe, static_cast<uint8_t>(i));
    g_agg_cqe[i] = aggregated(namebuf);
  }
}

/// Name for the mlx5 CQE opcode nibble: the completion class, not the engine operation.
/// Decompress, DMA and AES all complete as req; which engine ran is in the WQE.
/// The mlx5dv.h CQE namespace, not work-request or ibverbs work-completion opcodes;
/// all three start at 0 and mean different things.
const char* cqe_op_name(uint8_t op) {
  switch (op) {
    case 0x0:
      return "req";
    case 0x1:
      return "resp_write_imm";
    case 0x2:
      return "resp_send";
    case 0x3:
      return "resp_send_imm";
    case 0x4:
      return "resp_send_inv";
    case 0x5:
      return "resize_cq";
    case 0x6:
      return "no_packet";
    case 0xc:
      return "sig_err";
    case 0xd:
      return "req_err";
    case 0xe:
      return "resp_err";
    case 0xf:
      return "invalid";
    default:
      return nullptr;
  }
}

/// RECORDS: one JSON line per completion, the original behaviour. AGGREGATE: roll every
/// completion into per-CQ per-window counters and histograms instead. Separate from the generic
/// DATACRUMBS_ENABLE_AGGREGATION/DATACRUMBS_AGGREGATION_TYPE pair, which buckets a wrapped call's
/// duration by name (PfwSink::aggregate) and does not touch how this module counts its own CQEs.
enum class EngineCaptureMode { RECORDS, AGGREGATE };

EngineCaptureMode capture_mode() {
  return datacrumbs::ConfigurationManager::runtime().engine_capture_mode == "aggregate"
             ? EngineCaptureMode::AGGREGATE
             : EngineCaptureMode::RECORDS;
}

unsigned engine_sample_n() {
  return datacrumbs::ConfigurationManager::runtime().engine_sample;
}

unsigned engine_drain_us() {
  return datacrumbs::ConfigurationManager::runtime().engine_drain_us;
}

/// What the hot path (drain(), run from the app's own doca_pe_progress call or the timer drain
/// thread) hands to the background formatter. Plain and trivially copyable on purpose: pushing one
/// is a copy into the ring, nothing else, no string, no allocation, no syscall.
uint64_t be64_at(const unsigned char* p);
uint16_t be16_at(const unsigned char* p);
uint32_t be32_at(const unsigned char* p);

/// One completion as the hardware wrote it, plus when and where it was read. The sweep thread
/// copies the 64 bytes and nothing else; every field decode happens on the format thread. Decoding
/// on the sweep thread is slow enough to make it fall laps behind the ring.
struct RawCqe {
  unsigned char cqe[kCqeSize];
  uint64_t cpu_ns;
  uint8_t cq_idx;
  uint8_t err;  // error completion: its timestamp field is not a clock reading

  uint64_t hw_ns() const { return err ? 0 : be64_at(cqe + kTsOffset); }
  uint32_t byte_cnt() const { return be32_at(cqe + kByteCntOffset); }
  // Meaningful on a receive with immediate; a program that puts a sequence number there gives
  // the trace a per-message key across nodes.
  uint32_t imm() const { return be32_at(cqe + kImmOffset); }
  uint32_t qpn() const { return be32_at(cqe + kSopDropQpnOffset) & 0xffffffu; }
  uint16_t wqe_counter() const { return be16_at(cqe + kWqeCounterOffset); }
  uint8_t opcode() const { return static_cast<uint8_t>(cqe[kOpOwnOffset] >> 4); }
};

constexpr size_t kRingCap = 1u << 16;  // power of two: required by the index math below

/// Bounded SPSC ring, adapted from Dmitry Vyukov's "Bounded MPMC queue" (1024cores.net, public
/// domain). Single producer, single consumer: whoever holds g_ring_pushing pushes, whoever holds
/// g_ring_draining pops. Two indices, no compare-and-swap: a locked multi-producer version costs
/// more per push, and a 4096-entry ring can be lapped by the hardware in 0.7 ms at line rate.
struct RawCqeRing {
  RawCqe cells[kRingCap];
  alignas(64) std::atomic<uint64_t> head{0};  // next slot to write, producer-owned
  alignas(64) std::atomic<uint64_t> tail{0};  // next slot to read, consumer-owned
  uint64_t tail_seen = 0;                     // producer's cached copy of tail
  uint64_t head_seen = 0;                     // consumer's cached copy of head

  void init() {}

  /// Never blocks the caller. A full ring drops the item; the caller counts the drop.
  bool push(const RawCqe& item) {
    const uint64_t h = head.load(std::memory_order_relaxed);
    if (h - tail_seen >= kRingCap) {
      tail_seen = tail.load(std::memory_order_acquire);
      if (h - tail_seen >= kRingCap) return false;  // full
    }
    cells[h & (kRingCap - 1)] = item;
    head.store(h + 1, std::memory_order_release);
    return true;
  }

  bool pop(RawCqe* out) {
    const uint64_t t = tail.load(std::memory_order_relaxed);
    if (t == head_seen) {
      head_seen = head.load(std::memory_order_acquire);
      if (t == head_seen) return false;  // empty
    }
    *out = cells[t & (kRingCap - 1)];
    tail.store(t + 1, std::memory_order_release);
    return true;
  }
};

RawCqeRing g_ring;
std::atomic<uint64_t> g_ring_dropped{0};
std::atomic<uint64_t> g_lapped{0};  // completions the hardware overwrote before a sweep read them

/// Hot-path timing behind DATACRUMBS_ENGINE_STATS: the cost of the ring push alone, apart from
/// the sweep it runs inside (g_drain_ns already counts the whole sweep).
std::atomic<uint64_t> g_capture_calls{0};
std::atomic<uint64_t> g_capture_ns{0};

/// Log2-of-nanoseconds bucket for the inter-completion gap histogram. ns == 0 (no prior
/// completion seen yet on this CQ) reports bucket 0 rather than undefined clz(0).
constexpr int kGapBuckets = 64;
inline unsigned gap_bucket(uint64_t ns) {
  return ns == 0 ? 0u : static_cast<unsigned>(63 - __builtin_clzll(ns));
}

/// One CQ's running totals for the aggregate window in progress. Touched only by the ring's one
/// consumer (the drain thread), so plain integers are enough; the producers only ever touch the
/// ring itself.
struct CqTally {
  // A ring-sampled estimate, not an exact count: the ring can drop under load and the timer's
  // sweep cadence can miss a queue that fills and drains inside one tick. The exact count is the
  // doca_diag plugin's device counter (global_tx_cqes), not this tally.
  uint64_t count = 0;
  uint64_t bytes = 0;
  uint64_t opcode_hist[16] = {};
  uint64_t gap_hist[kGapBuckets] = {};
  uint64_t matched = 0;
  uint64_t missed = 0;
  uint64_t startup = 0;
  uint64_t last_hw_ns = 0;  // carried across windows, so the gap series has no seam at a tick
  bool touched = false;
};
CqTally g_cq_tally[kMaxCq];
/// Cadence for DATACRUMBS_ENGINE_SAMPLE, counting every completion tally_raw sees. Plain counter
/// would do (tally_raw runs only on the drain thread); kept atomic so it never becomes a second
/// lazily-guarded static of the kind under scrutiny elsewhere in this file.
std::atomic<uint64_t> g_sample_seen{0};
/// Cadence for DATACRUMBS_ENGINE_SAMPLE in RECORDS mode: incremented once per completion drain()
/// sees, regardless of which thread called it. Only the Nth completion is copied into the ring;
/// every other one costs this increment and the compare below, nothing else.
std::atomic<uint64_t> g_capture_seen{0};

/// Copies one completion into the ring. No formatting, no string, no lock: the ring push is the
/// entire cost this pays on whichever thread called it.
void capture(const unsigned char* e, int cq_idx, bool err, uint64_t now_ns) {
  const bool stats = stats_enabled();
  const uint64_t t0 = stats ? mono_ns() : 0;
  RawCqe r;
  std::memcpy(r.cqe, e, kCqeSize);
  r.cpu_ns = now_ns;
  r.cq_idx = static_cast<uint8_t>(cq_idx);
  r.err = err ? 1 : 0;
  if (!g_ring.push(r)) g_ring_dropped.fetch_add(1, std::memory_order_relaxed);
  if (stats) {
    g_capture_calls.fetch_add(1, std::memory_order_relaxed);
    g_capture_ns.fetch_add(mono_ns() - t0, std::memory_order_relaxed);
  }
}

/// Rolls one completion into its CQ's tally instead of a record. Returns true on the Nth
/// completion (DATACRUMBS_ENGINE_SAMPLE), when the caller should ALSO format a full record, so an
/// aggregate run can still spot-check individual completions.
bool tally_raw(const RawCqe& r, const char* join_state) {
  CqTally& t = g_cq_tally[r.cq_idx];
  t.touched = true;
  ++t.count;
  t.bytes += r.byte_cnt();
  ++t.opcode_hist[r.opcode() & 0xf];
  const uint64_t hw = r.hw_ns();
  if (t.last_hw_ns != 0 && hw > t.last_hw_ns) ++t.gap_hist[gap_bucket(hw - t.last_hw_ns)];
  if (hw != 0) t.last_hw_ns = hw;
  if (std::strcmp(join_state, "matched") == 0)
    ++t.matched;
  else if (std::strcmp(join_state, "missed") == 0)
    ++t.missed;
  else
    ++t.startup;
  const unsigned n = engine_sample_n();
  if (n <= 1) return false;  // no spot-check unless sampling is asked for; 1 would mean every one
  return (g_sample_seen.fetch_add(1, std::memory_order_relaxed) + 1) % n == 0;
}

void emit_from_raw(const RawCqe& r) {
  const bool stats = stats_enabled();
  const uint64_t emit_t0 = stats ? mono_ns() : 0;
  const uint64_t hw_ns = r.hw_ns();
  const uint32_t byte_cnt = r.byte_cnt();
  const uint32_t opcode = r.opcode();
  const int cq_idx = r.cq_idx;
  const uint16_t wqe_counter = r.wqe_counter();
  const uint32_t qpn = r.qpn();
  // The submit that wrote this entry, keyed on the queue pair it retired plus its index. See the
  // note on g_pending: an index alone is not a unique identity once more than one queue is live.
  // wqe_counter is already the hardware's own 16-bit field, so every value it can hold is in range;
  // there is no separate bound to check here.
  Wqe req{};
  bool joined = false;
  // AGGREGATE mode never populates the pending table (task_submit_wrap skips scan_wqe there), so
  // a lookup would only ever miss; skip it rather than pay an atomic exchange for a guaranteed no.
  const bool join_is_on = capture_mode() == EngineCaptureMode::RECORDS && join_enabled();
  if (join_is_on && take_pending(qpn, wqe_counter, &req)) {
    joined = true;
    g_joined_any.store(true, std::memory_order_relaxed);
  } else if (join_is_on) {
    // No submit outstanding at that key: the record still carries the completion, but the
    // engine it names is a guess, so say so rather than report a confident wrong name.
    g_join_miss.fetch_add(1, std::memory_order_relaxed);
  }
  // How it completed, beside the name that says what it was. mlx5 reserves opcodes 7-11 and
  // written() rejects them, so this only ever names a class the device really reported.
  const char* klass = cqe_op_name(static_cast<uint8_t>(opcode));
  if (klass == nullptr) klass = "reserved";
  // matched: the submit was found. startup: posted before this process attached, so there was
  // never a submit to find. missed: the scanner should have seen it and did not.
  const char* join_state =
      joined ? "matched" : (g_joined_any.load(std::memory_order_relaxed) ? "missed" : "startup");
  if (capture_mode() == EngineCaptureMode::AGGREGATE) {
    // Tally first: DATACRUMBS_ENGINE_SAMPLE names every Nth completion, not every Nth that
    // happens to also be joined, so the sample decision must run whether or not the tally
    // below is what ships. Falling through means format a full record anyway, same as RECORDS.
    if (!tally_raw(r, join_state)) {
      if (stats) g_emit_ns.fetch_add(mono_ns() - emit_t0, std::memory_order_relaxed);
      return;
    }
  }
  char namebuf[64];
  record_name_for(namebuf, sizeof(namebuf), joined, req, static_cast<uint8_t>(opcode));
  const char* record_name = namebuf;
  // The work-request opcode a joined completion retired: a name plus its raw byte, since a value
  // this build has no name for is still worth reading off the wire. 0xff is the "no name" sentinel
  // ibv.wr_opcode's own lookup already uses for the same reason, so the two shims read alike.
  char opcode_name[48] = "";
  uint8_t opcode_raw = 0xff;
  if (joined) {
    opcode_raw = req.opcode;
    // MLX5_OPCODE_MMO (0x2f), the value every engine op retires under, has no entry in this
    // kernel's device.h, so the generated table reports a miss rather than a wrong value.
    // mlx5.opcode_raw still carries 0x2f either way.
    if (!wqe_opcode_name(req.opcode, opcode_name, sizeof(opcode_name)))
      std::snprintf(opcode_name, sizeof(opcode_name), "op_0x%02x", req.opcode);
  }
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  // opcode_mod is a uint8_t: every value it holds indexes the table, no out-of-range fallback
  // needed. The CQE timestamp is the raw HCA cycle counter, not a PHC-domain reading, so remap_raw
  // (not remap_hw) carries it. phc here is resolved per CQ; see phc_of_context for why a
  // process-wide guess is wrong.
  const int phc = (cq_idx >= 0 && cq_idx < kMaxCq) ? g_cq[cq_idx].phc : -1;
  uint64_t ref = 0;
  if (hw_ns != 0) ref = s->clock().remap_raw(hw_ns);
  // Falling back to software time is not an error but is not the wire either, so ts says
  // which clock produced it rather than leaving a reader to infer it from the magnitude.
  const char* cqe_clock = ref != 0 ? "global" : "software";
  if (ref == 0) ref = s->clock().remap(mono_ns());

  // Both ends of the duration are CLOCK_MONOTONIC, never NIC vs CPU: mixing domains can make a
  // completion appear to land before its own submit, an artifact of the alignment error between
  // the two clock fits, not a real duration. Same-domain duration costs only the poll lag,
  // captured at detection time (r.cpu_ns) so formatting delay does not fold in.
  const unsigned long long seen_ns = r.cpu_ns;
  unsigned long long start = ref;
  unsigned long long dur = 0;
  unsigned ph = 2;  // COUNTER: a completion with no known start is a point
  long long submit_delta = 0;
  if (req.submit_ns != 0 && seen_ns > req.submit_ns) {
    start = s->clock().remap(req.submit_ns);
    dur = seen_ns - req.submit_ns;
    // Submit to the moment the poll noticed, NOT how long the engine ran. A consumer that sleeps
    // between progress calls puts its own cadence in here: this sample polls lazily and reports
    // tens of milliseconds for a copy of a few bytes. It is the latency the application actually
    // saw, which is worth having, and it is not engine time, which this device does not expose.
    ph = 1;
    // What the wire says minus what the CPU says, kept because it is the only measure of how far
    // apart the two domains are, and it decides whether any wire-referenced duration is meaningful.
    submit_delta = static_cast<long long>(ref) - static_cast<long long>(start);
  }
  // Same key the record was named with, so a selection addresses what a reader sees. Only in
  // RECORDS capture mode: an AGGREGATE-mode completion that reaches this point already fell
  // through tally_raw's sample check above, so it always ships as a full record, never a second
  // time into this (different, generic) aggregation path.
  const bool aggregate_this =
      capture_mode() == EngineCaptureMode::RECORDS &&
      (joined ? (req.opcode == kOpMmo ? g_agg_engine[req.opcode_mod] : g_agg_rdma[req.opcode])
              : g_agg_cqe[opcode & 0xf]);
  if (aggregate_this) {
    // byte_cnt is the one quantity this record carries (cqe.bytes above); the rest (opcode, cq
    // index, src/dst_len from the paired submit) are identities of the operation, not quantities
    // of it, so they are left out.
    datacrumbs::client::NumArg nums[1];
    nums[0].key = "cqe.bytes";
    nums[0].kind = datacrumbs::client::NumKind::UINT;
    nums[0].u = byte_cnt;
    const datacrumbs::client::CatArg cats[1] = {{"cqe.clock", cqe_clock}};
    // The same duration the record-mode path reports, so aggregating an engine does not silently
    // turn its latency into a count. It is zero when no submit was joined, which the bucket's own
    // minimum then shows.
    s->aggregate(record_name, DC_CAT, DC_TYPE, start, dur, nums, 1, cats, 1);
    return;
  }
  char line[640];
  const int n = std::snprintf(
      line, sizeof(line),
      // The engine reports when an operation finished and never when it started. A joined submit
      // supplies the start, so this is an interval whenever the join succeeded and a point when it
      // did not: COMPLETE with a zero duration would draw as a zero-width box and hide the
      // difference between instantaneous and unknown.
      R"({"id":%llu,"name":"%s","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":%u,"args":{"hhash":"%s","cqe.clock":"%s","cqe.phc":%d,"cqe.bytes":%u,"cqe.imm":%u,"cqe.opcode":%u,"cqe.class":"%s","cqe.cq":%d,"engine.op":"%s","engine.src_len":%llu,"engine.dst_len":%llu,"cqe.submit_delta_ns":%lld,"cqe.hw_ns":%llu,"cqe.join":"%s","mlx5.opcode":"%s","mlx5.opcode_raw":%u,"tool":"engine_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()), record_name,
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(start / DATACRUMBS_TIME_DIVISOR_NS),
      static_cast<unsigned long long>(dur), ph, s->hhash().c_str(), cqe_clock, phc, byte_cnt,
      r.imm(), opcode, klass, cq_idx, namebuf, static_cast<unsigned long long>(req.src_len),
      static_cast<unsigned long long>(req.dst_len), submit_delta,
      static_cast<unsigned long long>(ref), join_state, opcode_name, opcode_raw);
  if (n > 0) {
    s->write(line, static_cast<std::size_t>(n));
    g_emitted.fetch_add(1, std::memory_order_relaxed);
  }
  if (stats) g_emit_ns.fetch_add(mono_ns() - emit_t0, std::memory_order_relaxed);
}

uint64_t be64_at(const unsigned char* p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

uint16_t be16_at(const unsigned char* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t be32_at(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

bool written(uint8_t op) {
  return ((kCqeOpcodeSet >> op) & 1u) != 0;
}

/// 0 for a requester completion (MLX5_CQE_REQ and its error form), 1 for a responder one.
int cqe_class(uint8_t op) {
  return op == 0 || op == kCqeReqErr ? 0 : 1;
}

/// Usable CQE slots in a CQ umem.
/// The registration is one power-of-two CQE array plus a 4096-byte tail: 266240 bytes
/// is 4096 entries not 4160, and 20480 is 256 not 320. size/kCqeSize walks past the
/// end of the ring, breaking the owner-bit phase, which needs a power-of-two count.
size_t cq_entries(size_t umem_size) {
  size_t n = umem_size / kCqeSize;
  size_t p = 1;
  while (p * 2 <= n) p *= 2;
  return p;
}

/// Emit every CQE the hardware has written since the last sweep.
/// Validity is the mlx5 owner bit against the consumer index, not "the opcode looks
/// plausible": once the ring wraps, stale entries still carry defined opcodes and
/// nonzero timestamps.
size_t drain(Cq& cq, int idx) {
  const size_t mask = cq.entries - 1;
  size_t read = 0;
  const uint64_t now_ns = mono_ns();  // one clock read per sweep, not one per entry
  cq.ctr[0].seen_this_sweep = cq.ctr[1].seen_this_sweep = false;
  for (size_t n = 0; n < cq.entries; ++n) {
    const unsigned char* e = cq.buf + (cq.ci & mask) * kCqeSize;
    const uint8_t op_own = e[kOpOwnOffset];
    const uint8_t op = static_cast<uint8_t>(op_own >> 4);
    if (!written(op)) return read;
    const uint8_t phase = (cq.ci & cq.entries) != 0 ? 1 : 0;
    if ((op_own & kCqeOwnerMask) != phase) {
      // Not written for this lap, or the hardware is a whole lap ahead: the owner bit reads the
      // same either way. The entry just consumed tells them apart: overwritten means its counter
      // moved since it was read. Skip one lap, count it, and read on from the new phase.
      if (n == 0) {
        const unsigned char* prev = cq.buf + ((cq.ci - 1) & mask) * kCqeSize;
        const uint8_t prev_op = static_cast<uint8_t>(prev[kOpOwnOffset] >> 4);
        const Cq::CtrTrack& pt = cq.ctr[cqe_class(prev_op)];
        if (pt.have && !pt.is_static && written(prev_op) &&
            be16_at(prev + kWqeCounterOffset) != pt.last) {
          if (stats_enabled())
            DC_LOG_INFO(
                "[doca_engine] cq %d lap resync at ci=%zu: prev entry counter %u, last "
                "consumed %u, op_own 0x%02x",
                idx, cq.ci, be16_at(prev + kWqeCounterOffset), pt.last, op_own);
          cq.ci += cq.entries;
          g_lapped.fetch_add(cq.entries, std::memory_order_relaxed);
          cq.ctr[0].have = cq.ctr[1].have = false;
          continue;
        }
      }
      return read;
    }
    // A jump in the hardware's own entry counter at the seam between two sweeps is completions
    // overwritten that the owner bit could not show: an even number of laps reads as the
    // current phase. Per queue pair, so on a CQ shared by several it is an upper bound.
    const uint16_t ctr = be16_at(e + kWqeCounterOffset);
    Cq::CtrTrack& track = cq.ctr[cqe_class(op)];
    if (track.have) {
      const uint16_t delta = static_cast<uint16_t>(ctr - track.last);
      if (delta == 0) {
        track.is_static = true;
      } else if (track.seen_this_sweep) {
        if (track.stride == 0 || delta < track.stride) track.stride = delta;
      } else if (!track.is_static && track.stride != 0 && delta >= 2 * track.stride &&
                 delta < 0x8000) {
        // A backwards step is the work queue's own index wrapping at its depth, not a lap: a
        // 64-entry receive queue reads as 65472 forward. Only a forward gap counts.
        g_lapped.fetch_add(delta / track.stride - 1, std::memory_order_relaxed);
      }
    }
    track.last = ctr;
    track.have = true;
    track.seen_this_sweep = true;
    // A resize is not a work completion, and it invalidates both the entry count and the phase the
    // consumer index is riding on. Stop reading this queue rather than emit from a stale geometry.
    if (op == kCqeResize) {
      cq.buf = nullptr;
      g_unsupported_cq.fetch_add(1, std::memory_order_relaxed);
      return read;
    }
    // An error completion (0xd/0xe) carries no timestamp; its timestamp field is not a clock
    // reading.
    const bool err = op == kCqeReqErr || op == kCqeRespErr;
    // DATACRUMBS_ENGINE_SAMPLE thins the record stream for a workload the writer cannot keep up
    // with; the tally sees every completion regardless.
    const unsigned sample_n = engine_sample_n();
    const bool sample_gated =
        capture_mode() == EngineCaptureMode::RECORDS && sample_n > 1 &&
        (g_capture_seen.fetch_add(1, std::memory_order_relaxed) + 1) % sample_n != 0;
    if (!sample_gated) capture(e, idx, err, now_ns);
    ++cq.ci;
    ++read;
  }
  return read;
}

/// Sweep every ready CQ once. A sweep that finds the dereg hook mid-drain skips this tick; the
/// next one picks up whatever is left.
size_t sweep_all_cqs() {
  if (g_ring_pushing.test_and_set(std::memory_order_acquire)) return 0;
  size_t read = 0;
  for (int i = 0; i < kMaxCq; ++i) {
    if (g_cq[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_cq[i].buf == nullptr) continue;
    read += drain(g_cq[i], i);
  }
  g_ring_pushing.clear(std::memory_order_release);
  return read;
}

/// Turns whatever the ring holds into trace lines or tallies. This is where a RawCqe becomes
/// formatting cost; nothing that pushed it ever pays that cost itself.
// Bounded per tick: the write worker is shared, and an unbounded drain at a high completion rate
// starved the other sinks' rings. The tick reports work done, so the worker comes straight back.
constexpr unsigned kDrainPerTick = 4096;

bool drain_ring() {
  // A loser reports no work rather than waiting; the next tick picks up the rest.
  if (g_ring_draining.test_and_set(std::memory_order_acquire)) return false;
  RawCqe r;
  unsigned n = 0;
  while (n < kDrainPerTick && g_ring.pop(&r)) {
    emit_from_raw(r);
    ++n;
  }
  g_ring_draining.clear(std::memory_order_release);
  return n != 0;
}

/// Writes one AGGREGATED record per CQ that saw a completion this window, then resets the tally.
/// last_hw_ns is deliberately not reset: the gap series carries on across a tick with no seam.
void emit_cq_tally(int idx, CqTally& t, uint64_t window_start_ns) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  char hist[512] = "";
  std::size_t hp = 0;
  for (int i = 0; i < 16 && hp + 24 < sizeof(hist); ++i)
    if (t.opcode_hist[i] != 0)
      hp += static_cast<std::size_t>(
          std::snprintf(hist + hp, sizeof(hist) - hp, "%s\"%d\":%llu", hp ? "," : "", i,
                        static_cast<unsigned long long>(t.opcode_hist[i])));
  char gaps[1536] = "";
  std::size_t gp = 0;
  for (int i = 0; i < kGapBuckets && gp + 24 < sizeof(gaps); ++i)
    if (t.gap_hist[i] != 0)
      gp += static_cast<std::size_t>(std::snprintf(gaps + gp, sizeof(gaps) - gp, "%s\"%d\":%llu",
                                                   gp ? "," : "", i,
                                                   static_cast<unsigned long long>(t.gap_hist[i])));
  const uint64_t ts = s->clock().remap(window_start_ns) / DATACRUMBS_TIME_DIVISOR_NS;
  char line[2560];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"engine.aggregate","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":0,"ph":3,"args":{"hhash":"%s","cqe.cq":%d,)"
      R"("cqe.count":%llu,"cqe.bytes":%llu,"cqe.matched":%llu,"cqe.missed":%llu,)"
      R"("cqe.startup":%llu,"cqe.opcode_hist":{%s},"cqe.gap_log2_hist":{%s},"tool":"engine_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()),
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(ts), s->hhash().c_str(), idx,
      static_cast<unsigned long long>(t.count), static_cast<unsigned long long>(t.bytes),
      static_cast<unsigned long long>(t.matched), static_cast<unsigned long long>(t.missed),
      static_cast<unsigned long long>(t.startup), hist, gaps);
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
  t.count = t.bytes = t.matched = t.missed = t.startup = 0;
  std::memset(t.opcode_hist, 0, sizeof(t.opcode_hist));
  std::memset(t.gap_hist, 0, sizeof(t.gap_hist));
  t.touched = false;
}

/// Writes the reader's own health into the trace, not only into the log: a table with no engine
/// column has to be answerable from the trace alone. Every field is a count the run accumulated,
/// so a zero everywhere means the reader saw the whole queue.
void emit_health() {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  const uint64_t ts = s->clock().remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS;
  char line[1024];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"engine.health","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":0,"ph":2,"args":{"hhash":"%s",)"
      R"("health.emitted":%llu,"health.lapped":%llu,"health.ring_dropped":%llu,)"
      R"("health.dropped_umem":%llu,"health.dropped_cq":%llu,"health.unsupported_cq":%llu,)"
      R"("health.cq_at_offset":%llu,"health.join_miss":%llu,"health.join_overwrite":%llu,)"
      R"("health.max_scan_gap_ns":%llu,"tool":"engine_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()),
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(ts), s->hhash().c_str(),
      static_cast<unsigned long long>(g_emitted.load()),
      static_cast<unsigned long long>(g_lapped.load()),
      static_cast<unsigned long long>(g_ring_dropped.load()),
      static_cast<unsigned long long>(g_dropped_umem.load()),
      static_cast<unsigned long long>(g_dropped_cq.load()),
      static_cast<unsigned long long>(g_unsupported_cq.load()),
      static_cast<unsigned long long>(g_cq_offset.load()),
      static_cast<unsigned long long>(g_join_miss.load()),
      static_cast<unsigned long long>(g_join_overwrite.load()),
      static_cast<unsigned long long>(g_max_scan_gap_ns.load()));
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

/// One record per completion queue the reader refused, written where it is refused: the reason a
/// run has no engine term belongs in the trace beside the records it does have.
void emit_cq_skipped(const char* why, uint32_t umem_id, size_t entries, uint64_t offset,
                     size_t umem_size) {
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  const uint64_t ts = s->clock().remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS;
  char line[640];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"engine.cq_skipped","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":0,"ph":2,"args":{"hhash":"%s","cq.why":"%s",)"
      R"("cq.umem_id":%u,"cq.entries":%llu,"cq.umem_offset":%llu,"cq.umem_size":%llu,)"
      R"("tool":"engine_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()),
      static_cast<long>(datacrumbs::client::self_pid()), static_cast<int>(tid()),
      static_cast<unsigned long long>(ts), s->hhash().c_str(), why, umem_id,
      static_cast<unsigned long long>(entries), static_cast<unsigned long long>(offset),
      static_cast<unsigned long long>(umem_size));
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

/// Start of the aggregate window in progress. 0 until the first tick, which is indistinguishable
/// from "due immediately" and is harmless: with nothing tallied yet, the window closes empty.
uint64_t g_last_agg_tick_ns = 0;

/// One tick: sweep every bound CQ even if the app never calls doca_pe_progress itself (a DPA
/// sample's completion queue is bound but never polled by the DPA host API), drain the ring, and
/// in aggregate mode close any window whose interval elapsed. Called only from this module's own
/// background thread, one call at a time. @p force_emit closes every touched window on shutdown.
}  // namespace
void scan_wqe(Umem& u);  // defined below at global scope, after the hooks
namespace {

/// One sweep tick: send queues first, so a submit is in the join table before its completion is
/// read, then every completion ring. Nothing here formats: a 4096-entry ring wraps in 0.7 ms at
/// line rate, and a sweep that also formatted fell a lap behind and stopped reading for good.
size_t sweep_tick() {
  if (capture_mode() == EngineCaptureMode::RECORDS && join_enabled())
    for (int i = 0; i < kMaxUmem; ++i)
      if (g_umem[i].state.load(std::memory_order_acquire) == kStateReady) scan_wqe(g_umem[i]);
  return sweep_all_cqs();
}

/// One format tick: turn the raw ring into records or tallies, and close aggregate windows.
bool format_tick(bool force_emit = false) {
  const bool moved = drain_ring();
  if (capture_mode() != EngineCaptureMode::AGGREGATE) return moved;
  const uint64_t now = mono_ns();
  const uint64_t interval_ns =
      static_cast<uint64_t>(datacrumbs::ConfigurationManager::runtime().telemetry_interval_ms) *
      1000000ull;
  if (!force_emit && (interval_ns == 0 || now - g_last_agg_tick_ns < interval_ns)) return moved;
  unsigned touched = 0;
  for (int i = 0; i < kMaxCq; ++i)
    if (g_cq_tally[i].touched) {
      ++touched;
      emit_cq_tally(i, g_cq_tally[i], g_last_agg_tick_ns);
    }
  if (force_emit && stats_enabled())
    DC_LOG_INFO("[doca_engine] final aggregate flush: %u cq window(s) written", touched);
  g_last_agg_tick_ns = now;
  return true;
}

// The sweep runs on the client's scan worker and the formatting on its write worker
// (common/background.h). A tick that found work keeps its worker awake for another round; a timed
// sleep can overshoot by hundreds of microseconds and 0.7 ms is one lap at line rate.
std::shared_ptr<datacrumbs::client::Background::Task> g_sweep_task;
std::shared_ptr<datacrumbs::client::Background::Task> g_format_task;

}  // namespace

/// Record one registration. Both entry points land here: they are separate exported symbols with
/// different signatures, and hooking only the _ex form loses every umem an application registers
/// through the plain one, which silently costs us the CQ binding and so every completion.
namespace {
void note_umem(void* ctx, void* obj, void* addr, size_t size) {
  if (obj == nullptr) return;
  for (int i = 0; i < kMaxUmem; ++i) {
    int expect = kStateFree;
    if (!g_umem[i].state.compare_exchange_strong(expect, kStateClaimed, std::memory_order_acquire))
      continue;
    g_umem[i].ctx = ctx;
    g_umem[i].obj = obj;
    g_umem[i].addr = addr;
    g_umem[i].size = size;
    g_umem[i].id = *reinterpret_cast<uint32_t*>(obj);
    // A reused slot's cache still holds signatures from whatever this one held before; left in
    // place they could suppress the new region's first real scan of a position that coincidentally
    // reads the same 8 bytes the old occupant left there.
    std::memset(g_umem[i].ctrl_sig, 0, sizeof(g_umem[i].ctrl_sig));
    g_umem[i].state.store(kStateReady, std::memory_order_release);
    return;
  }
  g_dropped_umem.fetch_add(1, std::memory_order_relaxed);
}
}  // namespace

void* umem_reg_wrap(void* ctx, void* addr, size_t size, uint32_t access) {
  auto real =
      reinterpret_cast<void* (*)(void*, void*, size_t, uint32_t)>(gotcha_get_wrappee(g_h_umem_reg));
  if (real == nullptr) return nullptr;
  void* r = real(ctx, addr, size, access);
  // A tracer thread is datacrumbs' own (the DPA clock anchor's worker): its objects must never
  // surface as if they were the traced application's, so this skips remembering the umem at all
  // rather than filtering records after the fact.
  if (enabled() && !tracer_thread_active()) note_umem(ctx, r, addr, size);
  return r;
}

void* umem_reg_ex_wrap(void* ctx, void* in) {
  auto real = reinterpret_cast<void* (*)(void*, void*)>(gotcha_get_wrappee(g_h_umem_reg_ex));
  if (real == nullptr) return nullptr;
  void* r = real(ctx, in);
  // struct mlx5dv_devx_umem_in leads with { void *addr; size_t size; ... } and the returned
  // struct mlx5dv_devx_umem leads with uint32_t umem_id.
  if (enabled() && !tracer_thread_active())
    note_umem(ctx, r, *reinterpret_cast<void**>(in),
              *reinterpret_cast<size_t*>(static_cast<char*>(in) + sizeof(void*)));
  return r;
}

void* obj_create_wrap(void* ctx, const void* in, size_t inlen, void* out, size_t outlen) {
  auto real = reinterpret_cast<void* (*)(void*, const void*, size_t, void*, size_t)>(
      gotcha_get_wrappee(g_h_obj_create));
  if (real == nullptr) return nullptr;
  void* r = real(ctx, in, inlen, out, outlen);
  // Checked once, here, at creation: no thread of datacrumbs or its client may appear in a trace,
  // so a CQ the tracer's own anchor thread creates is never bound, and its completions never
  // scanned.
  if (!enabled() || tracer_thread_active() || inlen <= kCqUmemValidOffset) return r;
  const uint8_t* cmd = static_cast<const uint8_t*>(in);
  if (static_cast<uint16_t>((cmd[0] << 8) | cmd[1]) != kCreateCq) return r;
  // Bind the umem the command names, not the one registered most recently. Concurrent contexts
  // interleave their registrations, and picking the most recent one can silently bind the wrong
  // buffer.
  if ((cmd[kCqUmemValidOffset] & kCqUmemValidBit) == 0) return r;
  if (cmd[kCqcFormatOffset] != 0) {
    g_unsupported_cq.fetch_add(1, std::memory_order_relaxed);
    emit_cq_skipped("cqe format", be32_at(cmd + kCqUmemIdOffset), cmd[kCqcFormatOffset], 0, 0);
    if (stats_enabled())
      DC_LOG_INFO("[doca_engine] cq skipped: cqe format %u", cmd[kCqcFormatOffset]);
    return r;
  }
  const uint32_t want = be32_at(cmd + kCqUmemIdOffset);
  // The id alone can match whichever context registered it first, letting a small doorbell page
  // from an older context pose as this context's queue and read as an unhandled layout. Prefer
  // this context, and keep the id-only match as the fallback for a registration seen before its
  // context was known.
  int match = -1;
  for (int i = 0; i < kMaxUmem; ++i) {
    if (g_umem[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_umem[i].id != want) continue;
    if (g_umem[i].ctx == ctx) {
      match = i;
      break;
    }
    if (match < 0) match = i;
  }
  if (match >= 0) {
    const int i = match;
    if (g_umem[i].addr == nullptr || g_umem[i].size < kCqeSize) return r;
    for (int c = 0; c < kMaxCq; ++c) {
      int expect = kStateFree;
      if (!g_cq[c].state.compare_exchange_strong(expect, kStateClaimed, std::memory_order_acquire))
        continue;
      const uint64_t cq_off = be64_at(cmd + kCqUmemOffsetOffset);
      g_cq[c].entries = size_t{1} << (cmd[kCqcLogSizeOffset] & kCqcLogSizeMask);
      if (cq_off != 0) g_cq_offset.fetch_add(1, std::memory_order_relaxed);
      // Every byte read must lie inside the registration. The count alone is not enough: a queue
      // that fits at the base can still run past the end once its offset is taken into account,
      // and reading past the end is a segfault in the traced process, not a bad record.
      const bool fits = cq_off <= g_umem[i].size &&
                        g_cq[c].entries <= (g_umem[i].size - cq_off) / kCqeSize &&
                        g_cq[c].entries <= cq_entries(g_umem[i].size - cq_off);
      if (!fits) {
        g_unsupported_cq.fetch_add(1, std::memory_order_relaxed);
        emit_cq_skipped("does not fit its umem", want, g_cq[c].entries, cq_off, g_umem[i].size);
        // The size is the diagnostic: a queue that does not fit its registration means the wrong
        // registration, and the id alone once picked another context's doorbell page.
        if (stats_enabled())
          DC_LOG_INFO("[doca_engine] cq skipped: %zu entries at offset %llu in a %zu byte umem "
                      "(id %u, ctx %p)",
                      g_cq[c].entries, static_cast<unsigned long long>(cq_off), g_umem[i].size,
                      want, ctx);
        g_cq[c].state.store(kStateFree, std::memory_order_release);
        return r;
      }
      g_cq[c].buf = static_cast<unsigned char*>(g_umem[i].addr) + cq_off;
      g_cq[c].ci = 0;
      g_cq[c].umem_id = want;
      g_cq[c].phc = phc_of_context(static_cast<struct ibv_context*>(ctx));
      g_cq[c].state.store(kStateReady, std::memory_order_release);
      return r;
    }
    g_dropped_cq.fetch_add(1, std::memory_order_relaxed);
    return r;
  }
  return r;
}

int umem_dereg_wrap(void* umem) {
  auto real = reinterpret_cast<int (*)(void*)>(gotcha_get_wrappee(g_h_umem_dereg));
  if (real == nullptr) return -1;
  // A context that stops destroys its CQ. Reading it afterwards is a use-after-free. Both slots
  // go back to the pool.
  for (int i = 0; i < kMaxUmem; ++i) {
    if (g_umem[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_umem[i].obj != umem) continue;
    for (int c = 0; c < kMaxCq; ++c) {
      if (g_cq[c].state.load(std::memory_order_acquire) != kStateReady) continue;
      if (g_cq[c].umem_id != g_umem[i].id) continue;
      // A CQ that lives and dies inside one drain tick would otherwise lose every completion it
      // ever posted: catch it here, at the one point that is guaranteed to run before the memory
      // goes away, rather than depend on winning a race against the timer thread's next wakeup.
      while (g_ring_pushing.test_and_set(std::memory_order_acquire)) {
      }
      drain(g_cq[c], c);
      g_cq[c].buf = nullptr;
      g_cq[c].state.store(kStateFree, std::memory_order_release);
      g_ring_pushing.clear(std::memory_order_release);
    }
    g_umem[i].addr = nullptr;
    g_umem[i].state.store(kStateFree, std::memory_order_release);
  }
  return real(umem);
}

/// Read the work-queue entry a submit just wrote, if this region holds one.
/// Scanned forward from a cursor, not diffed: a diff also catches payload, and EC
/// data containing 0x2f posed as a control segment claiming entry index 0x7077,
/// which the few-thousand bound rejects.
void scan_wqe(Umem& u) {
  if (u.addr == nullptr || u.size < 64 || u.size > 256 * 1024) return;
  // A region with no engine descriptor usually never gets one: an RDMA send queue carries no MMO
  // control segment, so walking every registered region on every submit wastes work. Re-checked
  // periodically, since a queue can be empty when first seen and carry engine work later.
  if (u.empty_scans.load(std::memory_order_relaxed) >= kEmptyScansBeforeSkip) {
    if (u.skipped.fetch_add(1, std::memory_order_relaxed) + 1 < kRecheckEverySubmits) return;
    u.skipped.store(0, std::memory_order_relaxed);
  }
  // How long since this region was last actually walked. A submit that lands more than one SQ ring
  // size after the previous scan can have its entry overwritten by a later post before any scan
  // ever sees it, which reads as a join miss with no other symptom; this is the diagnostic for
  // that, not a correctness mechanism.
  const uint64_t scan_now = mono_ns();
  const uint64_t last = u.last_scan_ns.exchange(scan_now, std::memory_order_relaxed);
  if (last != 0) {
    const uint64_t gap = scan_now - last;
    uint64_t prev_max = g_max_scan_gap_ns.load(std::memory_order_relaxed);
    while (gap > prev_max &&
           !g_max_scan_gap_ns.compare_exchange_weak(prev_max, gap, std::memory_order_relaxed)) {
    }
  }
  bool found = false;
  const bool join_is_on =
      join_enabled();  // one config lookup for the whole walk, not one per entry
  const unsigned char* base = static_cast<const unsigned char*>(u.addr);
  for (size_t off = 0; off + 64 <= u.size; off += 64) {
    const unsigned char* e = base + off;
    const uint8_t op = e[3];
    // MMO selects an engine and its opcode_mod says which; the RDMA verbs name themselves. Only a
    // membership test here: the name itself is built later, at emit time, for whichever completion
    // actually gets joined, not for every position a scan merely passes over.
    if (op != kOpMmo && !wqe_opcode_known(op)) continue;
    // The full 16-bit range is trusted; see kWqeCounterDomain for why a narrower one is wrong at
    // scale. The `ds` check below is the sanity filter against payload that merely looks like a
    // control segment.
    const unsigned idx = static_cast<unsigned>((e[1] << 8) | e[2]);
    const unsigned ds = e[7];
    // Segment count of a real entry. Payload that happens to carry a valid opcode byte rarely
    // carries a plausible one too, and a zero would name an entry with no descriptors at all.
    if (ds == 0 || ds > 16) continue;
    found = true;
    // The ring is walked in full on every submit and a consumed entry is never cleared, so most
    // positions found here have not changed since the last pass. Comparing the 8 bytes in hand
    // skips both the segment loop and a join-table touch for already-processed content. A genuine
    // repost, even at a position whose earlier join was already taken, always differs and falls
    // through.
    const uint64_t sig = be64_at(e);
    const size_t slot = off / 64;
    const bool use_cache = scan_cache_enabled();
    if (use_cache && u.ctrl_sig[slot] == sig) continue;
    if (use_cache) u.ctrl_sig[slot] = sig;
    Wqe w{};
    // Control-segment qpn_ds: bytes 4-6 are the posting queue pair, big-endian, same field
    // wqe_spy.c reads off the wire. Needed because a submit index means nothing on its own once a
    // process drives more than one queue: two queues can post the same index and collide in one
    // shared slot if the queue pair is not part of the key.
    w.qpn = (static_cast<uint32_t>(e[4]) << 16) | (static_cast<uint32_t>(e[5]) << 8) | e[6];
    w.opcode_mod = e[0];
    w.opcode = op;
    w.submit_ns = mono_ns();
    // Segments after the control one are {byte_count, lkey, addr} big-endian. The first is the
    // operation's own descriptor and reads zero or one byte; source and destination follow, as a
    // 57-byte decompress and a 23-into-35-byte encrypt both confirmed.
    unsigned seen = 0;
    for (unsigned seg = first_data_seg(op); seg < ds && seg < 8; seg++) {
      const unsigned char* d = e + seg * 16;
      const uint64_t len = (static_cast<uint64_t>(d[0]) << 24) |
                           (static_cast<uint64_t>(d[1]) << 16) |
                           (static_cast<uint64_t>(d[2]) << 8) | d[3];
      if (len <= 1) continue;
      if (seen == 0)
        w.src_len = len;
      else if (seen == 1)
        w.dst_len = len;
      seen++;
    }
    // The ring is walked in full on every progress call and its entries are not cleared once
    // consumed, so most of what a scan finds is what the previous scan already recorded;
    // put_pending treats identical content at the same (qpn, idx) as that rescan rather than a new
    // submit, and counts it as an overwrite only when the content actually changed under a
    // still-unmatched slot.
    if (join_is_on) {
      bool overwrite = false;
      put_pending(w.qpn, idx, w, &overwrite);
      if (overwrite) g_join_overwrite.fetch_add(1, std::memory_order_relaxed);
    }
  }
  if (found)
    u.empty_scans.store(0, std::memory_order_relaxed);
  else if (u.empty_scans.load(std::memory_order_relaxed) < kEmptyScansBeforeSkip)
    u.empty_scans.fetch_add(1, std::memory_order_relaxed);
}

// Both hooks are pass-through. The application's thread does no per-completion work in any mode:
// the timer thread scans the send queues and sweeps the completion rings.
int task_submit_wrap(void* task) {
  auto real = reinterpret_cast<int (*)(void*)>(gotcha_get_wrappee(g_h_task_submit));
  if (real == nullptr) return -1;
  return real(task);
}

int pe_progress_wrap(void* pe) {
  auto real = reinterpret_cast<int (*)(void*)>(gotcha_get_wrappee(g_h_pe_progress));
  if (real == nullptr) return 0;
  return real(pe);
}

void datacrumbs::client::doca::init() {
  if (!enabled()) return;
  g_ring.init();
  // Built here, single-threaded, before any hook is installed and before the drain thread starts,
  // to avoid the static-init race that a lazily-constructed singleton hits when first touched
  // from more than one thread.
  datacrumbs::Singleton<EngineSink>::get_instance();
  init_agg_table();
  static gotcha_binding_t bindings[] = {
      {"mlx5dv_devx_umem_reg", reinterpret_cast<void*>(umem_reg_wrap), &g_h_umem_reg},
      {"mlx5dv_devx_umem_reg_ex", reinterpret_cast<void*>(umem_reg_ex_wrap), &g_h_umem_reg_ex},
      {"mlx5dv_devx_umem_dereg", reinterpret_cast<void*>(umem_dereg_wrap), &g_h_umem_dereg},
      {"mlx5dv_devx_obj_create", reinterpret_cast<void*>(obj_create_wrap), &g_h_obj_create},
      {"doca_task_submit", reinterpret_cast<void*>(task_submit_wrap), &g_h_task_submit},
      {"doca_pe_progress", reinterpret_cast<void*>(pe_progress_wrap), &g_h_pe_progress},
  };
  // Interposing a symbol a kernel-bypass path uses can break that path outright, so the set is
  // selectable: DATACRUMBS_ENGINE_WRAPS names the symbols to wrap and empty means all of them.
  static gotcha_binding_t selected[6];
  const std::string& want = datacrumbs::ConfigurationManager::runtime().engine_wraps;
  int n = 0;
  for (const auto& b : bindings) {
    if (!want.empty() && want.find(b.name) == std::string::npos) continue;
    selected[n++] = b;
  }
  if (n == 0) return;
  // A process that links no DOCA at all binds none of these, which is not a failure here.
  const gotcha_error_t rc = ::gotcha_wrap(selected, n, "datacrumbs_engine");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[doca_engine] gotcha_wrap failed: %d", static_cast<int>(rc));
  auto& bg = datacrumbs::client::Background::get();
  g_sweep_task = bg.add_scan([] { return sweep_tick() != 0; });
  g_format_task = bg.add_write([] { return format_tick(); });
}

void datacrumbs::client::doca::fini() {
  // The client stopped both workers before calling here. Whatever the last sweep left in the
  // hardware rings and the raw ring is read and formatted on this thread, and every window closes.
  auto& bg = datacrumbs::client::Background::get();
  bg.remove(g_sweep_task);
  bg.remove(g_format_task);
  if (g_sweep_task != nullptr) {
    datacrumbs::client::TracerThread mark;
    sweep_tick();
    // One tick drains kDrainPerTick; a program that exits right after its loop leaves more.
    while (drain_ring()) {
    }
    format_tick(/*force_emit=*/true);
  }
  // The same counters the lines below log, in the trace: an analysis reads the reader's own
  // health from the file it is analysing, without the run's stderr beside it.
  emit_health();
  // A lower bound: a queue whose index wraps at its own depth hides a gap larger than that
  // depth.
  const uint64_t lapped = g_lapped.load();
  if (lapped != 0)
    DC_LOG_WARN(
        "[doca_engine] sweep fell behind the hardware: at least %llu completion(s) "
        "overwritten before they were read",
        static_cast<unsigned long long>(lapped));
  const uint64_t rd = g_ring_dropped.load();
  if (rd != 0)
    DC_LOG_WARN("[doca_engine] completion ring full: dropped %llu completion(s) before formatting",
                static_cast<unsigned long long>(rd));
  const uint64_t cc = g_capture_calls.load();
  if (cc != 0) {
    const uint64_t cn = g_capture_ns.load();
    DC_LOG_INFO("[doca_engine] %llu captures: %llu ns/capture (hot-path ring push)",
                static_cast<unsigned long long>(cc), static_cast<unsigned long long>(cn / cc));
  }
  const uint64_t du = g_dropped_umem.load();
  const uint64_t dc = g_dropped_cq.load();
  if (du != 0 || dc != 0)
    DC_LOG_WARN("[doca_engine] slot table full: dropped %llu umem, %llu cq",
                static_cast<unsigned long long>(du), static_cast<unsigned long long>(dc));
  const uint64_t jm = g_join_miss.load();
  const uint64_t jo = g_join_overwrite.load();
  if (jm != 0 || jo != 0)
    DC_LOG_WARN(
        "[doca_engine] joined by queue pair and entry index: %llu completion(s) matched no submit, "
        "%llu submit(s) overwritten before completing",
        static_cast<unsigned long long>(jm), static_cast<unsigned long long>(jo));
  const uint64_t gap = g_max_scan_gap_ns.load();
  if (gap != 0)
    DC_LOG_INFO("[doca_engine] longest gap between two scans of one region: %llu ns",
                static_cast<unsigned long long>(gap));
  const uint64_t co = g_cq_offset.load();
  if (co != 0)
    DC_LOG_WARN("[doca_engine] %llu cq placed at an offset into its registration",
                static_cast<unsigned long long>(co));
  const uint64_t uc = g_unsupported_cq.load();
  if (uc != 0)
    DC_LOG_WARN("[doca_engine] skipped %llu cq with an unhandled layout",
                static_cast<unsigned long long>(uc));
  const uint64_t calls = g_drain_calls.load();
  if (calls != 0) {
    const uint64_t ns = g_drain_ns.load();
    const uint64_t ens = g_emit_ns.load();
    const uint64_t recs = g_emitted.load();
    // Sweep and write reported apart: every progress call pays the sweep, only a call that found a
    // completion pays the write.
    const uint64_t sweep = ns > ens ? ns - ens : 0;
    DC_LOG_INFO("[doca_engine] %llu drains: sweep %llu ns/drain, %llu records at %llu ns/record",
                static_cast<unsigned long long>(calls),
                static_cast<unsigned long long>(sweep / calls),
                static_cast<unsigned long long>(recs),
                static_cast<unsigned long long>(recs ? ens / recs : 0));
  }
  datacrumbs::Singleton<EngineSink>::finalize();  // destroys the sink, which flushes and closes
}
