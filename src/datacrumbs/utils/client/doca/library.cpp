// SPDX-License-Identifier: MIT

/**
 * @file engine_hwts.cpp
 * @brief Per-op hardware timestamps for the BlueField fixed-function engines.
 *
 * DMA, AES-GCM, erasure coding and decompress all complete on a standard 64-byte mlx5 CQE carrying
 * a hardware timestamp, exactly like RDMA. What differs is how the queue is made: DOCA builds these
 * CQs through mlx5dv_devx_obj_create (opcode 0x0400), not ibv_create_cq, so the ibverbs shim in
 * rdma_hwts.cpp never sees them. Measured on BlueField-3: decompress reported byte_cnt 100000,
 * DMA 16, AES-GCM 100012 (payload plus the 12-byte GCM tag), each with a distinct hw timestamp.
 *
 * The CREATE_CQ command names its buffer: cq_umem_id at byte 0x58, guarded by cq_umem_valid at
 * 0x5c. So the hook chain is: remember each umem against the id the driver hands back, bind the
 * named one on CREATE_CQ, then read new CQEs after every doca_pe_progress. Timestamps are remapped
 * through the per-PHC dc_timesync fit, which puts engine completions on the same axis as the eBPF
 * events and the RDMA records.
 *
 * There is no submit-side stamp here: the CQE is completion-only. Duration per op comes from
 * pairing with a uprobe on doca_task_submit, which is the server's job.
 */

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/doca/library.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dirent.h>
#include <limits.h>
#include <gotcha/gotcha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <atomic>

namespace {
// The labels this module puts on every record it writes: cat groups by the library surface,
// type names the instrumentation that produced it. Declared here rather than centrally so a
// module owns its own, as dftracer does in brahma/posix.cpp.
// Macros, not constants: folded into the format string at compile time they cost nothing,
// where passing them as %s arguments costs a strlen and a copy on every record.
#define DC_CAT "DOCA"
#define DC_TYPE "doca"

using datacrumbs::client::mono_ns;

constexpr uint16_t kCreateCq = 0x0400;
constexpr size_t kCqeSize = 64;
constexpr size_t kTsOffset = 0x30;  // 64-bit hardware timestamp
constexpr size_t kByteCntOffset = 0x2c;
constexpr size_t kSopDropQpnOffset = 0x38;  // queue number in the low 24 bits
constexpr size_t kWqeCounterOffset = 0x3c;  // index of the work-queue entry that produced this
constexpr size_t kOpOwnOffset = 0x3f;
constexpr uint8_t kCqeReqErr = 0xd;  // a failed op still completes, with no valid timestamp
constexpr uint8_t kCqeRespErr = 0xe;
constexpr uint8_t kCqeResize = 0x5;
// mlx5dv.h defines opcodes 0-6 and 12-14; 15 is MLX5_CQE_INVALID and 7-11 are reserved. Testing
// only for 15 accepts uninitialised queue memory as a completion: an eth RX capture reported three
// CQEs, two of them slots reading opcode 7 with a nonsense timestamp. Bit n set means n is real.
constexpr uint16_t kCqeOpcodeSet = 0x707f;
constexpr uint8_t kCqeOwnerMask = 0x1;
// CREATE_CQ input layout, confirmed on hardware: a run that registered umem id 2 immediately
// before produced 00 00 00 02 at 0x58 and 0x80 at 0x5c.
// log_cq_size, pinned by two CQs of known different size: 0x0c for a 4096-entry queue and 0x08 for
// a 256-entry one. Authoritative, unlike inferring the count from the registration size.
constexpr size_t kCqcLogSizeOffset = 0x1c;
constexpr uint8_t kCqcLogSizeMask = 0x1f;
// First byte of cq_context, holding cqe_sz and the compression enables. Zero on every CQ validated
// here, all of which decode as one 64-byte CQE per slot. A nonzero value means some other layout,
// most likely 128-byte CQEs or compressed mini-CQEs, which this reader cannot parse. Refuse those
// rather than emit nonsense.
constexpr size_t kCqcFormatOffset = 0x11;
// The CQ need not start at the registration's base: the command names a byte offset into it, and a
// provider that packs several queues into one registration uses it. Ignoring it pointed the reader
// at the wrong address and, past the end of the region, segfaulted the traced process.
constexpr size_t kCqUmemOffsetOffset = 0x50;
constexpr size_t kCqUmemIdOffset = 0x58;
constexpr size_t kCqUmemValidOffset = 0x5c;
constexpr uint8_t kCqUmemValidBit = 0x80;
constexpr int kMaxCq = 64;
constexpr int kMaxUmem = 256;

bool enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_enabled;
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

struct Umem {
  std::atomic<int> state{kStateFree};
  void* obj;
  void* addr;
  size_t size;
  uint32_t id;
  // Consecutive scans that found no engine descriptor, and submits skipped since the last look.
  // Relaxed throughout: a race costs one extra scan of a region, never a wrong record.
  std::atomic<unsigned> empty_scans{0};
  std::atomic<unsigned> skipped{0};
  /// The entry index this queue is expected to post next, and whether it is known yet.
  ///
  /// A consumed entry is not cleared from the ring, so a scan that looks at the whole region
  /// re-finds every old entry and records it again as a fresh submit. That phantom is then
  /// displaced by the genuine submit at the same index, which is what made overwrites the single
  /// largest source of unjoined completions. Entries are posted in sequence, so the index says
  /// which ones are new.
  std::atomic<uint32_t> next_idx{0};
  std::atomic<bool> have_next{false};
};
Umem g_umem[kMaxUmem];

struct Cq {
  std::atomic<int> state{kStateFree};
  std::atomic_flag draining = ATOMIC_FLAG_INIT;
  unsigned char* buf;
  size_t entries;  // always a power of two, see cq_entries()
  size_t ci;       // monotonic consumer index; the lap count drives the owner bit
  uint32_t umem_id;
};
Cq g_cq[kMaxCq];

// What a submit asked the engine to do, from the work-queue entry it wrote. A completion cannot
// answer this: compress, DMA and AES all land as one requester completion. Work goes out as
// MLX5_OPCODE_MMO (0x2f, mlx5dv.h) and the opcode_mod beside it selects the engine. Measured on
// this device against known inputs: 0x01 DMA, 0x03 decompress deflate, 0x06 AES-GCM, 0x07 EC.
struct Wqe {
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
    return opcode_mod == o.opcode_mod && opcode == o.opcode && src_len == o.src_len &&
           dst_len == o.dst_len;
  }
};
// A completion carries no pointer back to its request, but it does carry the index of the entry
// that produced it, and a submit knows the index it wrote. So the join is by that index rather
// than by arrival order, which was wrong the moment a queue completed anything out of order.
//
// The index alone is not a full identity: two queues can have entries live at the same index. The
// completion also carries a queue number, so a run that sees more than one is told its joins are
// ambiguous rather than being left to trust them. Mapping a queue number back to the memory region
// a submit was scanned from needs the queue-creation command, which this shim does not read.
constexpr int kPendMax = 4096;
/// Empty scans of one region before it stops being walked, and how often it is looked at again.
constexpr unsigned kEmptyScansBeforeSkip = 4;
constexpr unsigned kRecheckEverySubmits = 4096;  // the submit side already refuses an index at or beyond this
struct Pending {
  std::atomic<bool> live{false};
  Wqe wqe;
};
Pending g_pend[kPendMax];

/// Slots we could not take, and queues whose layout this reader does not handle. Reported at exit:
/// silently stopping would look identical to a workload that simply made no more queues.
/// Completions whose entry index matched no outstanding submit, and submits that overwrote an
/// index still waiting for one. Both mean a joined record named the wrong operation.
std::atomic<uint64_t> g_join_miss{0};
std::atomic<uint64_t> g_join_overwrite{0};
/// The queue numbers seen completing. More than one and an index is no longer a unique identity.
std::atomic<uint32_t> g_first_qpn{0};
std::atomic<uint64_t> g_multi_qpn{0};

std::atomic<uint64_t> g_dropped_umem{0};
std::atomic<uint64_t> g_dropped_cq{0};
std::atomic<uint64_t> g_unsupported_cq{0};
std::atomic<uint64_t> g_cq_offset{0};  // CQs that did not start at the registration base
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
// Counted apart from the sweep: writing a record compresses it, so a sweep that emitted once
// reported 6.5 ms against 325 ns for an empty one, which reads as a 20000x regression it is not.
std::atomic<uint64_t> g_emit_ns{0};

bool stats_enabled() {
  return datacrumbs::ConfigurationManager::runtime().engine_stats;
}

/// The PHC dc_timesync keys its remap on. Engine CQEs are stamped by the same HCA clock as RDMA
/// ones, so any netdev under the device reports the right index.
///
/// Read with opendir, never popen. This runs inside the traced process on the completion path, and
/// popen forks: a fork in a process holding registered RDMA memory repoints those pages
/// copy-on-write, the NIC then DMAs to the wrong physical pages, and the next send fails
/// IO_FAILED. Measured: six forks per emit killed a DOCA RDMA proxy on its first send.
int g_phc = -2;  // -2 not looked up yet, -1 looked up and absent
int phc_index() {
  if (g_phc != -2) return g_phc;
  g_phc = -1;  // a failed lookup is cached too: retrying it per completion is what forked repeatedly
  for (const char* dev : {"mlx5_0", "mlx5_1", "mlx5_2"}) {
    char path[256];
    std::snprintf(path, sizeof(path), "/sys/class/infiniband/%s/device/net", dev);
    DIR* d = opendir(path);
    if (d == nullptr) continue;
    char nic[NAME_MAX + 1] = {0};
    for (const dirent* e = readdir(d); e != nullptr; e = readdir(d)) {
      if (e->d_name[0] == '.') continue;
      std::snprintf(nic, sizeof(nic), "%s", e->d_name);
      break;
    }
    closedir(d);
    if (nic[0] == '\0') continue;
    char ptp_dir[NAME_MAX + 64];
    std::snprintf(ptp_dir, sizeof(ptp_dir), "/sys/class/net/%s/device/ptp", nic);
    DIR* q = opendir(ptp_dir);
    if (q == nullptr) continue;
    for (const dirent* e = readdir(q); e != nullptr; e = readdir(q)) {
      if (strncmp(e->d_name, "ptp", 3) != 0) continue;
      g_phc = atoi(e->d_name + 3);
      break;
    }
    closedir(q);
    if (g_phc != -1) break;
  }
  return g_phc;
}


/// Name for the engine an MMO work-queue entry selects. No header here names these; each was read
/// off the queue running a sample of known input size, so the segment lengths corroborate it.
/// Work-request opcodes, from the MLX5_OPCODE enum in mlx5dv.h. The control segment packs them as
/// htonl((opmod << 24) | (index << 8) | opcode), so the opcode is byte 3 and the index bytes 1-2.
constexpr uint8_t kOpNop = 0x00;
constexpr uint8_t kOpRdmaWrite = 0x08;
constexpr uint8_t kOpRdmaWriteImm = 0x09;
constexpr uint8_t kOpSend = 0x0a;
constexpr uint8_t kOpSendImm = 0x0b;
constexpr uint8_t kOpRdmaRead = 0x10;
constexpr uint8_t kOpAtomicCs = 0x11;
constexpr uint8_t kOpAtomicFa = 0x12;
constexpr uint8_t kOpMmo = 0x2f;

const char* wqe_opcode_name(uint8_t op) {
  switch (op) {
    case kOpNop:
      return "nop";
    case kOpRdmaWrite:
      return "rdma_write";
    case kOpRdmaWriteImm:
      return "rdma_write_imm";
    case kOpSend:
      return "send";
    case kOpSendImm:
      return "send_imm";
    case kOpRdmaRead:
      return "rdma_read";
    case kOpAtomicCs:
      return "atomic_cs";
    case kOpAtomicFa:
      return "atomic_fa";
    default:
      return nullptr;
  }
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

// Whether a given opcode_mod aggregates rather than records, resolved once when the module's
// sink opens so the completion path reads a table instead of matching a glob per completion.
// Named the same way emit() names the record: "engine.<mmo_engine_name>" when the engine is
// known, else "engine.unknown" (a completion whose submit was never seen names its cqe class
// instead, which this table cannot predict ahead of time; such a completion falls back to the
// module's own mode).
bool g_agg_engine[256] = {};   // engine.<mmo>, by opcode_mod
bool g_agg_rdma[256] = {};     // rdma.<verb>, by work-request opcode
bool g_agg_cqe[16] = {};       // cqe.<class>, by CQE opcode nibble

const char* cqe_op_name(uint8_t op);  // defined below, beside the other name tables

/// Name a record from what produced it, never from a word meaning "not looked up".
///
/// An opcode this build has no name for still identifies the operation: a reader can look 0x14 up
/// in the PRM, and can do nothing at all with "unknown". Falling back to the completion class was
/// worse still, because a joined request then read as an unjoined one.
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
    const char* verb = wqe_opcode_name(w.opcode);
    if (verb != nullptr)
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

/// Resolve the capture mode for every name this module can emit.
///
/// Keyed the same way the record is named, so a selection can say `rdma.*` or `engine.dma_memcpy`
/// and mean it. Keying only on the engine table made every RDMA record resolve as engine.unknown,
/// so selective aggregation could not address them at all and the only working choice was to
/// aggregate everything, which discards the per-operation hardware timestamps that are the reason
/// this module exists.
///
/// Resolved once at startup rather than matched per record: the match is a glob, and this runs on
/// the completion path.
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

/// Name for the mlx5 CQE opcode nibble. This is the completion class, not the engine operation:
/// decompress, DMA and AES all complete as req, and which engine ran is in the work-queue entry.
/// The mlx5dv.h CQE namespace, not the work-request or ibverbs work-completion opcodes; all three
/// start at 0 and mean different things. The record carries the number too, so an unnamed opcode
/// still reaches the reader.
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

void emit(uint64_t hw_ns, uint32_t byte_cnt, uint32_t opcode, int cq_idx, uint16_t wqe_counter,
          uint32_t qpn) {
  // One queue means an entry index identifies a submit on its own. A second queue can have an
  // entry live at the same index, so the joins stop being certain and the run is told once.
  uint32_t first = g_first_qpn.load(std::memory_order_relaxed);
  if (first == 0 && qpn != 0) {
    g_first_qpn.compare_exchange_strong(first, qpn, std::memory_order_relaxed);
    first = g_first_qpn.load(std::memory_order_relaxed);
  }
  if (qpn != 0 && first != 0 && qpn != first) g_multi_qpn.fetch_add(1, std::memory_order_relaxed);

  const bool stats = stats_enabled();
  const uint64_t emit_t0 = stats ? mono_ns() : 0;
  // The submit that wrote this entry index; see the note on g_pend.
  Wqe req{};
  bool joined = false;
  if (wqe_counter < kPendMax) {
    Pending& slot = g_pend[wqe_counter];
    if (slot.live.exchange(false, std::memory_order_acquire)) {
      req = slot.wqe;
      joined = true;
      g_joined_any.store(true, std::memory_order_relaxed);
    } else {
      // No submit outstanding at that index: the record still carries the completion, but the
      // engine it names is a guess, so say so rather than report a confident wrong name.
      g_join_miss.fetch_add(1, std::memory_order_relaxed);
    }
  }
  // How it completed, beside the name that says what it was. mlx5 reserves opcodes 7-11 and
  // written() rejects them, so this only ever names a class the device really reported.
  const char* klass = cqe_op_name(static_cast<uint8_t>(opcode));
  if (klass == nullptr) klass = "reserved";
  // matched: the submit was found. startup: posted before this process attached, so there was
  // never a submit to find. missed: the scanner should have seen it and did not.
  const char* join_state =
      joined ? "matched" : (g_joined_any.load(std::memory_order_relaxed) ? "missed" : "startup");
  char namebuf[64];
  record_name_for(namebuf, sizeof(namebuf), joined, req, static_cast<uint8_t>(opcode));
  const char* record_name = namebuf;
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  // opcode_mod is a uint8_t, so every value it can hold indexes the table; no out-of-range case
  // to fall back from, unlike the uint32_t op in the ibverbs shim.
  // The CQE timestamp field is the HCA free-running counter, not a PHC-domain reading:
  // REAL_TIME_CLOCK_ENABLE is False on this firmware, so the value counts nanoseconds from device
  // reset. remap_hw expects a timestamp already on a PHC and would place these decades away;
  // remap_raw is the path that carries the raw->synced fit and its skew term.
  const int phc = phc_index();
  uint64_t ref = 0;
  if (hw_ns != 0) ref = s->clock().remap_raw(hw_ns);
  // Falling back to software time is not an error but is not the wire either, so ts says
  // which clock produced it rather than leaving a reader to infer it from the magnitude.
  const char* cqe_clock = ref != 0 ? "global" : "software";
  if (ref == 0) ref = s->clock().remap(mono_ns());

  // The completion timestamp comes off the NIC and the submit off CLOCK_MONOTONIC, and both are
  // remapped onto the same epoch, which is the whole point of the shared clock: without it these
  // two could not be subtracted at all. A submit that is not older than its completion means the
  // join is wrong or the two clocks disagree, and inventing a duration there would be worse than
  // reporting the completion alone.
  // Both ends of the duration come off CLOCK_MONOTONIC, never one off the NIC and one off the CPU.
  // Measured on this device, a completion remapped from the NIC counter lands 5.5 to 10.4 us BEFORE
  // its own submit remapped from CLOCK_MONOTONIC, which is impossible and is the alignment error
  // between the two fits. A DMA of a few tens of bytes finishes well inside that error, so a
  // duration spanning the two domains would be noise with a plausible magnitude.
  //
  // Same-domain costs the lag between the operation finishing and the poll that noticed, which is
  // sub-microsecond here and, unlike the alignment error, is a bound and not a bias.
  const unsigned long long seen_ns = mono_ns();
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
  // Same key the record was named with, so a selection addresses what a reader sees.
  const bool aggregate_this =
      joined ? (req.opcode == kOpMmo ? g_agg_engine[req.opcode_mod] : g_agg_rdma[req.opcode])
             : g_agg_cqe[opcode & 0xf];
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
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      // The engine reports when an operation finished and never when it started. A joined submit
      // supplies the start, so this is an interval whenever the join succeeded and a point when it
      // did not: COMPLETE with a zero duration would draw as a zero-width box and hide the
      // difference between instantaneous and unknown.
      R"({"id":%llu,"name":"%s","cat":")" DC_CAT R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":%u,"args":{"hhash":"%s","cqe.clock":"%s","cqe.phc":%d,"cqe.bytes":%u,"cqe.opcode":%u,"cqe.class":"%s","cqe.cq":%d,"engine.op":"%s","engine.src_len":%llu,"engine.dst_len":%llu,"cqe.submit_delta_ns":%lld,"cqe.hw_ns":%llu,"cqe.join":"%s","tool":"engine_hwts"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()), record_name, static_cast<long>(datacrumbs::client::self_pid()),
      static_cast<int>(tid()), static_cast<unsigned long long>(start / DATACRUMBS_TIME_DIVISOR_NS),
      static_cast<unsigned long long>(dur), ph, s->hhash().c_str(), cqe_clock, phc, byte_cnt,
      opcode, klass, cq_idx, namebuf, static_cast<unsigned long long>(req.src_len),
      static_cast<unsigned long long>(req.dst_len), submit_delta,
      static_cast<unsigned long long>(ref), join_state);
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

/// Usable CQE slots in a CQ umem.
///
/// The registration is one power-of-two CQE array plus a 4096-byte tail: 266240 bytes is 4096
/// entries not 4160, and 20480 is 256 not 320. Taking size/kCqeSize walks past the end of the ring
/// and breaks the owner-bit phase, which depends on the count being a power of two.
size_t cq_entries(size_t umem_size) {
  size_t n = umem_size / kCqeSize;
  size_t p = 1;
  while (p * 2 <= n) p *= 2;
  return p;
}

/// Emit every CQE the hardware has written since the last sweep.
///
/// Validity is the mlx5 owner bit checked against the consumer index, not "the opcode looks
/// plausible". Once the ring wraps, stale entries still carry defined opcodes and nonzero
/// timestamps, so an opcode-only test stops finding new work and the drain silently goes deaf.
/// Measured before this fix: 20,000 DMA jobs produced 4,096 records, exactly one ring.
void drain(Cq& cq, int idx) {
  const size_t mask = cq.entries - 1;
  for (size_t n = 0; n < cq.entries; ++n) {
    const unsigned char* e = cq.buf + (cq.ci & mask) * kCqeSize;
    const uint8_t op_own = e[kOpOwnOffset];
    const uint8_t op = static_cast<uint8_t>(op_own >> 4);
    if (!written(op)) return;
    const uint8_t phase = (cq.ci & cq.entries) != 0 ? 1 : 0;
    if ((op_own & kCqeOwnerMask) != phase) return;
    // A resize is not a work completion, and it invalidates both the entry count and the phase the
    // consumer index is riding on. Stop reading this queue rather than emit from a stale geometry.
    if (op == kCqeResize) {
      cq.buf = nullptr;
      g_unsupported_cq.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    // An error completion (0xd/0xe) carries no timestamp. Measured: a failed lz4_block reported
    // op_own=0xd2 with ts=62725, which is not a clock reading.
    const bool err = op == kCqeReqErr || op == kCqeRespErr;
    emit(err ? 0 : be64_at(e + kTsOffset), be32_at(e + kByteCntOffset), op, idx,
         be16_at(e + kWqeCounterOffset), be32_at(e + kSopDropQpnOffset) & 0xffffffu);
    ++cq.ci;
  }
}

}  // namespace

/// Record one registration. Both entry points land here: they are separate exported symbols with
/// different signatures, and hooking only the _ex form loses every umem an application registers
/// through the plain one, which silently costs us the CQ binding and so every completion.
namespace {
void note_umem(void* obj, void* addr, size_t size) {
  if (obj == nullptr) return;
  for (int i = 0; i < kMaxUmem; ++i) {
    int expect = kStateFree;
    if (!g_umem[i].state.compare_exchange_strong(expect, kStateClaimed, std::memory_order_acquire))
      continue;
    g_umem[i].obj = obj;
    g_umem[i].addr = addr;
    g_umem[i].size = size;
    g_umem[i].id = *reinterpret_cast<uint32_t*>(obj);
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
  if (enabled()) note_umem(r, addr, size);
  return r;
}

void* umem_reg_ex_wrap(void* ctx, void* in) {
  auto real = reinterpret_cast<void* (*)(void*, void*)>(gotcha_get_wrappee(g_h_umem_reg_ex));
  if (real == nullptr) return nullptr;
  void* r = real(ctx, in);
  // struct mlx5dv_devx_umem_in leads with { void *addr; size_t size; ... } and the returned
  // struct mlx5dv_devx_umem leads with uint32_t umem_id.
  if (enabled())
    note_umem(r, *reinterpret_cast<void**>(in),
              *reinterpret_cast<size_t*>(static_cast<char*>(in) + sizeof(void*)));
  return r;
}

void* obj_create_wrap(void* ctx, const void* in, size_t inlen, void* out, size_t outlen) {
  auto real = reinterpret_cast<void* (*)(void*, const void*, size_t, void*, size_t)>(
      gotcha_get_wrappee(g_h_obj_create));
  if (real == nullptr) return nullptr;
  void* r = real(ctx, in, inlen, out, outlen);
  if (!enabled() || inlen <= kCqUmemValidOffset) return r;
  const uint8_t* cmd = static_cast<const uint8_t*>(in);
  if (static_cast<uint16_t>((cmd[0] << 8) | cmd[1]) != kCreateCq) return r;
  // Bind the umem the command names, not the one registered most recently. Concurrent contexts
  // interleave their registrations, and the old heuristic would silently bind the wrong buffer.
  if ((cmd[kCqUmemValidOffset] & kCqUmemValidBit) == 0) return r;
  if (cmd[kCqcFormatOffset] != 0) {
    g_unsupported_cq.fetch_add(1, std::memory_order_relaxed);
    return r;
  }
  const uint32_t want = be32_at(cmd + kCqUmemIdOffset);
  for (int i = 0; i < kMaxUmem; ++i) {
    if (g_umem[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_umem[i].id != want) continue;
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
        g_cq[c].state.store(kStateFree, std::memory_order_release);
        return r;
      }
      g_cq[c].buf = static_cast<unsigned char*>(g_umem[i].addr) + cq_off;
      g_cq[c].ci = 0;
      g_cq[c].umem_id = want;
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
  // A context that stops destroys its CQ. Reading it afterwards is a use-after-free: measured as a
  // segfault the moment a sample ran two phases. Both slots go back to the pool.
  for (int i = 0; i < kMaxUmem; ++i) {
    if (g_umem[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_umem[i].obj != umem) continue;
    for (int c = 0; c < kMaxCq; ++c) {
      if (g_cq[c].state.load(std::memory_order_acquire) != kStateReady) continue;
      if (g_cq[c].umem_id != g_umem[i].id) continue;
      g_cq[c].buf = nullptr;
      g_cq[c].state.store(kStateFree, std::memory_order_release);
    }
    g_umem[i].addr = nullptr;
    g_umem[i].state.store(kStateFree, std::memory_order_release);
  }
  return real(umem);
}

/// Read the work-queue entry a submit just wrote, if this region holds one.
///
/// Scanned forward from a cursor, not diffed: a diff also catches payload, and EC data containing
/// 0x2f posed as a control segment claiming entry index 0x7077, which the few-thousand bound
/// rejects.
void scan_wqe(Umem& u) {
  if (u.addr == nullptr || u.size < 64 || u.size > 256 * 1024) return;
  // A region that holds no engine descriptor never will hold one this run, in the ordinary case:
  // an RDMA send queue carries send/receive/read/write entries and no MMO control segment, so
  // walking it on every submit is work that cannot find anything. Walking every registered region
  // on every submit is what made a DOCA RDMA proxy miss its transport timeout and abort.
  //
  // Learned rather than assumed, and re-checked, because a queue can be empty when first seen and
  // carry engine work later.
  if (u.empty_scans.load(std::memory_order_relaxed) >= kEmptyScansBeforeSkip) {
    if (u.skipped.fetch_add(1, std::memory_order_relaxed) + 1 < kRecheckEverySubmits) return;
    u.skipped.store(0, std::memory_order_relaxed);
  }
  bool found = false;
  const bool sequential = u.have_next.load(std::memory_order_relaxed);
  const uint32_t want = u.next_idx.load(std::memory_order_relaxed);
  uint32_t highest = 0;
  bool any = false;
  const unsigned char* base = static_cast<const unsigned char*>(u.addr);
  for (size_t off = 0; off + 64 <= u.size; off += 64) {
    const unsigned char* e = base + off;
    const uint8_t op = e[3];
    // MMO selects an engine and its opcode_mod says which; the RDMA verbs name themselves. Both
    // are read here so a requester completion can be given the verb its own CQE does not carry.
    if (op != kOpMmo && wqe_opcode_name(op) == nullptr) continue;
    const unsigned idx = static_cast<unsigned>((e[1] << 8) | e[2]);
    if (idx >= 4096) continue;
    const unsigned ds = e[7];
    // Segment count of a real entry. Payload that happens to carry a valid opcode byte rarely
    // carries a plausible one too, and a zero would name an entry with no descriptors at all.
    if (ds == 0 || ds > 16) continue;
    found = true;
    // New means at or after the index the queue was about to post, not that one index exactly:
    // several entries can be posted between two scans, and accepting only the expected one dropped
    // every entry in between. Wrap-aware, and bounded by the pending table so a stale entry from
    // the far side of the ring still reads as old.
    const uint32_t age = (idx - want) & 0xffffu;
    if (sequential && age >= static_cast<uint32_t>(kPendMax)) {
      if (!any || idx > highest) {
        highest = idx;
        any = true;
      }
      continue;
    }
    if (!any || idx > highest) {
      highest = idx;
      any = true;
    }
    Wqe w{};
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
    if (idx < kPendMax) {
      Pending& slot = g_pend[idx];
      if (slot.live.load(std::memory_order_relaxed)) {
        // The ring is walked in full on every progress call and its entries are not cleared once
        // consumed, so most of what a scan finds is what the previous scan already recorded.
        // Identical content at the same index is that rescan, not a new submit.
        if (slot.wqe == w) continue;
        // Different content at an index still waiting for its completion is a genuine reuse: the
        // earlier submit will now be joined to whatever completes next. Counted, because the
        // record it produces names an engine that did not run it.
        g_join_overwrite.fetch_add(1, std::memory_order_relaxed);
      }
      slot.wqe = w;
      slot.live.store(true, std::memory_order_release);
    }
  }
  if (any) {
    // Sequence starts at whatever the queue has already reached, so entries posted before this
    // process attached are not replayed as new work.
    u.next_idx.store((highest + 1) & 0xffffu, std::memory_order_relaxed);
    u.have_next.store(true, std::memory_order_relaxed);
  }
  if (found)
    u.empty_scans.store(0, std::memory_order_relaxed);
  else if (u.empty_scans.load(std::memory_order_relaxed) < kEmptyScansBeforeSkip)
    u.empty_scans.fetch_add(1, std::memory_order_relaxed);
}

int task_submit_wrap(void* task) {
  auto real = reinterpret_cast<int (*)(void*)>(gotcha_get_wrappee(g_h_task_submit));
  if (real == nullptr) return -1;
  const int rc = real(task);
  if (enabled())
    for (int i = 0; i < kMaxUmem; ++i)
      if (g_umem[i].state.load(std::memory_order_acquire) == kStateReady) scan_wqe(g_umem[i]);
  return rc;
}

int pe_progress_wrap(void* pe) {
  auto real = reinterpret_cast<int (*)(void*)>(gotcha_get_wrappee(g_h_pe_progress));
  if (real == nullptr) return 0;
  const int r = real(pe);
  if (r == 0 || !enabled()) return r;
  if (sink() == nullptr) {
    // The singleton builds it once, so the hand-rolled compare-and-swap that used to guard this is
    // no longer needed. This branch therefore runs at most once per process, which is also the one
    // place to resolve the aggregation table.
    datacrumbs::Singleton<EngineSink>::get_instance();
    if (sink() == nullptr) return r;
    init_agg_table();
  }
  const bool stats = stats_enabled();
  const uint64_t t0 = stats ? mono_ns() : 0;
  for (int i = 0; i < kMaxCq; ++i) {
    if (g_cq[i].state.load(std::memory_order_acquire) != kStateReady) continue;
    if (g_cq[i].buf == nullptr) continue;
    // Two threads draining one queue would emit each CQE twice. A skipped sweep is harmless: the
    // next progress call picks the entries up.
    if (g_cq[i].draining.test_and_set(std::memory_order_acquire)) continue;
    drain(g_cq[i], i);
    g_cq[i].draining.clear(std::memory_order_release);
  }
  if (stats) {
    g_drain_calls.fetch_add(1, std::memory_order_relaxed);
    g_drain_ns.fetch_add(mono_ns() - t0, std::memory_order_relaxed);
  }
  return r;
}

void datacrumbs::client::doca::init() {
  if (!enabled()) return;
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
}

void datacrumbs::client::doca::fini() {
  const uint64_t du = g_dropped_umem.load();
  const uint64_t dc = g_dropped_cq.load();
  if (du != 0 || dc != 0)
    DC_LOG_WARN("[doca_engine] slot table full: dropped %llu umem, %llu cq",
                static_cast<unsigned long long>(du), static_cast<unsigned long long>(dc));
  const uint64_t jm = g_join_miss.load();
  const uint64_t jo = g_join_overwrite.load();
  if (jm != 0 || jo != 0)
    DC_LOG_WARN(
        "[doca_engine] joined by entry index: %llu completion(s) matched no submit, %llu submit(s) "
        "overwritten before completing",
        static_cast<unsigned long long>(jm), static_cast<unsigned long long>(jo));
  const uint64_t mq = g_multi_qpn.load();
  if (mq != 0)
    DC_LOG_WARN(
        "[doca_engine] %llu completion(s) from a second queue: an entry index is not a unique "
        "identity across queues, so the engine each record names is a guess",
        static_cast<unsigned long long>(mq));
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
