// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

/**
 * @file library.cpp
 * @brief Implementation of library initialization and finalization functions
 * for the datacrumbs client.
 *
 * This file contains functions that are called when the library is loaded and
 * unloaded. These functions are responsible for initializing and finalizing the
 * library's functionality.
 */

/**
 * Standard headers
 */
#include <arpa/inet.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <execinfo.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <unordered_map>
#include <unordered_set>

/**
 * Internal headers
 */
#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/client/library.h>

#include <stddef.h>
#include <sys/mman.h>

/**
 * @brief Called when the library is loaded.
 *
 * This function logs a message indicating that the library's start function has
 * been called, along with the current process ID.
 */
extern "C" __attribute__((visibility("default"))) void datacrumbs_start() {
  int pid = getpid();
  DC_LOG_INFO("Start called (pid: %d)", pid);
}

/**
 * @brief Called when the library is unloaded.
 *
 * This function logs a message indicating that the library's stop function has
 * been called, along with the current process ID.
 */
extern "C" __attribute__((visibility("default"))) void datacrumbs_stop() {
  int pid = getpid();
  DC_LOG_INFO("Stop called (pid: %d)", pid);
}

/**
 * RDMA hardware-timestamp capture (app-agnostic, no app changes).
 *
 * The NIC timestamps every completion in hardware, but RDMA poll is kernel-bypass AND inlined
 * (ibv_poll_cq is a static inline dispatching through cq->context->ops.poll_cq), so neither eBPF
 * nor plain interposition can time the wire. Here we transparently upgrade each CQ to a timestamped
 * EXTENDED CQ (ibv_create_cq_ex) and hijack that poll dispatch. Per completion the client records the
 * NIC hardware timestamp + wire join keys to its OWN per-thread CSV (dc_hwts_emit) -- no kernel trap,
 * safe on busy-poll bulk data planes; a merge step folds it onto the unified timeline via timesync.
 * DC_HWTS_UPROBE=1 additionally drives datacrumbs_rdma_completion (the server uprobes it, landing each
 * completion directly in the .pfw) -- only for low-rate CQs; per-completion trapping deadlocks the
 * DDS SPDK backend under bulk load.
 */
extern "C" {

// emit point: the server uprobes this and captures the args. noinline + the asm clobber keep it
// a real, uninlined, argument-carrying symbol.
static unsigned long long dc_emit_count = 0;  // DC_DEBUG diagnostic only
static unsigned long long dc_post_imm = 0;  // DC_DEBUG only: count of WITH_IMM posts (wire keys)
// capture-coverage counters: silently capturing NOTHING is indistinguishable from "no traffic", which
// is how a failed CQ upgrade cost us a whole validation run. These drive the exit warning below.
static unsigned long long dc_cq_total = 0;      // ibv_create_cq calls seen
static unsigned long long dc_cq_captured = 0;   // upgraded to a timestamped extended CQ + poll hijacked
static unsigned long long dc_cq_fallback = 0;   // upgrade failed -> plain CQ, NOT captured
static unsigned long long dc_completions = 0;   // completions actually self-emitted
// hook ENTRY counts (not emits): distinguishes "our hook never ran" from "it ran but did not emit".
static unsigned long long dc_n_pollcq = 0, dc_n_startpoll = 0, dc_n_nextpoll = 0, dc_n_postsend = 0;
static unsigned long long dc_n_wrsend = 0;  // ibv_wr_* send posts (see the send-post hook)
static int dc_hwts_on(void);  // fwd decl (defined with the CQ interposition below)
// imm/qp_num: wire-observable join keys read from the completion (no app change). imm is valid on
// recv-with-immediate only (tag=imm&0xFF, slot=imm>>8); qp_num separates QPs/legs.
//
// BYTE ORDER -- known asymmetry, mind it when joining the two sides:
//   * RECV completions carry imm exactly as ibverbs delivers it = NETWORK order (verified: a peer
//     sending htonl(0,1,2,3) shows up as 0, 16777216, 33554432, 50331648).
//   * The opcode=250 POST marker carries ntohl(imm) = HOST order (0,1,2,3), because at post time we
//     read the app's own imm_data field.
// So a consumer joining sender->receiver on this key MUST ntohl the recv side first (that is what
// wire_split3.py does). Left as-is deliberately: the recv value is "what was on the wire", and
// changing it now would silently re-interpret already-validated captures.
__attribute__((noinline, visibility("default"))) void datacrumbs_rdma_completion(
    uint64_t hw_ns, uint64_t wr_id, uint32_t opcode, uint32_t imm, uint32_t qp_num) {
  __asm__ __volatile__("" ::"r"(hw_ns), "r"(wr_id), "r"(opcode), "r"(imm), "r"(qp_num) : "memory");
  dc_emit_count++;
}
__attribute__((destructor)) static void dc_emit_report(void) {
  if (getenv("DC_DEBUG"))
    fprintf(stderr,
            "[dc-client] rdma completions emitted=%llu with_imm posts=%llu self_emit=%llu "
            "cq total=%llu captured=%llu fallback=%llu (pid %d)\n",
            dc_emit_count, dc_post_imm, dc_completions, dc_cq_total, dc_cq_captured, dc_cq_fallback,
            getpid());
  if (getenv("DC_DEBUG"))
    fprintf(stderr, "[dc-client] hook entries: poll_cq=%llu start_poll=%llu next_poll=%llu "
            "post_send=%llu wr_send=%llu\n",
            dc_n_pollcq, dc_n_startpoll, dc_n_nextpoll, dc_n_postsend, dc_n_wrsend);
  // ALWAYS warn (not DC_DEBUG-gated): zero capture must never look like "no traffic".
  // The worst case is dc_cq_total == 0: we were asked to capture RDMA and never even saw a CQ created,
  // i.e. the app builds its CQ through an API we do not hook. NB ibv_create_cq_ex is a static inline
  // dispatching via context->ops.create_cq_ex, so it is invisible both to us AND to `nm` on the binary
  // -- "it imports ibv_create_cq" does NOT mean that is the path taken. Fix = hook the context ops.
  if (dc_hwts_on() && dc_cq_total == 0)
    fprintf(stderr,
            "[dc-client] WARNING: DC_HWTS on but ZERO ibv_create_cq calls were intercepted (pid %d). "
            "If this process does RDMA it is using a CQ path we do not hook (e.g. ibv_create_cq_ex, "
            "which is an inline dispatching through context->ops, or DOCA/DevX). Capture is EMPTY -- "
            "do not read that as 'no traffic'.\n",
            getpid());
  else if (dc_hwts_on() && dc_cq_total > 0 && dc_completions == 0)
    fprintf(stderr,
            "[dc-client] WARNING: DC_HWTS on, %llu CQ(s) created but ZERO completions captured"
            "%s (pid %d). RDMA is not being traced -- do not read the empty output as 'no traffic'.\n",
            dc_cq_total,
            dc_cq_fallback ? "; the timestamped-CQ upgrade FAILED so poll was not hijacked" : "",
            getpid());
  else if (dc_hwts_on() && dc_cq_fallback > 0)
    fprintf(stderr,
            "[dc-client] WARNING: %llu of %llu CQ(s) fell back to a plain CQ (no hw timestamps); "
            "capture is PARTIAL (pid %d).\n",
            dc_cq_fallback, dc_cq_total, getpid());
}

// ---- timesync clock registry: put our timestamps on the REFERENCE timeline ----
// Read once from the dc_timesync seqlock snapshot. This is what lets the client emit real trace
// events instead of an out-of-band CSV that someone has to align by hand later (that hand step is
// where a stale offset once produced 100% causality violations). We keep the RAW value in args too,
// so a bad fit can always be re-derived -- remapping must never destroy the original measurement.
struct dc_clockmap {
  int valid = 0;
  int synced_phc = -1;
  int n_clocks = 0;
  int phc_id[DC_TIMESYNC_MAX_CLOCKS];
  int64_t phc_delta[DC_TIMESYNC_MAX_CLOCKS];
  int64_t bridge_mono_to_phc_ns = 0, anchor_phc_ns = 0, offset_ns = 0, skew_ppb = 0;
  int64_t rt_minus_mono = 0;  // local CLOCK_REALTIME - CLOCK_MONOTONIC, for cpu-tier events
  uint32_t ref_id = 0, self_id = 0;
  double residual_rms_ns = 0;
};
static dc_clockmap dc_cm;
static int dc_cm_loaded = 0;

static void dc_load_clockmap() {
  const char* p = getenv("DC_TIMESYNC_SNAPSHOT");
  if (!p || !*p) p = DC_TIMESYNC_DEFAULT_PATH;
  int fd = open(p, O_RDONLY);
  if (fd >= 0) {
    void* m = mmap(nullptr, sizeof(struct dc_timesync_snapshot), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m != MAP_FAILED) {
      volatile struct dc_timesync_snapshot* s = (struct dc_timesync_snapshot*)m;
      for (int t = 0; t < 8; t++) {  // seqlock: retry while a write is in progress
        uint32_t a = __atomic_load_n((uint32_t*)&s->seq, __ATOMIC_ACQUIRE);
        if (a & 1u) continue;
        dc_cm.ref_id = s->ref_id;
        dc_cm.self_id = s->self_id;
        dc_cm.bridge_mono_to_phc_ns = s->bridge_mono_to_phc_ns;
        dc_cm.anchor_phc_ns = s->anchor_phc_ns;
        dc_cm.offset_ns = s->offset_ns;
        dc_cm.skew_ppb = s->skew_ppb;
        dc_cm.residual_rms_ns = s->residual_rms_ns;
        dc_cm.synced_phc = (s->version >= 2) ? s->synced_phc_index : -1;
        dc_cm.n_clocks = 0;
        if (s->version >= 2)
          for (uint32_t i = 0; i < s->n_clocks && i < DC_TIMESYNC_MAX_CLOCKS; i++)
            if (s->clocks[i].valid) {
              dc_cm.phc_id[dc_cm.n_clocks] = s->clocks[i].phc_index;
              dc_cm.phc_delta[dc_cm.n_clocks] = s->clocks[i].delta_to_synced_ns;
              dc_cm.n_clocks++;
            }
        uint32_t b = __atomic_load_n((uint32_t*)&s->seq, __ATOMIC_ACQUIRE);
        if (a == b && s->magic == DC_TIMESYNC_MAGIC && s->valid) dc_cm.valid = 1;
        if (a == b) break;
      }
      munmap(m, sizeof(struct dc_timesync_snapshot));
    }
  }
  struct timespec rt, mo;
  clock_gettime(CLOCK_REALTIME, &rt);
  clock_gettime(CLOCK_MONOTONIC, &mo);
  dc_cm.rt_minus_mono = (int64_t)((uint64_t)rt.tv_sec * 1000000000ull + rt.tv_nsec) -
                        (int64_t)((uint64_t)mo.tv_sec * 1000000000ull + mo.tv_nsec);
}

// Map a local timestamp onto the reference timeline. phc >= 0: t is a NIC hw ts on that PHC.
// phc < 0: t is CLOCK_REALTIME (the cpu-tier post markers). Returns 0 if we cannot place it --
// callers must then NOT pretend the event is aligned.
static uint64_t dc_to_ref_ns(uint64_t t, int phc) {
  if (!dc_cm.valid) return 0;
  int64_t synced;
  if (phc >= 0) {
    int found = 0;
    int64_t d = 0;
    for (int i = 0; i < dc_cm.n_clocks; i++)
      if (dc_cm.phc_id[i] == phc) { d = dc_cm.phc_delta[i]; found = 1; break; }
    if (!found) return 0;  // unknown clock -> refuse rather than emit a 20 s lie
    synced = (int64_t)t + d;
  } else {  // REALTIME -> MONOTONIC -> local synced PHC
    synced = ((int64_t)t - dc_cm.rt_minus_mono) + dc_cm.bridge_mono_to_phc_ns;
  }
  double drift = (double)dc_cm.skew_ppb * (double)(synced - dc_cm.anchor_phc_ns) / 1e9;
  return (uint64_t)(synced + dc_cm.offset_ns + (int64_t)drift);
}

// pfw (in-trace, self-describing: carries the clock registry) by default. DC_HWTS_FORMAT=csv keeps the
// compact sink, and it is not legacy baggage -- MEASURED 249 bytes/event as .pfw vs 52 as CSV (4.8x).
// The DDS data plane emits ~3.9M completions per run: 199MB as CSV, ~950MB as .pfw, written by the SPDK
// busy-poll reactor that a per-completion kernel trap already deadlocked once. So: .pfw for anything you
// want on the unified timeline, CSV for firehose data planes. Archived captures are CSV too, and
// experiments/lib/dc_trace.py reads both.
static int dc_fmt_pfw() {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS_FORMAT");
    v = (e && !strcmp(e, "csv")) ? 0 : 1;
  }
  return v;
}

// ---- client-side hardware-timestamp sink (per-thread, lock-free, periodically flushed) ----
// The server-uprobed datacrumbs_rdma_completion above traps the kernel PER COMPLETION; on a busy-poll
// SPDK reactor draining the DDS bulk data plane that DEADLOCKS the backend. So by default the client
// records each completion into a thread-local buffer and write()s it in batches to its own CSV -- no
// uprobe, no per-completion trap. A merge step folds these onto the unified datacrumbs timeline via
// timesync (cpu_ns is CLOCK_REALTIME = same epoch as the .pfw us clock; hw_ns is the NIC wallclock).
// Flushed every DC_SINK_FLUSH_N records (not just at destructor): the SPDK backend traps SIGTERM, so
// a destructor-only flush would lose everything. The old hot path stays available via DC_HWTS_UPROBE.
// gettid() is a SYSCALL and the .pfw line used to call it per event, on the same busy-poll thread that
// is draining the data plane. It is invariant per thread -- cache it. (Measured: the .pfw emit path cost
// 4.2x the CSV path; this and the oversized line were the difference.)
// Same story as gettid: modern glibc dropped its getpid() cache, so the .pfw line paid a SECOND
// syscall per event. Both are invariant for the life of the process/thread.
static int dc_pid_cached = 0;
static inline int dc_pid() {
  if (!dc_pid_cached) dc_pid_cached = getpid();
  return dc_pid_cached;
}
// Hand-rolled unsigned formatting. snprintf with a 12-argument format string has to parse that format
// on every completion; this is the hot path of a busy-poll data plane, and it is why the .pfw emit was
// ~9x costlier than CSV and pushed the artifact format the wrong way.
static inline char* dc_u64(char* p, uint64_t v) {
  char t[20];
  int n = 0;
  do { t[n++] = (char)('0' + (v % 10)); v /= 10; } while (v);
  while (n) *p++ = t[--n];
  return p;
}
// Byte loop, NOT memcpy: the literals are 8-20 bytes and there are ~14 of them per event, so memcpy
// here meant 14 libc calls per completion -- a profile of the traced consumer put 25.9% of its time in
// libc while dc_hwts_emit itself was 2.1%. With a constant size the compiler unrolls this into stores.
#define DC_LIT(p, lit)                                        \
  do {                                                        \
    const char* _s = (lit);                                   \
    for (size_t _i = 0; _i < sizeof(lit) - 1; _i++) *p++ = _s[_i]; \
  } while (0)
static thread_local long dc_tid_cached = 0;
static inline long dc_tid() {
  if (!dc_tid_cached) dc_tid_cached = (long)syscall(SYS_gettid);
  return dc_tid_cached;
}
#define DC_SINK_BUF 262144
#define DC_SINK_FLUSH_N dc_flush_n()
// Flush cadence trades crash-safety for syscalls. Default 256: on a firehose that is ~1 write per 256
// completions instead of per 32, and a killed proxy still leaves all but the last 256 on disk.
static int dc_flush_n() {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS_FLUSH_N");
    v = (e && *e) ? atoi(e) : 128;  // 128 measured best; 256 was notably worse on the .pfw path
    if (v < 1) v = 1;
  }
  return v;
}
struct dc_sink {
  int fd = -1;  // -2 = open failed once, stop trying
  size_t len = 0;
  unsigned n = 0;
  char buf[DC_SINK_BUF];
  ~dc_sink() {  // clean thread/process exit (e.g. host duckdb) flushes the final tail
    if (fd >= 0) {
      if (len) { ssize_t w = write(fd, buf, len); (void)w; }
      // Terminate the .pfw stream the way the datacrumbs writer does ("[" ... one object per line ...
      // "]"). A killed process cannot do this, so readers must tolerate its absence -- but on a clean
      // exit an unterminated trace is just a malformed one.
      if (dc_fmt_pfw()) { ssize_t w = write(fd, "]\n", 2); (void)w; }
      close(fd);
    }
  }
};
static thread_local dc_sink dc_ts_sink;
static int dc_uprobe_on() {  // DC_HWTS_UPROBE=1 -> ALSO drive the (hot) server-uprobe symbol
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS_UPROBE");
    v = (e && *e && e[0] != '0') ? 1 : 0;
  }
  return v;
}
static inline void dc_sink_flush(dc_sink* s) {
  if (s->fd >= 0 && s->len) {
    ssize_t w = write(s->fd, s->buf, s->len);
    (void)w;
    s->len = 0;
  }
}
// The clock registry, emitted identically into both formats (a ph:"M" metadata event for .pfw, the
// same object behind a "# " comment for CSV). Keeping ONE writer is the point: a capture that cannot
// describe its own clocks cannot be placed on the cross-node timeline, and that must not depend on
// which output format someone picked for performance reasons.
static int dc_registry_json(char* out, size_t cap, const char* prefix, long tid) {
  int o = snprintf(out, cap,
                   "%s{\"ph\":\"M\",\"name\":\"datacrumbs.clock_registry\",\"pid\":%d,"
                   "\"tid\":%ld,\"args\":{\"valid\":%d,\"ref_id\":%u,\"self_id\":%u,"
                   "\"synced_phc\":%d,\"anchor_phc_ns\":%lld,\"offset_ns\":%lld,"
                   "\"skew_ppb\":%lld,\"residual_ns\":%.0f,"
                   // CPU-clock bridge. Without these two a consumer can align hw-tier events but NOT
                   // cpu-tier ones (send posts, any uprobe-style event): the registry described the
                   // NIC clocks and silently omitted the one the CPU stamps with. Discovered when the
                   // send-post hook made producer-departure capturable and nothing could place it.
                   "\"rt_minus_mono_ns\":%lld,\"bridge_mono_to_phc_ns\":%lld,\"clocks\":[",
                   prefix, getpid(), tid, dc_cm.valid, dc_cm.ref_id, dc_cm.self_id, dc_cm.synced_phc,
                   (long long)dc_cm.anchor_phc_ns, (long long)dc_cm.offset_ns,
                   (long long)dc_cm.skew_ppb, dc_cm.residual_rms_ns,
                   (long long)dc_cm.rt_minus_mono, (long long)dc_cm.bridge_mono_to_phc_ns);
  for (int i = 0; i < dc_cm.n_clocks && o < (int)cap - 128; i++)
    o += snprintf(out + o, cap - o, "%s{\"phc\":%d,\"delta_to_synced_ns\":%lld}",
                  i ? "," : "", dc_cm.phc_id[i], (long long)dc_cm.phc_delta[i]);
  o += snprintf(out + o, cap - o, "]}}\n");
  return o;
}

static void dc_hwts_emit(uint64_t hw, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp,
                         int phc, const char* tier) {
  dc_sink* s = &dc_ts_sink;
  if (s->fd == -2) return;
  if (s->fd < 0) {  // first completion on this thread -> open <dir>/dc_hwts_<pid>_<tid>.csv
    const char* dir = getenv("DC_HWTS_OUT");
    if (!dir || !*dir) dir = getenv("DATACRUMBS_TRACE_DIR");
    if (!dir || !*dir) dir = "/tmp";
    char path[512];
    long tid = dc_tid();
    if (!dc_cm_loaded) { dc_cm_loaded = 1; dc_load_clockmap(); }
    snprintf(path, sizeof(path), "%s/dc_hwts_%d_%ld.%s", dir, getpid(), tid,
             dc_fmt_pfw() ? "pfw" : "csv");
    mkdir(dir, 0755);  // DC_HWTS_OUT pointing at a non-existent dir silently disabled capture for a
                       // whole debugging session (fd=-2 below is permanent) -- create it, and if it
                       // still fails SAY SO. A capture path must never fail quietly.
    s->fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (s->fd < 0) {
      fprintf(stderr, "[dc-client] ERROR: cannot open %s (%s) -- hw-timestamp capture DISABLED\n",
              path, strerror(errno));
      s->fd = -2;
      return;
    }
    if (!dc_fmt_pfw()) {
      // CSV carries the SAME clock registry as .pfw, as a leading # comment. Without it CSV was a
      // second-class format that could not be aligned cross-node, which is why .pfw was made the
      // default -- at 4.2x the emit cost. With the registry here, the compact format stays fully
      // self-describing and dc_trace.py/csv2pfw.py can reconstruct the trace losslessly.
      char hdr[2048];
      int o = dc_registry_json(hdr, sizeof(hdr), "# ", tid);
      o += snprintf(hdr + o, sizeof(hdr) - o, "cpu_ns,hw_ns,wr_id,opcode,imm,qp_num,phc,tier\n");
      ssize_t w = write(s->fd, hdr, o);
      (void)w;
    } else {
      // Chrome-trace stream + a ph:"M" metadata event carrying the whole clock registry, so the
      // trace is SELF-DESCRIBING: any consumer can (re)align it with no external state, no snapshot
      // file, and no per-run offset pasted into a script.
      char hdr[2048];
      int o = snprintf(hdr, sizeof(hdr), "[\n");
      o += dc_registry_json(hdr + o, sizeof(hdr) - o, "", tid);
      ssize_t w = write(s->fd, hdr, o);
      (void)w;
    }
  }
  // reserve room for the longest possible record before formatting in place
  if (s->len + 512 >= sizeof(s->buf)) dc_sink_flush(s);
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  uint64_t cpu = (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
  int k;
  if (!dc_fmt_pfw()) {
    k = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%llu,%llu,%llu,%u,%u,%u,%d,%s\n",
                 (unsigned long long)cpu, (unsigned long long)hw, (unsigned long long)wr_id, op,
                 imm, qp, phc, tier);
  } else {
    // ts on the REFERENCE timeline in us (what every .pfw consumer expects), with the raw value and
    // its clock kept in args so the mapping stays auditable/reversible. ref=0 => we could not place
    // it; emit ts=0 and say so rather than silently produce a plausible-but-wrong time.
    uint64_t ref = dc_to_ref_ns(hw ? hw : cpu, hw ? phc : -1);
    char* p = s->buf + s->len;
    DC_LIT(p, "{\"name\":\"rdma_");
    if (op == 250) DC_LIT(p, "post"); else DC_LIT(p, "completion");
    DC_LIT(p, "\",\"cat\":\"rdma_hwts\",\"ph\":\"X\",\"ts\":");
    p = dc_u64(p, ref / 1000);
    DC_LIT(p, ",\"dur\":0,\"pid\":");
    p = dc_u64(p, (uint64_t)dc_pid());
    DC_LIT(p, ",\"tid\":");
    p = dc_u64(p, (uint64_t)dc_tid());
    DC_LIT(p, ",\"args\":{\"aligned\":");
    *p++ = ref ? '1' : '0';
    DC_LIT(p, ",\"raw_ns\":");
    p = dc_u64(p, hw ? hw : cpu);
    DC_LIT(p, ",\"cpu_ns\":");
    p = dc_u64(p, cpu);
    DC_LIT(p, ",\"phc\":");
    if (phc < 0) { *p++ = '-'; p = dc_u64(p, (uint64_t)(-phc)); } else p = dc_u64(p, (uint64_t)phc);
    DC_LIT(p, ",\"tier\":\"");
    size_t tl = strlen(tier); memcpy(p, tier, tl); p += tl;
    DC_LIT(p, "\",\"wr_id\":");
    p = dc_u64(p, wr_id);
    DC_LIT(p, ",\"opcode\":");
    p = dc_u64(p, op);
    DC_LIT(p, ",\"imm\":");
    p = dc_u64(p, imm);
    DC_LIT(p, ",\"qp\":");
    p = dc_u64(p, qp);
    DC_LIT(p, "}}\n");
    k = (int)(p - (s->buf + s->len));
  }
  if (k > 0) s->len += (size_t)k;
  dc_completions++;
  if (++s->n % DC_SINK_FLUSH_N == 0 || s->len + 128 >= sizeof(s->buf)) dc_sink_flush(s);
}

static struct ibv_cq* (*dc_real_create_cq)(struct ibv_context*, int, void*,
                                           struct ibv_comp_channel*, int) = nullptr;
static int (*dc_orig_poll_cq)(struct ibv_cq*, int, struct ibv_wc*) = nullptr;
static int dc_wallclock = 0;  // 1 = NIC exposes wallclock-ns completion timestamps

// HW-ts interception costs a poll-path indirection per poll -> opt in via DC_HWTS; otherwise the
// client is a thin passthrough (native poll speed) that still provides the pid gate. Cached.
static int dc_hwts_on(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS");
    v = (e && *e && e[0] != '0') ? 1 : 0;
  }
  return v;
}

// Which PHC hardware-stamps this context's completions. A node has several independent PHCs (4 on
// BlueField) and a hw timestamp is meaningless until you know which one it came from -- that is the
// clock_id the dc_timesync registry keys its remap table on. Resolved ONCE per CQ (sysfs + one
// ethtool ioctl), never on the poll path. An ibv device can expose several netdevs and only one
// carries a PHC (e.g. mlx5_0 -> p0 has PHC 0 while pf0hpf has none), so take the first with a valid
// index. Returns -1 if unknown -> the consumer must NOT remap that timestamp.
static int dc_phc_of_context(struct ibv_context* ctx) {
  if (!ctx || !ctx->device) return -1;
  // Resolve ibv_get_device_name through dlvsym like the real ibv_create_cq above. We do NOT link
  // -libverbs, so a plain call is an unversioned undefined reference against a VERSIONED symbol; that
  // mis-binds and returns garbage (observed: a "name" pointer of 0x19, which segfaults snprintf).
  static const char* (*real_get_name)(struct ibv_device*) = nullptr;
  if (!real_get_name) {
    real_get_name =
        (const char* (*)(struct ibv_device*))dlvsym(RTLD_NEXT, "ibv_get_device_name", "IBVERBS_1.1");
    if (!real_get_name)  // unversioned fallback
      real_get_name = (const char* (*)(struct ibv_device*))dlsym(RTLD_NEXT, "ibv_get_device_name");
  }
  if (!real_get_name) return -1;
  const char* dev = real_get_name(ctx->device);
  if (getenv("DC_DEBUG"))
    fprintf(stderr, "[dc-client] phc-resolve: ctx=%p device=%p name=%s\n", (void*)ctx,
            (void*)ctx->device, dev ? dev : "(null)");
  if (!dev) return -1;
  char dir[256];
  snprintf(dir, sizeof(dir), "/sys/class/infiniband/%s/device/net", dev);
  DIR* d = opendir(dir);
  if (!d) return -1;
  int phc = -1;
  for (struct dirent* e; (e = readdir(d)) != nullptr;) {
    if (e->d_name[0] == '.') continue;
    struct ethtool_ts_info info = {};
    info.cmd = ETHTOOL_GET_TS_INFO;
    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, e->d_name, IFNAMSIZ - 1);
    ifr.ifr_data = (char*)&info;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) continue;
    int rc = ioctl(s, SIOCETHTOOL, &ifr);
    close(s);
    if (rc == 0 && info.phc_index >= 0) {
      phc = info.phc_index;
      break;
    }
  }
  closedir(d);
  return phc;
}

// Extended CQs WE created -> the PHC their timestamps are on. Only ours are extended; polling a
// non-extended CQ as extended derefs a garbage start_poll pointer -> dc_poll_cq bridges ours,
// delegates the rest. Using a map means the poll path gets the clock_id from the SAME lookup it
// already does for membership -- no extra hot-path cost.
struct dc_cqinfo {
  int phc = -1;              // clock_id these hw timestamps are on
  uint64_t wc_flags = 0;     // flags the CQ was ACTUALLY created with -> which read_*() are legal
  int (*start_poll)(struct ibv_cq_ex*, struct ibv_poll_cq_attr*) = nullptr;  // originals, when we
  int (*next_poll)(struct ibv_cq_ex*) = nullptr;                             // hook the ex poll path
  struct ibv_cq_ex* cqx = nullptr;  // kept so the exit summary can re-check our pfns are still installed
};
static std::unordered_map<struct ibv_cq*, dc_cqinfo> dc_our_cqs;
static thread_local int dc_in_poll_bridge = 0;  // set by dc_poll_cq so we do not emit twice

// ---- WITH_IMM post marker (reorder-robust wire key on the SENDER) ----
// A send completion carries no immediate, and for DDS the response-meta write (RDMA_WRITE_WITH_IMM,
// wr_id=9, imm=htonl(TailC)) is UNSIGNALED -> it has no completion at all. So at POST we emit the
// wire key (opcode=250 marker, cpu_ns post time) for every *_WITH_IMM WR. The receiver sees the same
// value as its recv imm -> TailC is a reorder-robust host<->DPU join key (survives concurrency, where
// index-order pairing fails). Cheap: the hot post path only does one opcode check per WR; the marker
// (and the sync CSV write) fire only on the rare WITH_IMM posts -- no per-completion map/lock/ring.
static int (*dc_orig_post_send)(struct ibv_qp*, struct ibv_send_wr*, struct ibv_send_wr**) = nullptr;
static int dc_post_send(struct ibv_qp* qp, struct ibv_send_wr* wr, struct ibv_send_wr** bad) {
  dc_n_postsend++;
  for (struct ibv_send_wr* w = wr; w; w = w->next) {
    if (w->opcode == IBV_WR_RDMA_WRITE_WITH_IMM || w->opcode == IBV_WR_SEND_WITH_IMM) {
      dc_post_imm++;  // DC_DEBUG only
      dc_hwts_emit(0, w->wr_id, 250, ntohl(w->imm_data), qp->qp_num, -1, "cpu");
    }
  }
  return dc_orig_post_send ? dc_orig_post_send(qp, wr, bad) : -1;
}

// bridge invoked in place of the provider poll_cq (via the hijacked context->ops.poll_cq): runs the
// extended poll, reads the hardware completion timestamp, and fills the app's legacy ibv_wc.
static int dc_poll_cq(struct ibv_cq* cq, int ne, struct ibv_wc* wc) {
  dc_n_pollcq++;
  auto it = dc_our_cqs.find(cq);
  if (it == dc_our_cqs.end())  // not an extended CQ we made -> use the real provider poll
    return dc_orig_poll_cq ? dc_orig_poll_cq(cq, ne, wc) : 0;
  const int cq_phc = it->second.phc;  // clock_id these hw timestamps are on
  struct ibv_cq_ex* cqx = (struct ibv_cq_ex*)cq;  // layout-compatible (ibv_cq_ex_to_cq is a cast)
  struct ibv_poll_cq_attr attr = {0};
  // This bridge emits for every completion itself, and the CQ's start_poll/next_poll may ALSO be
  // hooked (an app can create via _ex yet poll with legacy ibv_poll_cq). Suppress the CQ-level emit
  // for the duration so each completion is recorded exactly once.
  dc_in_poll_bridge = 1;
  if (ibv_start_poll(cqx, &attr)) {
    dc_in_poll_bridge = 0;
    return 0;  // ENOENT/empty or error
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
    uint64_t hw =
        dc_wallclock ? ibv_wc_read_completion_wallclock_ns(cqx) : ibv_wc_read_completion_ts(cqx);
    // recv-with-imm carries the wire key directly; senders emit theirs at post (opcode=250 marker).
    uint32_t imm = (wc[i].wc_flags & IBV_WC_WITH_IMM) ? wc[i].imm_data : 0;
    dc_hwts_emit(hw, cqx->wr_id, (uint32_t)wc[i].opcode, imm, wc[i].qp_num, cq_phc, "hw");
    if (dc_uprobe_on())  // opt-in hot path: per-completion kernel trap, unsafe on bulk data planes
      datacrumbs_rdma_completion(hw, cqx->wr_id, (uint32_t)wc[i].opcode, imm, wc[i].qp_num);
    i++;
    // Break BEFORE ibv_next_poll: it advances to (and consumes) the next completion, so breaking
    // after it silently DROPS that completion. Harmless for one-at-a-time busy-poll (buddy, host
    // DuckDB); fatal for burst consumers -- the DDS backend polls ne=1 with 2+ ready and hangs.
    if (i >= ne) break;
  } while (ibv_next_poll(cqx) == 0);
  ibv_end_poll(cqx);
  dc_in_poll_bridge = 0;
  return i;
}

// ---- extended-CQ poll hook ----
// An app using ibv_cq_ex polls with ibv_start_poll/ibv_next_poll, which are inlines calling function
// pointers ON THE CQ (cq->start_poll), NOT context->ops.poll_cq. So upgrading such a CQ is not enough:
// without hooking these we register the CQ and still capture nothing (measured on ib_send_lat:
// cq total=2 captured=2, self_emit=0). Hook them per-CQ and emit on each successful poll.
//
// Field safety: read_*() is only legal for fields whose flag was requested at creation, so every read
// is gated on the CQ's actual wc_flags. (Reading an unrequested field is exactly what segfaulted the
// app earlier.) wr_id/status are plain struct members and always valid.

static void dc_emit_from_cqex(struct ibv_cq_ex* cqx, const dc_cqinfo& ci) {
  if (dc_in_poll_bridge) return;  // the legacy bridge already emits for this completion
  uint32_t opcode = ibv_wc_read_opcode(cqx);  // core field, always valid
  uint32_t imm = 0;
  if (ci.wc_flags & IBV_WC_EX_WITH_IMM) {
    uint32_t f = ibv_wc_read_wc_flags(cqx);
    if (f & IBV_WC_WITH_IMM) imm = ibv_wc_read_imm_data(cqx);
  }
  uint32_t qp = (ci.wc_flags & IBV_WC_EX_WITH_QP_NUM) ? ibv_wc_read_qp_num(cqx) : 0;
  uint64_t hw = 0;
  if (ci.wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK)
    hw = ibv_wc_read_completion_wallclock_ns(cqx);
  else if (ci.wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP)
    hw = ibv_wc_read_completion_ts(cqx);
  dc_hwts_emit(hw, cqx->wr_id, opcode, imm, qp, ci.phc, "hw");
}

// The ORIGINALS are global, not per-CQ: one provider per process here, and more importantly the
// application's correctness must never depend on our bookkeeping. If our lookup misses we still call
// through and simply do not record -- an earlier version returned ENOENT on a miss, which told the app
// "no completions" forever and hung ib_send_lat. Losing capture is acceptable; breaking the app is not.
static int (*dc_orig_start_poll)(struct ibv_cq_ex*, struct ibv_poll_cq_attr*) = nullptr;
static int (*dc_orig_next_poll)(struct ibv_cq_ex*) = nullptr;

static int dc_start_poll(struct ibv_cq_ex* cqx, struct ibv_poll_cq_attr* attr) {
  dc_n_startpoll++;
  if (!dc_orig_start_poll) return ENOENT;
  int rc = dc_orig_start_poll(cqx, attr);
  if (rc == 0) {
    auto it = dc_our_cqs.find(ibv_cq_ex_to_cq(cqx));
    if (it != dc_our_cqs.end()) dc_emit_from_cqex(cqx, it->second);
  }
  return rc;
}
static int dc_next_poll(struct ibv_cq_ex* cqx) {
  dc_n_nextpoll++;
  if (!dc_orig_next_poll) return ENOENT;
  int rc = dc_orig_next_poll(cqx);
  if (rc == 0) {
    auto it = dc_our_cqs.find(ibv_cq_ex_to_cq(cqx));
    if (it != dc_our_cqs.end()) dc_emit_from_cqex(cqx, it->second);
  }
  return rc;
}

// The check must run while the app is still alive: dc_our_cqs is a static C++ object and is destroyed
// BEFORE our ((destructor)), so inspecting it there sees an empty map (measured: no output at all).
// ibv_destroy_cq is a real exported symbol, so we can interpose it and check at teardown instead.
extern "C" __attribute__((visibility("default"))) int ibv_destroy_cq(struct ibv_cq* cq) {
  static int (*real_destroy)(struct ibv_cq*) = nullptr;
  if (!real_destroy) {
    real_destroy = (int (*)(struct ibv_cq*))dlvsym(RTLD_NEXT, "ibv_destroy_cq", "IBVERBS_1.1");
    if (!real_destroy) real_destroy = (int (*)(struct ibv_cq*))dlsym(RTLD_NEXT, "ibv_destroy_cq");
  }
  if (getenv("DC_DEBUG")) {
    auto it = dc_our_cqs.find(cq);
    if (it != dc_our_cqs.end() && it->second.cqx)
      fprintf(stderr, "[dc-client] cq %p pfns at destroy: start_poll=%s next_poll=%s ops.poll_cq=%s\n",
              (void*)it->second.cqx,
              it->second.cqx->start_poll == dc_start_poll ? "OURS" : "OVERWRITTEN",
              it->second.cqx->next_poll == dc_next_poll ? "OURS" : "OVERWRITTEN",
              cq->context->ops.poll_cq == dc_poll_cq ? "OURS" : "OVERWRITTEN");
    else
      fprintf(stderr, "[dc-client] destroy of UNREGISTERED cq %p\n", (void*)cq);
  }
  dc_our_cqs.erase(cq);
  return real_destroy ? real_destroy(cq) : -1;
}

// ---- ops-table hook: catch the INLINE ibv_create_cq_ex ----
// ibv_create_cq_ex is a static inline in verbs.h dispatching through verbs_context->create_cq_ex, so
// it exports NO symbol and LD_PRELOAD can never see it (measured: a program using it yields
// cq total=0 and zero capture -- exactly the ib_send_lat failure). The only hook point is the ops
// table, reachable once we own the context -> we interpose ibv_open_device below.
int dc_opshook_level(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS_OPSHOOK");
    v = (e && *e) ? atoi(e) : 0;  // OFF by default -- see the boundary note above
  }
  return v;
}
static struct ibv_cq_ex* (*dc_orig_create_cq_ex)(struct ibv_context*,
                                                 struct ibv_cq_init_attr_ex*) = nullptr;
// Our own legacy ibv_create_cq calls ibv_create_cq_ex internally; without this guard that call would
// re-enter dc_create_cq_ex and register/flag the CQ twice.
static thread_local int dc_in_legacy_create = 0;

static struct ibv_cq_ex* dc_create_cq_ex(struct ibv_context* context,
                                         struct ibv_cq_init_attr_ex* attr) {
  if (getenv("DC_DEBUG")) fprintf(stderr, "[dc-client] ENTER dc_create_cq_ex\n");
  if (!dc_orig_create_cq_ex) return nullptr;
  if (dc_in_legacy_create || !dc_hwts_on() || !attr) return dc_orig_create_cq_ex(context, attr);
  // DC_HWTS_OPSHOOK bisect levels: 2 = pure pass-through (hook installed, we touch nothing),
  // 3 = timestamp flags only (no ops hijack, no registration), 1 = full.
  extern int dc_opshook_level(void);
  int lvl = dc_opshook_level();
  if (lvl == 2) return dc_orig_create_cq_ex(context, attr);
  dc_cq_total++;
  const uint64_t caller_flags = attr->wc_flags;  // ADD timestamps to what the app asked for
  attr->wc_flags = caller_flags | IBV_WC_STANDARD_FLAGS |
                   IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK;
  struct ibv_cq_ex* cqx = dc_orig_create_cq_ex(context, attr);
  // MUST record which timestamp field this CQ actually carries: dc_poll_cq picks
  // ibv_wc_read_completion_wallclock_ns() vs ibv_wc_read_completion_ts() from this flag, and reading
  // the field whose flag was NOT requested at creation is undefined -> it segfaults on the first
  // poll. (Omitting this line is exactly what crashed the app here; the legacy path sets it too.)
  if (cqx) dc_wallclock = 1;
  if (!cqx) {  // degrade to a raw device tick before giving up (same policy as the legacy path)
    attr->wc_flags = caller_flags | IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;
    cqx = dc_orig_create_cq_ex(context, attr);
    if (cqx) dc_wallclock = 0;
  }
  if (!cqx) {  // device refuses timestamps -> honour the app's original request, capture nothing
    attr->wc_flags = caller_flags;
    dc_cq_fallback++;
    return dc_orig_create_cq_ex(context, attr);
  }
  const uint64_t made_flags = attr->wc_flags;  // what the CQ was ACTUALLY created with
  attr->wc_flags = caller_flags;  // never leave the caller's struct mutated
  if (lvl == 3) return cqx;        // bisect: flags applied, but do not touch ops or register
  if (lvl != 5) {                  // 5 = register only, no ops hijack
    if (!dc_orig_poll_cq) dc_orig_poll_cq = context->ops.poll_cq;
    context->ops.poll_cq = dc_poll_cq;
    if (!dc_orig_post_send) dc_orig_post_send = context->ops.post_send;
    context->ops.post_send = dc_post_send;
  }
  if (lvl != 4) {                  // 4 = ops hijack only, no registration
    dc_cqinfo ci;
    ci.phc = dc_phc_of_context(context);
    ci.wc_flags = made_flags;       // augmented set -> which read_*() are legal
    ci.cqx = cqx;
    dc_our_cqs.emplace(ibv_cq_ex_to_cq(cqx), ci);
    if (!dc_orig_start_poll) dc_orig_start_poll = cqx->start_poll;
    if (!dc_orig_next_poll) dc_orig_next_poll = cqx->next_poll;
    if (cqx->start_poll == dc_orig_start_poll) cqx->start_poll = dc_start_poll;
    if (cqx->next_poll == dc_orig_next_poll) cqx->next_poll = dc_next_poll;
  }
  dc_cq_captured++;
  return cqx;
}

// Install the extended-ops hook on a freshly opened context. Factored out because a device can be
// opened through more than one entry point and we must cover them all: perftest/ib_send_lat opens via
// mlx5dv_open_device (direct verbs), so hooking only ibv_open_device left it completely uncaptured
// (measured: cq total=0).
// ---- send-POST capture: the head of the producer->consumer chain ----
// Without this the producer side is half-captured. An RC SEND completion is ACK-timed, so the only
// producer event we had fires ~2.7 us AFTER the consumer's RECV (measured, 20000/20000 messages) --
// i.e. the captures contained the ACK return leg but NOT the outbound wire, and producer->consumer
// time was simply not derivable.
//
// Two reasons the old ibv_post_send interposition never saw these sends:
//   * perftest and friends use the ibv_wr_* API ("ibv_wr* API : ON"), whose inlines dispatch through
//     function pointers ON THE QP, never through context->ops.post_send (measured: post_send=0 hook
//     entries across a whole run);
//   * the post marker was only emitted for *_WITH_IMM opcodes, and a plain SEND carries no immediate.
// So hook the QP's own wr_send/wr_send_imm, and mark EVERY send.
//
// The emit lands in the app's send path (~0.3 us), so this is opt-in via DC_HWTS_POSTHOOK and must be
// validated against an untraced baseline before any number from it is trusted -- same rule as the poll
// hook, which broke an app the last time that rule was skipped.
static int dc_posthook_on(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS_POSTHOOK");
    v = (e && *e && e[0] != '0') ? 1 : 0;
  }
  return v;
}
static void (*dc_orig_wr_send)(struct ibv_qp_ex*) = nullptr;
static void (*dc_orig_wr_send_imm)(struct ibv_qp_ex*, __be32) = nullptr;

// wr_id is set by the caller on the QP before it calls ibv_wr_send(), so it is readable here and gives
// the same join key the completion carries. Emitted AFTER the provider builds the WQE: that is the
// moment the app has finished handing the message over. NB the doorbell rings at wr_complete(), so for
// a batch this marks WQE build, not the hardware post -- for one-WR-per-iteration senders they coincide.
static void dc_wr_send(struct ibv_qp_ex* qpx) {
  dc_orig_wr_send(qpx);
  dc_n_wrsend++;
  dc_hwts_emit(0, qpx->wr_id, 250, 0, qpx->qp_base.qp_num, -1, "cpu");
}
static void dc_wr_send_imm(struct ibv_qp_ex* qpx, __be32 imm) {
  dc_orig_wr_send_imm(qpx, imm);
  dc_n_wrsend++;
  dc_hwts_emit(0, qpx->wr_id, 250, ntohl(imm), qpx->qp_base.qp_num, -1, "cpu");
}

static struct ibv_qp* (*dc_orig_create_qp_ex)(struct ibv_context*,
                                              struct ibv_qp_init_attr_ex*) = nullptr;
static struct ibv_qp* dc_create_qp_ex(struct ibv_context* context,
                                      struct ibv_qp_init_attr_ex* attr) {
  struct ibv_qp* qp = dc_orig_create_qp_ex ? dc_orig_create_qp_ex(context, attr) : nullptr;
  if (!qp || !dc_hwts_on() || !dc_posthook_on()) return qp;
  // Only a QP created with SEND_OPS_FLAGS carries the wr_* pointers; touching them otherwise would
  // dereference whatever happens to sit at that offset.
  if (!attr || !(attr->comp_mask & IBV_QP_INIT_ATTR_SEND_OPS_FLAGS)) return qp;
  struct ibv_qp_ex* qpx = ibv_qp_to_qp_ex(qp);
  if (!qpx) return qp;
  if (qpx->wr_send) {
    if (!dc_orig_wr_send) dc_orig_wr_send = qpx->wr_send;
    if (qpx->wr_send == dc_orig_wr_send) qpx->wr_send = dc_wr_send;
  }
  if (qpx->wr_send_imm) {
    if (!dc_orig_wr_send_imm) dc_orig_wr_send_imm = qpx->wr_send_imm;
    if (qpx->wr_send_imm == dc_orig_wr_send_imm) qpx->wr_send_imm = dc_wr_send_imm;
  }
  if (getenv("DC_DEBUG"))
    fprintf(stderr, "[dc-client] post-hook installed on qp %u\n", qp->qp_num);
  return qp;
}

static void dc_hook_context(struct ibv_context* ctx, const char* via) {
  if (!ctx || !dc_hwts_on() || dc_opshook_level() <= 0) return;
  struct verbs_context* vctx = verbs_get_ctx_op(ctx, create_cq_ex);
  if (getenv("DC_DEBUG"))
    fprintf(stderr, "[dc-client] ops-hook via %s: vctx=%p sz=%zu our_sizeof=%zu\n", via, (void*)vctx,
            vctx ? (size_t)vctx->sz : (size_t)0, sizeof(struct verbs_context));
  if (!vctx) return;
  if (!dc_orig_create_cq_ex) dc_orig_create_cq_ex = vctx->create_cq_ex;
  vctx->create_cq_ex = dc_create_cq_ex;
  if (dc_posthook_on()) {
    struct verbs_context* qctx = verbs_get_ctx_op(ctx, create_qp_ex);
    if (qctx) {
      if (!dc_orig_create_qp_ex) dc_orig_create_qp_ex = qctx->create_qp_ex;
      qctx->create_qp_ex = dc_create_qp_ex;
    }
  }
}

// ON by default (DC_HWTS_OPSHOOK=0 disables). Hooks the ops table so we also catch the inline
// ibv_create_cq_ex, which exports no symbol and is otherwise invisible.
__attribute__((visibility("default"))) struct ibv_context* ibv_open_device(
    struct ibv_device* device) {
  static struct ibv_context* (*real_open)(struct ibv_device*) = nullptr;
  if (!real_open) {
    real_open = (struct ibv_context* (*)(struct ibv_device*))dlvsym(RTLD_NEXT, "ibv_open_device",
                                                                   "IBVERBS_1.1");
    if (!real_open)
      real_open = (struct ibv_context* (*)(struct ibv_device*))dlsym(RTLD_NEXT, "ibv_open_device");
  }
  if (!real_open) return nullptr;
  struct ibv_context* ctx = real_open(device);
  dc_hook_context(ctx, "ibv_open_device");
  return ctx;
}

// mlx5 direct-verbs open. Declared locally (attr as void*) so we do not need mlx5dv.h or a libmlx5
// link -- we only care about the returned context. If the real symbol is absent the call fails just
// as it would without us.
__attribute__((visibility("default"))) struct ibv_context* mlx5dv_open_device(
    struct ibv_device* device, void* attr) {
  static struct ibv_context* (*real_open)(struct ibv_device*, void*) = nullptr;
  if (!real_open) {
    real_open = (struct ibv_context* (*)(struct ibv_device*, void*))dlvsym(
        RTLD_NEXT, "mlx5dv_open_device", "MLX5_1.7");
    if (!real_open)
      real_open =
          (struct ibv_context* (*)(struct ibv_device*, void*))dlsym(RTLD_NEXT, "mlx5dv_open_device");
  }
  if (!real_open) return nullptr;
  struct ibv_context* ctx = real_open(device, attr);
  dc_hook_context(ctx, "mlx5dv_open_device");
  return ctx;
}

// intercept the (versioned) legacy ibv_create_cq -> timestamped extended CQ + hijack poll dispatch.
__attribute__((visibility("default"))) struct ibv_cq* ibv_create_cq(
    struct ibv_context* context, int cqe, void* cq_context, struct ibv_comp_channel* channel,
    int comp_vector) {
  if (!dc_real_create_cq)
    dc_real_create_cq =
        (struct ibv_cq * (*)(struct ibv_context*, int, void*, struct ibv_comp_channel*, int))
            dlvsym(RTLD_NEXT, "ibv_create_cq", "IBVERBS_1.1");
  if (getenv("DC_DEBUG")) fprintf(stderr, "[dc-client] ENTER ibv_create_cq (legacy)\n");
  dc_cq_total++;
  if (!dc_hwts_on())  // opt-out of HW-ts -> native passthrough
    return dc_real_create_cq ? dc_real_create_cq(context, cqe, cq_context, channel, comp_vector)
                             : nullptr;
  dc_wallclock = 1;

  struct ibv_cq_init_attr_ex attr = {0};
  attr.cqe = cqe;
  attr.cq_context = cq_context;
  attr.channel = channel;
  attr.comp_vector = comp_vector;
  attr.wc_flags = IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK;

  // guard: this inline now dispatches through our own dc_create_cq_ex hook -- pass it through
  dc_in_legacy_create = 1;
  struct ibv_cq_ex* cqx = ibv_create_cq_ex(context, &attr);  // inline -> provider verbs-context op
  if (!cqx) {
    // WALLCLOCK unsupported on this context -> DEGRADE, don't give up: a raw (free-running device)
    // completion timestamp still gives exact same-CQ deltas, which is most of the value. Only if that
    // also fails do we hand back a plain CQ -- and then we must NOT hijack poll (dc_poll_cq would read
    // a non-extended CQ as extended and deref garbage), so capture for this CQ is genuinely zero.
    attr.wc_flags = IBV_WC_STANDARD_FLAGS | IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;
    cqx = ibv_create_cq_ex(context, &attr);
    if (cqx) {
      dc_wallclock = 0;  // hw_ns is now a raw device tick, not wallclock ns
    } else {
      dc_cq_fallback++;
      dc_wallclock = 0;
      dc_in_legacy_create = 0;
      return dc_real_create_cq ? dc_real_create_cq(context, cqe, cq_context, channel, comp_vector)
                               : nullptr;
    }
  }
  if (!dc_orig_poll_cq) dc_orig_poll_cq = context->ops.poll_cq;  // save real provider poll once
  context->ops.poll_cq = dc_poll_cq;  // the app's inlined ibv_poll_cq dispatches here
  if (!dc_orig_post_send) dc_orig_post_send = context->ops.post_send;  // for posted-imm correlation
  context->ops.post_send = dc_post_send;
  struct ibv_cq* ret = ibv_cq_ex_to_cq(cqx);
  { dc_cqinfo ci; ci.phc = dc_phc_of_context(context); ci.wc_flags = attr.wc_flags;
    dc_our_cqs.emplace(ret, ci); }
  dc_cq_captured++;
  dc_in_legacy_create = 0;
  return ret;
}

}  // extern "C"

/**
 * @brief Library initialization function.
 *
 * This function is intended to be called automatically when the library is
 * loaded. It calls the datacrumbs_start function to perform any necessary
 * startup actions.
 */
extern "C" void dc_segv_handler(int sig) {
  void* bt[40];
  int n = backtrace(bt, 40);
  fprintf(stderr, "[dc-client] SIGSEGV (sig %d) backtrace:\n", sig);
  backtrace_symbols_fd(bt, n, 2);
  _exit(139);
}

void datacrumbs_init(void) {
  if (getenv("DC_DEBUG")) signal(SIGSEGV, dc_segv_handler);
  datacrumbs_start();
}

/**
 * @brief Library finalization function.
 *
 * This function is intended to be called automatically when the library is
 * unloaded. It calls the datacrumbs_stop function to perform any necessary
 * cleanup actions.
 */
void datacrumbs_fini(void) {
  datacrumbs_stop();
}