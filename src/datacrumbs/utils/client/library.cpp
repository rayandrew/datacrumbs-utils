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
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <mutex>
#include <unordered_map>
#include <unordered_set>

/**
 * Internal headers
 */
#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/client/library.h>

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
// imm/qp_num: wire-observable join keys read from the completion (no app change). imm is valid on
// recv-with-immediate only (tag=imm&0xFF, slot=imm>>8); qp_num separates QPs/legs.
__attribute__((noinline, visibility("default"))) void datacrumbs_rdma_completion(
    uint64_t hw_ns, uint64_t wr_id, uint32_t opcode, uint32_t imm, uint32_t qp_num) {
  __asm__ __volatile__("" ::"r"(hw_ns), "r"(wr_id), "r"(opcode), "r"(imm), "r"(qp_num) : "memory");
  dc_emit_count++;
}
__attribute__((destructor)) static void dc_emit_report(void) {
  if (getenv("DC_DEBUG"))
    fprintf(stderr, "[dc-client] rdma completions emitted=%llu (pid %d)\n", dc_emit_count,
            getpid());
}

// ---- client-side hardware-timestamp sink (per-thread, lock-free, periodically flushed) ----
// The server-uprobed datacrumbs_rdma_completion above traps the kernel PER COMPLETION; on a busy-poll
// SPDK reactor draining the DDS bulk data plane that DEADLOCKS the backend. So by default the client
// records each completion into a thread-local buffer and write()s it in batches to its own CSV -- no
// uprobe, no per-completion trap. A merge step folds these onto the unified datacrumbs timeline via
// timesync (cpu_ns is CLOCK_REALTIME = same epoch as the .pfw us clock; hw_ns is the NIC wallclock).
// Flushed every DC_SINK_FLUSH_N records (not just at destructor): the SPDK backend traps SIGTERM, so
// a destructor-only flush would lose everything. The old hot path stays available via DC_HWTS_UPROBE.
#define DC_SINK_BUF 65536
#define DC_SINK_FLUSH_N 256
struct dc_sink {
  int fd = -1;  // -2 = open failed once, stop trying
  size_t len = 0;
  unsigned n = 0;
  char buf[DC_SINK_BUF];
  ~dc_sink() {  // clean thread/process exit (e.g. host duckdb) flushes the final tail
    if (fd >= 0) {
      if (len) { ssize_t w = write(fd, buf, len); (void)w; }
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
static void dc_hwts_emit(uint64_t hw, uint64_t wr_id, uint32_t op, uint32_t imm, uint32_t qp) {
  dc_sink* s = &dc_ts_sink;
  if (s->fd == -2) return;
  if (s->fd < 0) {  // first completion on this thread -> open <dir>/dc_hwts_<pid>_<tid>.csv
    const char* dir = getenv("DC_HWTS_OUT");
    if (!dir || !*dir) dir = getenv("DATACRUMBS_TRACE_DIR");
    if (!dir || !*dir) dir = "/tmp";
    char path[512];
    long tid = (long)syscall(SYS_gettid);
    snprintf(path, sizeof(path), "%s/dc_hwts_%d_%ld.csv", dir, getpid(), tid);
    s->fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (s->fd < 0) {
      s->fd = -2;
      return;
    }
    const char* hdr = "cpu_ns,hw_ns,wr_id,opcode,imm,qp_num\n";
    ssize_t w = write(s->fd, hdr, strlen(hdr));
    (void)w;
  }
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  uint64_t cpu = (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
  int k = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%llu,%llu,%llu,%u,%u,%u\n",
                   (unsigned long long)cpu, (unsigned long long)hw, (unsigned long long)wr_id, op,
                   imm, qp);
  if (k > 0) s->len += (size_t)k;
  if (++s->n % DC_SINK_FLUSH_N == 0 || s->len + 128 >= sizeof(s->buf)) dc_sink_flush(s);
}

static struct ibv_cq* (*dc_real_create_cq)(struct ibv_context*, int, void*,
                                           struct ibv_comp_channel*, int) = nullptr;
static int (*dc_orig_poll_cq)(struct ibv_cq*, int, struct ibv_wc*) = nullptr;
static int dc_wallclock = 0;  // 1 = NIC exposes wallclock-ns completion timestamps

// HW-ts interception costs a poll-path indirection per poll -> opt in via DC_HWTS; otherwise the
// client is a thin passthrough (native poll speed) that still provides the pid gate. Cached.
static int dc_hwts_on() {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("DC_HWTS");
    v = (e && *e && e[0] != '0') ? 1 : 0;
  }
  return v;
}

// Extended CQs WE created (O(1) membership). Only ours are extended; polling a non-extended CQ as
// extended derefs a garbage start_poll pointer -> dc_poll_cq bridges ours, delegates the rest.
static std::unordered_set<struct ibv_cq*> dc_our_cqs;
static inline int dc_is_ours(struct ibv_cq* cq) {
  return dc_our_cqs.find(cq) != dc_our_cqs.end();
}

// ---- posted-imm correlation (reorder-robust per-message wire key on the SENDER) ----
// A SEND completion carries no immediate, but the wire key (for DDS the response-ring TailC =
// htonl(imm) on RDMA_WRITE_WITH_IMM) is known at POST. RC QP completions are in-order with the
// SIGNALED posts on that QP, so a per-QP ring of posted imms (pushed at post, popped at completion)
// lets each send completion recover its posted imm. Joining host(recv imm) == DPU(posted imm) is then
// robust to cross-QP reordering (concurrency), unlike index-order pairing. Opt-in via DC_HWTS (same
// gate as the CQ upgrade). Single-reactor SPDK posts+polls a QP on one thread -> no lock; DC_QRING
// >> in-flight depth keeps push/pop aligned (only SIGNALED posts are pushed, matching completions).
#define DC_QRING 8192
struct dc_qimm {
  uint32_t ring[DC_QRING];
  uint64_t post = 0, done = 0;
};
static std::unordered_map<uint32_t, dc_qimm*> dc_qimm_map;  // keyed by qp_num
static std::mutex dc_qimm_mtx;  // guards the MAP only (concurrent host has many threads); the per-QP
                                // ring is single-threaded (one QP is serviced by one thread).
static dc_qimm* dc_qimm_for(uint32_t qpn) {
  std::lock_guard<std::mutex> lk(dc_qimm_mtx);
  auto it = dc_qimm_map.find(qpn);
  if (it != dc_qimm_map.end()) return it->second;
  dc_qimm* q = new dc_qimm();
  dc_qimm_map[qpn] = q;
  return q;
}
static int (*dc_orig_post_send)(struct ibv_qp*, struct ibv_send_wr*, struct ibv_send_wr**) = nullptr;
// hijacked context->ops.post_send: record each SIGNALED post's imm (0 unless *_WITH_IMM) per QP, in
// order, so the matching send completion can recover it. Delegates to the real provider post_send.
static int dc_post_send(struct ibv_qp* qp, struct ibv_send_wr* wr, struct ibv_send_wr** bad) {
  dc_qimm* q = dc_qimm_for(qp->qp_num);
  for (struct ibv_send_wr* w = wr; w; w = w->next) {
    if (!(w->send_flags & IBV_SEND_SIGNALED)) continue;  // only signaled WRs complete
    uint32_t imm = 0;
    if (w->opcode == IBV_WR_RDMA_WRITE_WITH_IMM || w->opcode == IBV_WR_SEND_WITH_IMM)
      imm = ntohl(w->imm_data);
    q->ring[q->post++ & (DC_QRING - 1)] = imm;
  }
  return dc_orig_post_send ? dc_orig_post_send(qp, wr, bad) : -1;
}
// recv-class completions carry the received immediate directly; send-class recover it from the ring.
static inline int dc_is_recv_op(unsigned op) {
  return op == IBV_WC_RECV || op == IBV_WC_RECV_RDMA_WITH_IMM;
}

// bridge invoked in place of the provider poll_cq (via the hijacked context->ops.poll_cq): runs the
// extended poll, reads the hardware completion timestamp, and fills the app's legacy ibv_wc.
static int dc_poll_cq(struct ibv_cq* cq, int ne, struct ibv_wc* wc) {
  if (!dc_is_ours(cq))  // not an extended CQ we made -> use the real provider poll
    return dc_orig_poll_cq ? dc_orig_poll_cq(cq, ne, wc) : 0;
  struct ibv_cq_ex* cqx = (struct ibv_cq_ex*)cq;  // layout-compatible (ibv_cq_ex_to_cq is a cast)
  struct ibv_poll_cq_attr attr = {0};
  if (ibv_start_poll(cqx, &attr)) return 0;  // ENOENT/empty or error
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
    // imm = the wire key. Recv-class: the received immediate. Send-class: the posted immediate
    // recovered from the per-QP ring (the completion itself carries none) -> both sides share TailC.
    uint32_t imm;
    if (dc_is_recv_op(wc[i].opcode)) {
      imm = (wc[i].wc_flags & IBV_WC_WITH_IMM) ? wc[i].imm_data : 0;
    } else {
      dc_qimm* q = dc_qimm_for(wc[i].qp_num);
      imm = (q->done < q->post) ? q->ring[q->done++ & (DC_QRING - 1)] : 0;
    }
    dc_hwts_emit(hw, cqx->wr_id, (uint32_t)wc[i].opcode, imm, wc[i].qp_num);  // client self-emit
    if (dc_uprobe_on())  // opt-in hot path: per-completion kernel trap, unsafe on bulk data planes
      datacrumbs_rdma_completion(hw, cqx->wr_id, (uint32_t)wc[i].opcode, imm, wc[i].qp_num);
    i++;
    // Break BEFORE ibv_next_poll: it advances to (and consumes) the next completion, so breaking
    // after it silently DROPS that completion. Harmless for one-at-a-time busy-poll (buddy, host
    // DuckDB); fatal for burst consumers -- the DDS backend polls ne=1 with 2+ ready and hangs.
    if (i >= ne) break;
  } while (ibv_next_poll(cqx) == 0);
  ibv_end_poll(cqx);
  return i;
}

// intercept the (versioned) legacy ibv_create_cq -> timestamped extended CQ + hijack poll dispatch.
__attribute__((visibility("default"))) struct ibv_cq* ibv_create_cq(
    struct ibv_context* context, int cqe, void* cq_context, struct ibv_comp_channel* channel,
    int comp_vector) {
  if (!dc_real_create_cq)
    dc_real_create_cq =
        (struct ibv_cq * (*)(struct ibv_context*, int, void*, struct ibv_comp_channel*, int))
            dlvsym(RTLD_NEXT, "ibv_create_cq", "IBVERBS_1.1");
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

  struct ibv_cq_ex* cqx = ibv_create_cq_ex(context, &attr);  // inline -> provider verbs-context op
  if (!cqx) {  // device lacks timestamped CQ support -> fall back so we never break the app
    dc_wallclock = 0;
    return dc_real_create_cq ? dc_real_create_cq(context, cqe, cq_context, channel, comp_vector)
                             : nullptr;
  }
  if (!dc_orig_poll_cq) dc_orig_poll_cq = context->ops.poll_cq;  // save real provider poll once
  context->ops.poll_cq = dc_poll_cq;  // the app's inlined ibv_poll_cq dispatches here
  if (!dc_orig_post_send) dc_orig_post_send = context->ops.post_send;  // for posted-imm correlation
  context->ops.post_send = dc_post_send;
  struct ibv_cq* ret = ibv_cq_ex_to_cq(cqx);
  dc_our_cqs.insert(ret);
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