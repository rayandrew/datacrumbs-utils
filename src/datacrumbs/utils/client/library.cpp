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
#include <dlfcn.h>
#include <execinfo.h>
#include <infiniband/verbs.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * EXTENDED CQ (ibv_create_cq_ex) and hijack that poll dispatch. Per completion we call the real
 * symbol datacrumbs_rdma_completion(hw_ns, wr_id, opcode, imm, qp_num); datacrumbs uprobes it, so
 * each .pfw event carries the CPU timestamp (event ts) AND the NIC hardware timestamp + wire join
 * keys (args) -- the CPU<->hardware correlation eBPF cannot produce on its own.
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

static struct ibv_cq* (*dc_real_create_cq)(struct ibv_context*, int, void*,
                                           struct ibv_comp_channel*, int) = nullptr;
static int (*dc_orig_poll_cq)(struct ibv_cq*, int, struct ibv_wc*) = nullptr;
static int dc_wallclock = 0;  // 1 = NIC exposes wallclock-ns completion timestamps

// Registry of the extended CQs WE created. Hijacking context->ops.poll_cq affects every CQ on the
// context, but only ours are extended; polling a non-extended CQ as extended would deref a garbage
// start_poll pointer (the intermittent crash). So dc_poll_cq only bridges our CQs and delegates
// any other to the original provider poll.
#define DC_MAX_CQ 512
static struct ibv_cq* dc_our_cqs[DC_MAX_CQ];
static int dc_ncq = 0;
static int dc_is_ours(struct ibv_cq* cq) {
  for (int i = 0; i < dc_ncq; i++)
    if (dc_our_cqs[i] == cq) return 1;
  return 0;
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
    if (i >= ne) break;
    wc[i].wr_id = cqx->wr_id;
    wc[i].status = cqx->status;
    wc[i].opcode = ibv_wc_read_opcode(cqx);
    wc[i].wc_flags = ibv_wc_read_wc_flags(cqx);
    wc[i].byte_len = ibv_wc_read_byte_len(cqx);
    wc[i].qp_num = ibv_wc_read_qp_num(cqx);
    if (wc[i].wc_flags & IBV_WC_WITH_IMM) wc[i].imm_data = ibv_wc_read_imm_data(cqx);
    uint64_t hw =
        dc_wallclock ? ibv_wc_read_completion_wallclock_ns(cqx) : ibv_wc_read_completion_ts(cqx);
    datacrumbs_rdma_completion(hw, cqx->wr_id, (uint32_t)wc[i].opcode,
                               (wc[i].wc_flags & IBV_WC_WITH_IMM) ? wc[i].imm_data : 0,
                               wc[i].qp_num);
    i++;
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
  struct ibv_cq* ret = ibv_cq_ex_to_cq(cqx);
  if (dc_ncq < DC_MAX_CQ) dc_our_cqs[dc_ncq++] = ret;  // remember it is extended
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