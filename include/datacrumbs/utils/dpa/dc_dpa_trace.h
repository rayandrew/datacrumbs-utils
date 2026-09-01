// SPDX-License-Identifier: MIT

// Device-side join records for a DPA kernel. Include from a __dpa_global__ kernel and emit one
// record per completion; the host module parses them back into the trace.
//
// The device log is used rather than doca_dpa_dev_trace, which is dropped from a thread handler: it
// indexes lib_dev_p_tracer_ctx and returns on a clear enable byte that the DOCA thread path never
// sets, with no error. See dpu-trails reverse-eng/findings/op-coverage.md.

#ifndef DATACRUMBS_UTILS_DPA_TRACE_H
#define DATACRUMBS_UTILS_DPA_TRACE_H

#include <doca_dpa_dev.h>
#include <dpaintrin.h>

/// Marks a line the host parser owns. Anything else on the stream is left alone.
#define DC_DPA_TAG "DCDPA"

/// A completion the kernel just handled. wr_index and immediate are the join key: they name the
/// same mlx5 work request the peer posted, so a DPA end and an ARM end meet without a new id.
#define DC_DPA_RX(comp_element, payload)                                                        \
  DOCA_DPA_DEV_LOG_INFO(DC_DPA_TAG " rx t=%lu type=%lu wr=%lu imm=%lu ud=%lu val=%lu\n",        \
                        (unsigned long)__dpa_thread_time(),                                     \
                        (unsigned long)doca_dpa_dev_get_completion_type(comp_element),          \
                        (unsigned long)doca_dpa_dev_rdma_completion_get_wr_index(comp_element), \
                        (unsigned long)doca_dpa_dev_get_completion_immediate(comp_element),     \
                        (unsigned long)doca_dpa_dev_get_completion_user_data(comp_element),     \
                        (unsigned long)(payload))

/// A post the kernel just issued, so the peer's DC_DPA_RX can be matched to it.
#define DC_DPA_TX(payload, tag0, tag1)                                                \
  DOCA_DPA_DEV_LOG_INFO(DC_DPA_TAG " tx t=%lu sent=%lu a=%lu b=%lu\n",                \
                        (unsigned long)__dpa_thread_time(), (unsigned long)(payload), \
                        (unsigned long)(tag0), (unsigned long)(tag1))

#endif  // DATACRUMBS_UTILS_DPA_TRACE_H
