/* SPDX-License-Identifier: MIT */

/* DPA-side half of the clock anchor: pairs the DPA clock with the global epoch via dpa/library.cpp
 * on the host. A blocking RPC, not a launched kernel: doca_dpa_rpc returns the value directly, so
 * no completion event or host/device copy is needed to get one reading off the device.
 */

#include <doca_dpa_dev.h>
#include <doca_dpa_dev_buf.h>
#include <dpaintrin.h>
#include <stdint.h>

__dpa_rpc__ uint64_t dc_dpa_anchor_kernel(void) {
  return (uint64_t)__dpa_thread_time();
}

/* Window-mode burst kernel (host module: dpa/library.cpp). Each slot is its own 64B block: DPA
 * window accesses are 64B aligned, so an Arm-written field and a DPA-written field must not share
 * a cache line, or one side's write clobbers the other's.
 */
struct dc_dpa_window_slot {
  uint64_t a;
  uint64_t b;
  uint8_t pad[48];
};

struct dc_dpa_window_mem {
  struct dc_dpa_window_slot pulse; /* DPA writes: a=seq, b=dpa_us. The Arm's clock samples. */
  struct dc_dpa_window_slot req;   /* Arm writes: a=request seq, for the round-trip probe. */
  struct dc_dpa_window_slot resp;  /* DPA writes: a=echoed seq, b=dpa_us at echo. */
  struct dc_dpa_window_slot ctrl;  /* Arm writes: a=1 to end the burst. */
};

/* Ends when the Arm sets ctrl.a, or after 4 x burst_us on the DPA clock if the Arm never does.
 * m is volatile so the compiler cannot hoist the loop's loads and hide the stop flag.
 * mmap_handle is widened to uint64_t to keep the host's variadic launch call unambiguous.
 */
__dpa_global__ void dc_dpa_window_kernel(uint64_t mmap_handle, uint64_t mem_addr,
                                         uint64_t burst_us) {
  volatile struct dc_dpa_window_mem* m =
      (volatile struct dc_dpa_window_mem*)doca_dpa_dev_mmap_get_external_ptr(
          (doca_dpa_dev_mmap_t)mmap_handle, mem_addr);
  if (m == 0) return;

  const uint64_t t0 = (uint64_t)__dpa_thread_time();
  const uint64_t end = t0 + 4 * burst_us;
  uint64_t seq = 0;
  uint64_t last_req = 0;

  while ((uint64_t)__dpa_thread_time() < end) {
    seq++;
    m->pulse.a = seq;
    m->pulse.b = (uint64_t)__dpa_thread_time();
    __dpa_thread_window_writeback();

    __dpa_thread_window_read_inv();
    if (m->ctrl.a != 0) break;
    const uint64_t req = m->req.a;
    if (req != last_req) {
      last_req = req;
      m->resp.a = req;
      m->resp.b = (uint64_t)__dpa_thread_time();
      __dpa_thread_window_writeback();
    }
  }
}
