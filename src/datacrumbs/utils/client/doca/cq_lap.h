#ifndef DATACRUMBS_UTILS_CLIENT_DOCA_CQ_LAP_H
#define DATACRUMBS_UTILS_CLIENT_DOCA_CQ_LAP_H

#include <cstdint>

/// The completion queue's two "did the sweep miss anything" tests, with no device and no globals
/// so they can be driven from a test. The sweep in library.cpp owns the queue walk and calls in.
namespace datacrumbs::utils::doca_cq {

/// The hardware's entry counter is 16 bits and wraps; a work queue is never deeper than the
/// completion queue it reports to.
constexpr uint32_t kCtrWrap = 0x10000;

/// One queue pair's running view of that counter, carried across sweeps.
struct CtrTrack {
  uint16_t last = 0;
  uint16_t stride = 0;  ///< smallest step seen inside one sweep: one operation's worth
  bool have = false;
  bool is_static = false;     ///< a counter that never moves says nothing about gaps
  bool seen_this_sweep = false;
};

/// Completions the sweep missed, from a forward jump in the entry counter between two sweeps.
/// Updates @p t. Returns 0 while the step is one operation, a rescan, or the work queue's own
/// index wrapping backwards at its depth.
inline uint32_t missed_from_counter(CtrTrack& t, uint16_t ctr, uint32_t cq_entries) {
  uint32_t missed = 0;
  if (t.have) {
    const uint16_t delta = static_cast<uint16_t>(ctr - t.last);
    if (delta == 0) {
      t.is_static = true;
    } else if (t.seen_this_sweep) {
      if (t.stride == 0 || delta < t.stride) t.stride = delta;
    } else if (!t.is_static && t.stride != 0 && delta >= 2 * t.stride &&
               delta < kCtrWrap - cq_entries) {
      missed = delta / t.stride - 1;
    }
  }
  t.last = ctr;
  t.have = true;
  t.seen_this_sweep = true;
  return missed;
}

/// Whether an entry whose owner bit does not match the phase is a whole lap ahead rather than one
/// the hardware has not written yet. The entry just consumed tells them apart: its counter moved
/// since it was read, so the hardware has been past here again.
inline bool is_lap_not_empty(const CtrTrack& prev, bool prev_written, uint16_t prev_ctr) {
  return prev.have && !prev.is_static && prev_written && prev_ctr != prev.last;
}

}  // namespace datacrumbs::utils::doca_cq

#endif  // DATACRUMBS_UTILS_CLIENT_DOCA_CQ_LAP_H
