#ifndef DATACRUMBS_UTILS_TIMESYNC_RAW_CONVERT_H
#define DATACRUMBS_UTILS_TIMESYNC_RAW_CONVERT_H

#include <datacrumbs/common/dc_timesync_snapshot.h>

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

// Raw HCA cycle count -> nanoseconds. Plain C so both the daemon (dc_timesync.c) and the C++ reader
// share this one implementation instead of each carrying its own copy of the overflow fix below.

#ifdef __cplusplus
extern "C" {
#endif

// Port of the vendor mlx5dv_ts_to_ns (rdma-core, infiniband/mlx5dv.h, dual GPLv2/BSD),
// reimplemented so callers that never touch a raw HCA timestamp are not forced to depend on
// libibverbs. Widens the intermediate multiply to 128 bits: the vendor version multiplies in plain
// uint64_t and overflows past about 4.6 seconds of staleness when mult is near 2^31, which produces
// a sawtooth error in the result.

// `clock_info->mask` (raw_clock_info_mask) bounds how far `raw_cycles` may sit from
// raw_clock_info_last_cycles before the modular delta below wraps to the wrong sign.
// See raw_clock_info_valid in dc_timesync_snapshot.h for how the snapshot stays fresh enough
// that this never matters in practice.
static inline uint64_t datacrumbs_timesync_raw_ts_to_ns(const struct dc_timesync_snapshot* s,
                                                        uint64_t raw_cycles) {
  uint64_t delta = (raw_cycles - s->raw_clock_info_last_cycles) & s->raw_clock_info_mask;
  uint64_t nsec = s->raw_clock_info_nsec;
  if (delta > s->raw_clock_info_mask / 2) {
    delta = (s->raw_clock_info_last_cycles - raw_cycles) & s->raw_clock_info_mask;
    nsec -= (uint64_t)(((__uint128_t)delta * s->raw_clock_info_mult - s->raw_clock_info_frac) >>
                       s->raw_clock_info_shift);
  } else {
    nsec += (uint64_t)(((__uint128_t)delta * s->raw_clock_info_mult + s->raw_clock_info_frac) >>
                       s->raw_clock_info_shift);
  }
  return nsec;
}

#ifdef __cplusplus
}  // extern "C"
#endif

#ifdef __cplusplus
namespace datacrumbs::timesync {
inline uint64_t raw_ts_to_ns(const dc_timesync_snapshot& s, uint64_t raw_cycles) {
  return datacrumbs_timesync_raw_ts_to_ns(&s, raw_cycles);
}
}  // namespace datacrumbs::timesync
#endif

#endif  // DATACRUMBS_UTILS_TIMESYNC_RAW_CONVERT_H
