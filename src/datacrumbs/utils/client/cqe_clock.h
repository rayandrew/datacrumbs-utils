#ifndef DATACRUMBS_UTILS_CLIENT_CQE_CLOCK_H
#define DATACRUMBS_UTILS_CLIENT_CQE_CLOCK_H

#include <datacrumbs/utils/timesync/timesync_raw_convert.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <dlfcn.h>
#include <infiniband/mlx5dv.h>

#include <cstdint>
#include <cstdlib>

// A CQE stamp counts its own device's free-running clock. The daemon fits one device's counter
// (its raw device); a CQ on any other device converts through that device's clock_info into its
// own PHC, which the daemon's clock registry crosses to the synced one.

namespace datacrumbs::client::cqe_clock {

using GetClockInfo = int (*)(struct ibv_context*, struct mlx5dv_clock_info*);

// libibverbs dlopens the provider privately, so this opens it by name rather than linking it.
inline GetClockInfo resolve() {
  static GetClockInfo get = nullptr;
  static bool resolved = false;
  if (!resolved) {
    resolved = true;
    void* h = dlopen("libmlx5.so.1", RTLD_LAZY | RTLD_NOLOAD);
    if (h != nullptr) get = reinterpret_cast<GetClockInfo>(dlsym(h, "mlx5dv_get_clock_info"));
  }
  return get;
}

inline uint64_t device_ns(const struct mlx5dv_clock_info& ci, uint64_t raw) {
  return datacrumbs_timesync_cycles_to_ns(ci.nsec, ci.last_cycles, ci.frac, ci.mult, ci.shift,
                                          ci.mask, raw);
}

// Same counter: the device's own last_cycles, converted through the daemon's tuple, lands on the
// device's own nsec. Another device's counter lands seconds away.
inline bool fitted(const datacrumbs::timesync::Reader& clock, const struct mlx5dv_clock_info& ci) {
  constexpr long long kSameCounterNs = 1000000;
  datacrumbs::timesync::Reader::RawClockInfo d;
  if (!clock.raw_clock_info(&d)) return false;
  const uint64_t via = datacrumbs_timesync_cycles_to_ns(d.nsec, d.last_cycles, d.frac, d.mult,
                                                        d.shift, d.mask, ci.last_cycles);
  return std::llabs(static_cast<long long>(via - ci.nsec)) < kSameCounterNs;
}

// How often a cached clock_info is reread: well inside the mask/2 bound the conversion needs.
constexpr uint64_t kRefreshNs = 100000000;

}  // namespace datacrumbs::client::cqe_clock

#endif  // DATACRUMBS_UTILS_CLIENT_CQE_CLOCK_H
