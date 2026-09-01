// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_CLOCK_H
#define DATACRUMBS_UTILS_CLIENT_CLOCK_H

#include <time.h>

#include <cstdint>

namespace datacrumbs::client {

/// Nanoseconds on CLOCK_MONOTONIC. Every shim stamps its records here, from one definition: a
/// timestamp wrong in one shim and right in the rest is not a difference a trace shows.
inline std::uint64_t mono_ns() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<std::uint64_t>(t.tv_sec) * 1000000000ull +
         static_cast<std::uint64_t>(t.tv_nsec);
}

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_CLIENT_CLOCK_H
