// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_CLOCK_H
#define DATACRUMBS_UTILS_CLIENT_CLOCK_H

#include <time.h>

#include <atomic>
#include <cstdint>

#if defined(__x86_64__)
#include <x86intrin.h>
#endif

namespace datacrumbs::client {

inline std::uint64_t mono_ns_syscall() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<std::uint64_t>(t.tv_sec) * 1000000000ull +
         static_cast<std::uint64_t>(t.tv_nsec);
}

/// The CPU's own cycle counter, cheaper to read than a clock_gettime syscall. No isb before the
/// read: the barrier would order the read against the pipeline, which costs more than the extra
/// precision is worth here. Returns 0 where there is no counter.
inline std::uint64_t cycles() {
#if defined(__aarch64__)
  std::uint64_t c;
  asm volatile("mrs %0, cntvct_el0" : "=r"(c) : : "memory");
  return c;
#elif defined(__x86_64__)
  return __rdtsc();
#else
  return 0;
#endif
}

/// CLOCK_MONOTONIC nanoseconds, from the cycle counter and a calibration against the kernel clock.
/// The rate is fitted over the whole run, so it converges; the offset is refreshed every
/// millisecond, so the kernel's NTP slew (tens of ppm) costs under 10 ns between refreshes.
/// Every shim stamps its records here, from one definition.
inline std::uint64_t mono_ns_calibrated();

/// A refresh can step the offset back by the slew since the last one, under 10 ns. Callers
/// subtract stamps unsigned, so each thread's clock never runs backwards.
inline std::uint64_t mono_ns() {
  thread_local std::uint64_t last = 0;
  const std::uint64_t v = mono_ns_calibrated();
  if (v < last) return last;
  last = v;
  return v;
}

inline std::uint64_t mono_ns_calibrated() {
  struct Calib {
    std::atomic<std::uint32_t> seq{0};
    std::uint64_t base_cyc = 0, base_ns = 0, init_cyc = 0, init_ns = 0;
    double ns_per_cyc = 0;
    std::uint64_t refresh_cyc = 0;  // 0 until the rate is known
  };
  static Calib& cal = *new Calib;  // heap: still valid while static destructors run
  const std::uint64_t c = cycles();
  if (c == 0) return mono_ns_syscall();
  for (int spin = 0; spin < 8; ++spin) {
    const std::uint32_t s0 = cal.seq.load(std::memory_order_acquire);
    if (s0 & 1u) continue;
    const std::uint64_t base_cyc = cal.base_cyc, base_ns = cal.base_ns, refresh = cal.refresh_cyc;
    const double rate = cal.ns_per_cyc;
    std::atomic_thread_fence(std::memory_order_acquire);
    if (cal.seq.load(std::memory_order_relaxed) != s0) continue;
    if (refresh != 0 && c >= base_cyc && c - base_cyc < refresh)
      return base_ns + static_cast<std::uint64_t>(static_cast<double>(c - base_cyc) * rate);
    break;
  }
  // Refresh: one kernel read, then publish. A thread that loses the race uses the kernel value.
  const std::uint64_t now_cyc = cycles();
  const std::uint64_t now_ns = mono_ns_syscall();
  std::uint32_t e = cal.seq.load(std::memory_order_relaxed) & ~1u;
  if (cal.seq.compare_exchange_strong(e, e + 1, std::memory_order_acquire)) {
    if (cal.init_cyc == 0) {
      cal.init_cyc = now_cyc;
      cal.init_ns = now_ns;
    } else if (now_ns - cal.init_ns >= 10000000ull) {
      // Wait for a baseline period before trusting a fitted rate. Until then every read falls
      // back to the kernel clock. A run that finishes before the baseline window ends never gets
      // a fitted rate at all, and that is fine: it just keeps paying the syscall cost.
      cal.ns_per_cyc =
          static_cast<double>(now_ns - cal.init_ns) / static_cast<double>(now_cyc - cal.init_cyc);
      cal.refresh_cyc = static_cast<std::uint64_t>(1000000.0 / cal.ns_per_cyc);  // 1 ms
    }
    cal.base_cyc = now_cyc;
    cal.base_ns = now_ns;
    cal.seq.store(e + 2, std::memory_order_release);
  }
  return now_ns;
}

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_CLIENT_CLOCK_H
