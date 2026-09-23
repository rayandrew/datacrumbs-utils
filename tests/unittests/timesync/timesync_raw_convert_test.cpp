// Regression test for the vendor raw-cycle -> ns conversion. On some firmware, mult/shift happen
// to form an identity (1 cycle == 1 ns), which can hide a bug where the raw CQE timestamp is used
// unconverted. These cases use a synthetic, non-identity mult/shift so a regression back to
// "assume raw_cycles is already ns" fails immediately instead of by luck.
//
// Plain if/return rather than assert(): this project builds Release, where assert() is compiled
// out.

#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <datacrumbs/utils/timesync/timesync_raw_convert.h>

#include <cstdio>

namespace {

// 250 MHz device clock: 1e9 ns/s / 250e6 cycles/s = 4 ns/cycle, expressed as mult/shift so the test
// stays exact integer arithmetic (mult/2^shift == 4 exactly).
dc_timesync_snapshot make_snapshot(uint64_t last_cycles, uint64_t nsec) {
  dc_timesync_snapshot s{};
  s.raw_clock_info_valid = 1;
  s.raw_clock_info_last_cycles = last_cycles;
  s.raw_clock_info_nsec = nsec;
  s.raw_clock_info_frac = 0;
  s.raw_clock_info_mult = 4u << 20;
  s.raw_clock_info_shift = 20;
  s.raw_clock_info_mask = 0x1ffffffffffull;  // 41 bits, matching known hardware
  return s;
}

bool check(const char* name, uint64_t got, uint64_t want) {
  if (got == want) return true;
  std::fprintf(stderr, "FAIL %s: got %llu want %llu\n", name, (unsigned long long)got,
               (unsigned long long)want);
  return false;
}

}  // namespace

int main() {
  bool ok = true;

  // Forward: a raw timestamp newer than the anchor advances nsec by delta_cycles * 4.
  {
    const dc_timesync_snapshot s = make_snapshot(1000, 5000000);
    ok &= check("forward", datacrumbs::timesync::raw_ts_to_ns(s, 3500), 5010000);
  }

  // Backward: a raw timestamp captured before the anchor (the normal case for a CQE that finished
  // between two clock_info refreshes) must subtract, not silently wrap into a huge forward jump.
  {
    const dc_timesync_snapshot s = make_snapshot(100000, 5000000);
    ok &= check("backward", datacrumbs::timesync::raw_ts_to_ns(s, 99000), 4996000);
  }

  // 41-bit wrap: raw_cycles has wrapped past the mask boundary and is numerically small, but is
  // really a few hundred cycles AHEAD of last_cycles. Without the mask, (raw - last) is hugely
  // negative and would be read as an enormous backward jump instead of a small forward one.
  // last_cycles sits 500 steps below the mask; the counter takes 500 steps to reach the mask, one
  // more to wrap to 0, then 200 more to reach raw_cycles: delta is 701, not the naive 700.
  {
    const uint64_t mask = 0x1ffffffffffull;
    const dc_timesync_snapshot s = make_snapshot(mask - 500, 5000000);
    ok &= check("wrap", datacrumbs::timesync::raw_ts_to_ns(s, 200), 5000000 + 701 * 4);
  }

  // A non-1:1 mult/shift must actually change the answer versus treating raw_cycles as ns: this is
  // the regression the identity firmware could not catch on its own.
  {
    const dc_timesync_snapshot s = make_snapshot(1000, 5000000);
    const uint64_t raw_cycles = 3500;
    const uint64_t got = datacrumbs::timesync::raw_ts_to_ns(s, raw_cycles);
    if (got == raw_cycles) {
      std::fprintf(stderr, "FAIL identity_regression: got == raw_cycles (%llu)\n",
                   (unsigned long long)raw_cycles);
      ok = false;
    }
  }

  // Overflow regression: with mult near 2^31, the vendor mlx5dv_ts_to_ns multiplies delta*mult in
  // plain uint64_t and overflows once delta exceeds about 4.6 seconds of cycles, producing a
  // multi-second sawtooth error well inside the 41-bit mask's normal wrap bound of about 18
  // minutes. This test uses a delta of 10 seconds, past that threshold, so it fails under plain
  // 64-bit arithmetic and passes only because raw_ts_to_ns widens to 128 bits.
  {
    dc_timesync_snapshot s{};
    s.raw_clock_info_valid = 1;
    s.raw_clock_info_last_cycles = 1000000000000ull;
    s.raw_clock_info_nsec = 5000000000000ull;
    s.raw_clock_info_frac = 0;
    s.raw_clock_info_mult = 1u << 31;
    s.raw_clock_info_shift = 31;
    s.raw_clock_info_mask = 0x1ffffffffffull;
    const uint64_t delta = 10000000000ull;  // 10 s at 1 cycle/ns
    const uint64_t got =
        datacrumbs::timesync::raw_ts_to_ns(s, s.raw_clock_info_last_cycles + delta);
    ok &= check("overflow_10s_identity_mult", got, s.raw_clock_info_nsec + delta);
  }

  if (!ok) return 1;
  std::printf("timesync_raw_convert_test: all cases passed\n");
  return 0;
}
