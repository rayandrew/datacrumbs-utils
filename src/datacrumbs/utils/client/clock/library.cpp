// Interposes gettimeofday only, so the wrapped tool is unmodified. Falls back to the
// real call when no snapshot is mapped or the fit is invalid.
// Shifts callers onto the global epoch, a PHC-synced wall clock: absolute values move
// onto the shared axis, deltas are preserved (affine fit, skew ~= 1).

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <datacrumbs/common/logging.h>
#include <datacrumbs/utils/client/clock/library.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <gotcha/gotcha.h>
#include <sys/time.h>
#include <time.h>

#include <cstdio>

namespace {
datacrumbs::timesync::Reader& reader() {
  static datacrumbs::timesync::Reader r = [] {
    datacrumbs::timesync::Reader x;
    x.map();
    return x;
  }();
  return r;
}
}  // namespace

namespace {
gotcha_wrappee_handle_t g_h_gettimeofday;
}

// Wrapped through GOTCHA like every other module. Defining the symbol and chaining with dlsym is
// what made two shims segfault together, each resolving a pointer the other had redirected.
static int gettimeofday_dcwrap(struct timeval* tv, void* tz) {
  auto real =
      reinterpret_cast<int (*)(struct timeval*, void*)>(gotcha_get_wrappee(g_h_gettimeofday));
  if (real == nullptr) return -1;
  if (tv == nullptr) return real(tv, tz);

  const unsigned long long mono = datacrumbs::client::mono_ns();
  const unsigned long long global = reader().remap(mono);
  if (global == mono) return real(tv, tz);  // no valid fit: real wall clock

  tv->tv_sec = static_cast<time_t>(global / 1000000000ULL);
  tv->tv_usec = static_cast<suseconds_t>((global % 1000000000ULL) / 1000ULL);
  return 0;
}

void datacrumbs::client::clock::init() {
  if (!datacrumbs::ConfigurationManager::runtime().clock_enabled) return;
  static gotcha_binding_t bindings[] = {
      {"gettimeofday", reinterpret_cast<void*>(gettimeofday_dcwrap), &g_h_gettimeofday},
  };
  const gotcha_error_t rc = ::gotcha_wrap(bindings, 1, "datacrumbs_clock");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[clock] gotcha_wrap failed: %d", static_cast<int>(rc));
}

void datacrumbs::client::clock::fini() {}
