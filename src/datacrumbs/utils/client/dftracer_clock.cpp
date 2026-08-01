// datacrumbs global-clock shim: LD_PRELOAD alongside dftracer (or any tool that timestamps with
// gettimeofday) so its events land on the dc_timesync global cross-node epoch and merge with the
// datacrumbs server trace. Interposes gettimeofday only -- dftracer is used unmodified. When no
// snapshot is mapped (or no valid fit), falls back to the real gettimeofday so nothing breaks.
//
// This shifts every gettimeofday caller in the process to the global epoch, which is a PHC-synced
// wall clock: absolute values move onto the shared axis, deltas are preserved (affine fit, skew~=1).

#define _GNU_SOURCE
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <time.h>

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

extern "C" int gettimeofday(struct timeval* tv, void* tz) {
  static int (*real)(struct timeval*, void*) = nullptr;
  if (real == nullptr) real = (int (*)(struct timeval*, void*))dlsym(RTLD_NEXT, "gettimeofday");
  if (tv == nullptr) return real(tv, tz);

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  const unsigned long long mono =
      static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
  const unsigned long long global = reader().remap(mono);
  if (global == mono) return real(tv, tz);  // no valid fit: real wall clock

  tv->tv_sec = static_cast<time_t>(global / 1000000000ULL);
  tv->tv_usec = static_cast<suseconds_t>((global % 1000000000ULL) / 1000ULL);
  return 0;
}
