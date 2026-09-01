// SPDX-License-Identifier: MIT

// Writes one window boundary into the trace, on the trace's own clock.
//
// A harness that stamps a window with the node's wall clock has to reproduce the mapping the
// timesync plugin applies to every event, and reproducing it is what went wrong: one run put every
// window 51 s ahead of its own trace, which files each configuration's events under a later one and
// looks like nothing is wrong. Writing the boundary through the same sink every client shim uses
// removes the second implementation rather than correcting it.
//
//   datacrumbs_window_mark                       print the current time on the trace's timeline
//   datacrumbs_window_mark <label> <begin|end>   write the boundary
//
// The boundary is written on pid 0, the node lane the samplers already use, not on this process.
// Each invocation is a separate short-lived process, so attributing the marker to its own pid gave
// every window edge a process lane of its own holding one instant and nothing else.
//
// Asking the time is the default because it is the question anything outside datacrumbs has to ask
// before it can say when something happened, and answering it here is what keeps the mapping in one
// place. The harness
// used to add the timesync offset to a wall-clock reading, but that offset maps PHC time onto the
// reference timeline, not wall clock onto it, so it skipped the monotonic-to-PHC bridge and mixed
// two domains. It was out by 51 s against 25 s windows.

#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <time.h>

#include <cstdio>
#include <cstring>

namespace {
using datacrumbs::client::mono_ns;

}  // namespace

int main(int argc, char** argv) {
  if (argc == 1 || (argc == 2 && std::strcmp(argv[1], "--now") == 0)) {
    datacrumbs::client::PfwSink probe("window", DATACRUMBS_ENV_WINDOW_OUT);
    std::printf("%llu\n", static_cast<unsigned long long>(probe.clock().remap(mono_ns()) /
                                                          DATACRUMBS_TIME_DIVISOR_NS));
    return 0;
  }
  if (argc < 3) {
    std::fprintf(stderr, "usage: %s [<label> <begin|end>]\n", argv[0]);
    return 2;
  }
  const char* label = argv[1];
  const char* edge = argv[2];
  if (std::strcmp(edge, "begin") != 0 && std::strcmp(edge, "end") != 0) {
    std::fprintf(stderr, "%s: edge must be begin or end, got '%s'\n", argv[0], edge);
    return 2;
  }

  datacrumbs::client::PfwSink sink("window", DATACRUMBS_ENV_WINDOW_OUT);
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"window","type":"marker","pid":0,"tid":0,"ts":%llu,"ph":2,"args":{"hhash":"%s","edge":"%s","tool":"window_mark"}})"
      "\n",
      static_cast<unsigned long long>(sink.next_id()), label,
      static_cast<unsigned long long>(sink.clock().remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS),
      sink.hhash().c_str(), edge);
  if (n <= 0) return 1;
  sink.write(line, static_cast<std::size_t>(n));
  sink.flush();
  return 0;
}
