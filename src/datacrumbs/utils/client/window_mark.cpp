// SPDX-License-Identifier: MIT

// Writes the boundary through the same sink every client shim uses, to avoid
// re-deriving the timesync mapping. Doing that separately drifted a window 51 s.
// Written on pid 0, the shared node lane: a short-lived process's own pid would
// give each window edge a lane holding one instant.

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
