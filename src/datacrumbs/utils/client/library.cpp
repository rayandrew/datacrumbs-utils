// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

/**
 * @file library.cpp
 * @brief Client lifecycle hooks, emitting the program's start and end as .pfw records.
 *
 * The server trace cannot bound the workload: it starts when the server attaches and ends when the
 * server stops, so on a node running a daemon its events span everything. A uprobe on main cannot
 * either, since main never returns when an app exits via exit(). A destructor does, but not under
 * SIGKILL, so consumers must tolerate a begin with no end.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/client/library.h>
#include <datacrumbs/utils/client/pfw_sink.h>

// Server-uprobe target: a noinline no-op the server probes so the marker lands in the node's own
// trace instead of a per-process sidecar. The asm keeps the args live at the probe site. Only fires
// when a probeset names it, so the sidecar stays the fallback for untraced runs.
extern "C" __attribute__((noinline, visibility("default"))) void datacrumbs_program_marker(
    uint64_t phase, uint64_t ts_us, uint64_t dur_us) {
  __asm__ __volatile__("" ::"r"(phase), "r"(ts_us), "r"(dur_us) : "memory");
}

namespace {

constexpr const char* kCat = "dc_program";

/// DC_PROGRAM_SINK=0 drops the sidecar and reports only through the uprobe target, for runs whose
/// probeset carries datacrumbs_program_marker.
bool sink_on() {
  const char* e = std::getenv("DC_PROGRAM_SINK");
  return e == nullptr || (*e != '\0' && e[0] != '0');
}

bool markers_on() {
  const char* e = std::getenv("DC_PROGRAM");
  return e == nullptr || (*e != '\0' && e[0] != '0');
}

unsigned long long mono_ns() {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<unsigned long long>(t.tv_sec) * 1000000000ULL + t.tv_nsec;
}

/// Process name, so a trace holding several preloaded processes can tell the app from a daemon.
const char* comm() {
  static char name[64] = {0};
  if (name[0] == '\0') {
    FILE* f = std::fopen("/proc/self/comm", "r");
    if (f != nullptr) {
      if (std::fgets(name, sizeof(name), f) != nullptr) name[strcspn(name, "\n")] = '\0';
      std::fclose(f);
    }
    if (name[0] == '\0') std::snprintf(name, sizeof(name), "unknown");
  }
  return name;
}

datacrumbs::client::PfwSink* g_sink = nullptr;
unsigned long long g_start_us = 0;

void emit(const char* name, unsigned long long ts_us, unsigned long long dur_us) {
  if (g_sink == nullptr) return;
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"%s","type":"marker","pid":%d,"tid":%ld,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s","exe":"%s"}})"
      "\n",
      static_cast<unsigned long long>(g_sink->next_id()), name, kCat, getpid(),
      static_cast<long>(syscall(SYS_gettid)), ts_us, dur_us, g_sink->hhash().c_str(), comm());
  if (n <= 0) return;
  g_sink->write(line, static_cast<std::size_t>(n));
  g_sink->flush();  // two records per process, and the end one must survive an abrupt teardown
}

void report(unsigned long long phase, unsigned long long ts_us, unsigned long long dur_us) {
  datacrumbs_program_marker(phase, ts_us, dur_us);
  emit(phase == 0 ? "program_begin" : "program", ts_us, dur_us);
}

/// Emit the end marker and tear the sink down. Idempotent.
void finish() {
  if (g_start_us == 0) return;
  datacrumbs::timesync::Reader clock;
  clock.map();
  const unsigned long long end_us =
      (g_sink != nullptr ? g_sink->clock() : clock).remap(mono_ns()) / 1000;
  report(1, g_start_us, end_us > g_start_us ? end_us - g_start_us : 0);
  g_start_us = 0;
  delete g_sink;
  g_sink = nullptr;
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void datacrumbs_start() {
  DC_LOG_INFO("Start called (pid: %d)", getpid());
  if (!markers_on()) return;
  if (sink_on()) g_sink = new datacrumbs::client::PfwSink("program", "DC_PROGRAM_OUT");
  datacrumbs::timesync::Reader clock;
  clock.map();
  g_start_us = (g_sink != nullptr ? g_sink->clock() : clock).remap(mono_ns()) / 1000;
  report(0, g_start_us, 0);
}

extern "C" __attribute__((visibility("default"))) void datacrumbs_stop() {
  DC_LOG_INFO("Stop called (pid: %d)", getpid());
  finish();  // no-op when datacrumbs_fini already ran; the uprobe marker is lost on this path
}

void datacrumbs_init(void) {
  datacrumbs_start();
}

void datacrumbs_fini(void) {
  // Before datacrumbs_stop, not inside it: the server uprobes that function's entry to unmark the
  // process from the pid gate (init.bpf.c trace_client_stop), and anything reported after that is
  // filtered out. Measured: the end marker was dropped for every process until this ordering.
  finish();
  datacrumbs_stop();
}
