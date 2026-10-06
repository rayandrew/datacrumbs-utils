// SPDX-License-Identifier: MIT

// The marks that keep datacrumbs' own threads and I/O out of a trace. In their own header so the
// background service (background.h) and the sink (pfw_sink.h) can both include them without a
// cycle.

#ifndef DATACRUMBS_UTILS_COMMON_TRACER_THREAD_H
#define DATACRUMBS_UTILS_COMMON_TRACER_THREAD_H

#include <sched.h>

#include <cstdlib>
#include <string>

namespace datacrumbs::client {

/// Pins the calling thread to @p cpus, a taskset-style list ("2,5-7"). Empty or unparsable
/// leaves the inherited mask. For datacrumbs' own workers only: without a pin, a worker inherits
/// the application's cores and competes with it for CPU time.
inline void pin_worker(const std::string& cpus) {
  if (cpus.empty()) return;
  cpu_set_t set;
  CPU_ZERO(&set);
  const char* p = cpus.c_str();
  while (*p != '\0') {
    char* end = nullptr;
    const long lo = std::strtol(p, &end, 10);
    if (end == p) return;
    long hi = lo;
    if (*end == '-') {
      p = end + 1;
      hi = std::strtol(p, &end, 10);
      if (end == p) return;
    }
    for (long c = lo; c <= hi && c < CPU_SETSIZE; ++c)
      if (c >= 0) CPU_SET(c, &set);
    p = *end == ',' ? end + 1 : end;
  }
  if (CPU_COUNT(&set) != 0) sched_setaffinity(0, sizeof(set), &set);
}

/// True while this thread is inside datacrumbs' own I/O.
///
/// The sink writes its trace with fwrite. Without this flag, a module that wraps stdio calls
/// would also capture the sink's own write as if it were the application's I/O. A per-call guard
/// is not enough, because the sink drains on its own worker thread: the worker sets this flag for
/// its whole life, and every wrapper checks it.
inline thread_local bool g_in_datacrumbs_io = false;

/// Sets the bypass for as long as it is in scope.
struct IoBypass {
  bool prev = g_in_datacrumbs_io;
  IoBypass() { g_in_datacrumbs_io = true; }
  ~IoBypass() { g_in_datacrumbs_io = prev; }
};

}  // namespace datacrumbs::client

/// Announce a thread that only does datacrumbs' own sink I/O, so kernel probes can exclude it.
///
/// g_in_datacrumbs_io covers the userspace wrappers, but a kernel probe cannot read a thread_local,
/// and by then no file descriptor survives to check either. The server attaches to these two
/// symbols instead and keys a map on the thread id. Call once per worker, never per write.
///
/// Defined here rather than in one .cpp: every binary that owns a sink needs them, and the ones
/// that do not link the client library (window_mark) would otherwise fail to link. noinline and a
/// non-empty body keep the symbol alive for the uprobe to attach to.
extern "C" inline __attribute__((visibility("default"), noinline)) void
datacrumbs_io_thread_begin() {
  asm volatile("");
}
extern "C" inline __attribute__((visibility("default"), noinline)) void datacrumbs_io_thread_end() {
  asm volatile("");
}

namespace datacrumbs::client {

/// Marks the calling thread as a sink worker for as long as it is in scope.
struct IoThreadMark {
  IoThreadMark() { datacrumbs_io_thread_begin(); }
  ~IoThreadMark() { datacrumbs_io_thread_end(); }
};

/// Whether the calling thread is datacrumbs' own for the purpose of the GOTCHA vendor_api
/// wrappers. gotcha_wrap.h's Guard reads it beside its own g_in_wrapper: a tracer thread is
/// "already inside a wrapper", permanently.
inline thread_local bool g_tracer_thread = false;

/// For a file that cannot include gotcha_wrap.h but still must not record datacrumbs' own device
/// calls (client/doca/library.cpp's DevX hooks).
inline bool tracer_thread_active() {
  return g_tracer_thread;
}

/// Marks the calling thread as datacrumbs' own for as long as it is in scope: excludes it from
/// kernel probes (IoThreadMark) and from every GOTCHA-wrapped vendor call (g_tracer_thread). Use
/// this for any thread that calls a wrapped vendor API.
struct TracerThread {
  IoThreadMark io;
  bool prev = g_tracer_thread;
  TracerThread() { g_tracer_thread = true; }
  ~TracerThread() { g_tracer_thread = prev; }
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_COMMON_TRACER_THREAD_H
