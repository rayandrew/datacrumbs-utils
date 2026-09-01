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

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/client/clock/library.h>
#include <datacrumbs/utils/client/doca/library.h>
#include <datacrumbs/utils/client/dpa/library.h>
#include <datacrumbs/utils/client/ibverbs/library.h>
#include <datacrumbs/utils/client/library.h>
#include <datacrumbs/utils/client/posix/library.h>
#include <datacrumbs/utils/client/stdio/library.h>
#include <datacrumbs/utils/client/wrap/library.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// Server-uprobe target: a noinline no-op the server probes so the marker lands in the node's own
// trace instead of a per-process sidecar. The asm keeps the args live at the probe site. Only fires
// when a probeset names it, so the sidecar stays the fallback for untraced runs.
extern "C" __attribute__((noinline, visibility("default"))) void datacrumbs_program_marker(
    uint64_t phase, uint64_t ts_us, uint64_t dur_us) {
  __asm__ __volatile__("" ::"r"(phase), "r"(ts_us), "r"(dur_us) : "memory");
}

namespace {
using datacrumbs::client::mono_ns;

constexpr const char* kCat = "dc_program";

/// DC_PROGRAM_SINK=0 drops the sidecar and reports only through the uprobe target, for runs whose
/// probeset carries datacrumbs_program_marker.
bool sink_on() {
  return datacrumbs::ConfigurationManager::runtime().program_sink;
}

bool markers_on() {
  return datacrumbs::ConfigurationManager::runtime().program_enabled;
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

/// The program marker sink, held by the singleton. A type of its own because Singleton keys on the
/// type and every module has a sink of its own, which must not be shared.
struct ProgramSink {
  datacrumbs::client::PfwSink sink{"program", DATACRUMBS_ENV_PROGRAM_OUT};
};

/// Borrowed, and null when the run asked for markers without a sink of their own.
inline datacrumbs::client::PfwSink* sink() {
  ProgramSink* s = datacrumbs::Singleton<ProgramSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}
unsigned long long g_start_us = 0;

void emit(const char* name, unsigned long long ts_us, unsigned long long dur_us) {
  if (sink() == nullptr) return;
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"%s","type":"marker","pid":%d,"tid":%ld,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s","exe":"%s"}})"
      "\n",
      static_cast<unsigned long long>(sink()->next_id()), name, kCat, datacrumbs::client::self_pid(),
      static_cast<long>(datacrumbs::client::self_tid()), ts_us, dur_us, sink()->hhash().c_str(), comm());
  if (n <= 0) return;
  sink()->write(line, static_cast<std::size_t>(n));
  sink()->flush();  // two records per process, and the end one must survive an abrupt teardown
}

/// Emit a pid-keyed metadata record, the dftracer convention for labelling a process.
void emit_metadata(const char* name, const char* key, const char* value) {
  if (sink() == nullptr) return;
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"dftracer","type":"metadata","pid":%d,"tid":%ld,"ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
      "\n",
      static_cast<unsigned long long>(sink()->next_id()), name, datacrumbs::client::self_pid(),
      static_cast<long>(datacrumbs::client::self_tid()), sink()->hhash().c_str(), key, value);
  if (n > 0) sink()->write(line, static_cast<std::size_t>(n));
}

/// Rank of this process in MPI_COMM_WORLD, or -1 if this is not an MPI process.
///
/// Resolved entirely at run time so one client serves MPI and non-MPI apps alike: linking MPI would
/// force every preloaded process to resolve MPI_COMM_WORLD, which under OpenMPI is a data symbol.
/// The world communicator has no portable representation, so it is taken from OpenMPI's symbol when
/// present and otherwise from the MPICH ABI constant, which mvapich2 and Intel MPI share.
int world_rank() {
  void* comm_rank = dlsym(RTLD_DEFAULT, "PMPI_Comm_rank");
  if (comm_rank == nullptr) comm_rank = dlsym(RTLD_DEFAULT, "MPI_Comm_rank");
  if (comm_rank == nullptr) return -1;

  int rank = -1;
  if (void* ompi_world = dlsym(RTLD_DEFAULT, "ompi_mpi_comm_world")) {
    if (reinterpret_cast<int (*)(void*, int*)>(comm_rank)(ompi_world, &rank) != 0) return -1;
  } else {
    constexpr int kMpichCommWorld = 0x44000000;
    if (reinterpret_cast<int (*)(int, int*)>(comm_rank)(kMpichCommWorld, &rank) != 0) return -1;
  }
  return rank;
}

/// Record the rank once MPI_Init has returned. No Initialized/Finalized guard is needed the way
/// dftracer needs one: this only runs from inside the MPI_Init wrappers, so MPI is up by
/// construction, and a process forked before MPI_Init never reaches it.
void record_rank() {
  static bool done = false;
  if (done || sink() == nullptr) return;
  const int rank = world_rank();
  if (rank < 0) return;
  done = true;

  // Record name "PR" and a string value are what dftracer emits and what readers dispatch on; a
  // JSON number is dropped silently by the is_string() check on the consuming side.
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%d", rank);
  emit_metadata("PR", "rank", buf);
  char pname[64];
  std::snprintf(pname, sizeof(pname), "Rank %d", rank);
  emit_metadata("process_name", "process_name", pname);
  sink()->flush();
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
      (sink() != nullptr ? sink()->clock() : clock).remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS;
  report(1, g_start_us, end_us > g_start_us ? end_us - g_start_us : 0);
  g_start_us = 0;
  datacrumbs::Singleton<ProgramSink>::finalize();  // destroys the sink, which flushes
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void datacrumbs_start() {
  DC_LOG_INFO("[dc-client] start (pid %d)", getpid());
  if (!markers_on()) return;
  if (sink_on()) datacrumbs::Singleton<ProgramSink>::get_instance();
  datacrumbs::timesync::Reader clock;
  clock.map();
  g_start_us =
      (sink() != nullptr ? sink()->clock() : clock).remap(mono_ns()) / DATACRUMBS_TIME_DIVISOR_NS;
  report(0, g_start_us, 0);
}

extern "C" __attribute__((visibility("default"))) void datacrumbs_stop() {
  DC_LOG_INFO("[dc-client] stop (pid %d)", getpid());
  finish();  // no-op when datacrumbs_fini already ran; the uprobe marker is lost on this path
}

// MPI_Init is the first moment a rank exists. Wrapping it costs a non-MPI process nothing, since
// nothing ever calls it. The real symbol comes from RTLD_NEXT, so LD_PRELOAD order is what puts
// these ahead of libmpi's.
extern "C" __attribute__((visibility("default"))) int MPI_Init(int* argc, char*** argv) {
  static int (*real)(int*, char***) = nullptr;
  if (real == nullptr) real = (int (*)(int*, char***))dlsym(RTLD_NEXT, "MPI_Init");
  if (real == nullptr) return -1;
  const int rc = real(argc, argv);
  if (rc == 0) record_rank();
  return rc;
}

extern "C" __attribute__((visibility("default"))) int MPI_Init_thread(int* argc, char*** argv,
                                                                      int required, int* provided) {
  static int (*real)(int*, char***, int, int*) = nullptr;
  if (real == nullptr)
    real = (int (*)(int*, char***, int, int*))dlsym(RTLD_NEXT, "MPI_Init_thread");
  if (real == nullptr) return -1;
  const int rc = real(argc, argv, required, provided);
  if (rc == 0) record_rank();
  return rc;
}

// Every module in a fixed order, from one constructor. As separate preloaded libraries the order
// came from how a user spelled LD_PRELOAD: two modules wrapping one symbol by different mechanisms
// segfaulted, one bound nothing because it ran before the module holding its state, and each
// opened its own sink.
void datacrumbs_init(void) {
  // Before anything can log: stdout belongs to the program being traced, and it reports its own
  // results there.
  DC_LOG_SET_STREAM(stderr);
  datacrumbs_start();
  // The wrapped API surface first: it records the calls the others only see the effects of.
#if DATACRUMBS_UTILS_HAVE_API_WRAP
  datacrumbs::client::wrap::init();
#endif
#if DATACRUMBS_UTILS_HAVE_IBVERBS
  datacrumbs::client::ibverbs::init();
#endif
#if DATACRUMBS_UTILS_HAVE_DOCA
  datacrumbs::client::doca::init();
#endif
  datacrumbs::client::dpa::init();
  datacrumbs::client::posix::init();
  datacrumbs::client::stdio::init();
  datacrumbs::client::clock::init();
}

void datacrumbs_fini(void) {
  // Reverse of init, so a module is never asked to write after the one it reports through has gone.
  datacrumbs::client::clock::fini();
  datacrumbs::client::stdio::fini();
  datacrumbs::client::posix::fini();
  datacrumbs::client::dpa::fini();
#if DATACRUMBS_UTILS_HAVE_DOCA
  datacrumbs::client::doca::fini();
#endif
#if DATACRUMBS_UTILS_HAVE_IBVERBS
  datacrumbs::client::ibverbs::fini();
#endif
#if DATACRUMBS_UTILS_HAVE_API_WRAP
  datacrumbs::client::wrap::fini();
#endif
  // Before datacrumbs_stop, not inside it: the server uprobes that function's entry to unmark the
  // process from the pid gate (init.bpf.c trace_client_stop), and anything reported after that is
  // filtered out. Measured: the end marker was dropped for every process until this ordering.
  finish();
  datacrumbs_stop();
}
