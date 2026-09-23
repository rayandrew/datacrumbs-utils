// SPDX-License-Identifier: MIT

/**
 * @brief Emits the program's start and end as .pfw records.
 * A uprobe on main cannot mark the end, since main never returns under exit(). A destructor can,
 * but not under SIGKILL. Consumers must tolerate a begin with no end.
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
#include <datacrumbs/utils/common/compress_pool.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// Noinline so the server can uprobe it; the marker then lands in the node's own trace, not a
// sidecar. The asm keeps the arguments live at the probe site. The sidecar stays the fallback for
// runs whose probeset does not name this function.
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

/// A type of its own because Singleton keys on the type, and each module's sink must not be shared.
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
      static_cast<unsigned long long>(sink()->next_id()), name, kCat,
      datacrumbs::client::self_pid(), static_cast<long>(datacrumbs::client::self_tid()), ts_us,
      dur_us, sink()->hhash().c_str(), comm());
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
/// Resolved at run time, not linked, so one client serves MPI and non-MPI apps alike.
/// Reads through OpenMPI's symbol when present, else the MPICH ABI constant shared
/// by mvapich2 and Intel MPI.
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

/// Record the rank once MPI_Init has returned. No Initialized/Finalized guard is needed: this only
/// runs from inside the MPI_Init wrappers, so MPI is already up.
void record_rank() {
  static bool done = false;
  if (done || sink() == nullptr) return;
  const int rank = world_rank();
  if (rank < 0) return;
  done = true;

  // Record name "PR" with a string value: readers dispatch on this, and drop a JSON number
  // silently.
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
// nothing calls it. The real symbol comes from RTLD_NEXT, so LD_PRELOAD order must put this
// library ahead of libmpi's.
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

// Every module in a fixed order, from one constructor, not as separate preloaded libraries. That
// left the order to how a user spelled LD_PRELOAD: two modules wrapping the same symbol by
// different mechanisms segfaulted, and one bound nothing because it ran before the module holding
// its state.
// DATACRUMBS_CRASH_BACKTRACE=1: a fatal signal prints the raw backtrace to stderr, then re-raises.
// For the DPUs, which have no debugger; resolve the offsets with addr2line on the build machine.
void crash_backtrace(int sig) {
  void* frames[64];
  const int n = backtrace(frames, 64);
  const char head[] = "[datacrumbs] fatal signal, backtrace:\n";
  (void)!::write(2, head, sizeof(head) - 1);
  backtrace_symbols_fd(frames, n, 2);
  signal(sig, SIG_DFL);
  raise(sig);
}

void install_crash_backtrace() {
  const char* v = getenv("DATACRUMBS_CRASH_BACKTRACE");
  if (v == nullptr || *v != '1') return;
  // The first backtrace() dlopens libgcc_s and mallocs; from a handler inside free() that
  // deadlocks.
  void* warm[4];
  backtrace(warm, 4);
  struct sigaction sa{};
  sa.sa_handler = crash_backtrace;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESETHAND;
  for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE}) sigaction(sig, &sa, nullptr);
}

void datacrumbs_init(void) {
  // Before anything can log: stdout belongs to the traced program, not to us.
  DC_LOG_SET_STREAM(stderr);
  install_crash_backtrace();
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
  // Both background workers first, so every module's fini runs its last tick on this thread and no
  // worker is mid-call while a module tears down.
  datacrumbs::client::Background::get().stop();
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
  // Every sink has waited for its members by now; a sink destroyed later compresses inline.
  datacrumbs::client::CompressPool::get().stop();
  // Before datacrumbs_stop, not inside it: the server uprobes that function's entry to unmark the
  // process from the pid gate (init.bpf.c trace_client_stop), and drops anything reported after.
  finish();
  datacrumbs_stop();
}
