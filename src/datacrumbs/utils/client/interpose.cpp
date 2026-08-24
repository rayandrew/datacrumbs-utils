// LD_PRELOAD interposition client: wrap a configured set of libc I/O calls and write COMPLETE .pfw
// records directly, on the dc_timesync global timeline. This is the cheap userspace rung of the
// backend ladder (no uprobe, no server round-trip); its trace merges with the server's .pfw at
// collect. Enable a subset with DATACRUMBS_INTERPOSE=read,write,... (default: the full set below).

#define _GNU_SOURCE
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/utils/client/pfw_sink.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace {

// Reentrancy guard: our own writer does I/O (fwrite -> write), which would re-enter these wrappers.
thread_local bool g_in_trace = false;

// State on the heap behind a POD pointer set in the constructor. A std::string global would be
// wiped by its own dynamic initializer running AFTER the constructor attribute.
struct State {
  datacrumbs::client::PfwSink* sink = nullptr;
  struct {
    bool read, write, pread, pwrite, close, fsync;
  } on{};
};

State* g_state = nullptr;

unsigned long long mono_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

// Append one COMPLETE record (matches ChromeWriter's NORMAL schema; pid=tid, tid=tgid as elsewhere).
void emit(const char* name, unsigned long long t0_mono, unsigned long long t1_mono) {
  State* s = g_state;
  if (s == nullptr) return;
  g_in_trace = true;
  const unsigned long long ts_us = s->sink->clock().remap(t0_mono) / 1000;
  const unsigned long long dur_ns = t1_mono > t0_mono ? t1_mono - t0_mono : 0;
  const unsigned long long dur_us = dur_ns / 1000 + (dur_ns % 1000 != 0 ? 1 : 0);
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":"libc","type":"interpose","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s"}})"
      "\n",
      static_cast<unsigned long long>(s->sink->next_id()), name,
      static_cast<long>(syscall(SYS_gettid)), getpid(), ts_us, dur_us, s->sink->hhash().c_str());
  if (n > 0) s->sink->write(line, static_cast<std::size_t>(n));
  g_in_trace = false;
}

bool enabled(const char* env, const char* name) {
  if (env == nullptr || *env == '\0') return true;  // default: all wrappers on
  const std::string list(env);
  const std::string tok(name);
  std::size_t pos = list.find(tok);
  while (pos != std::string::npos) {
    const bool left = pos == 0 || list[pos - 1] == ',';
    const bool right = pos + tok.size() == list.size() || list[pos + tok.size()] == ',';
    if (left && right) return true;
    pos = list.find(tok, pos + 1);
  }
  return false;
}

__attribute__((constructor)) void interpose_init() {
  g_in_trace = true;  // suppress tracing of our own setup I/O
  auto* s = new State();
  // $USER stays in the file name: /tmp is shared, so two users tracing at once would collide.
  const char* user = std::getenv("USER");
  if (user == nullptr || *user == '\0') user = "unknown";
  char tag[128];
  std::snprintf(tag, sizeof(tag), "interpose-%s", user);
  s->sink = new datacrumbs::client::PfwSink(tag, nullptr);

  const char* env = std::getenv("DATACRUMBS_INTERPOSE");
  s->on = {enabled(env, "read"), enabled(env, "write"), enabled(env, "pread64"),
           enabled(env, "pwrite64"), enabled(env, "close"), enabled(env, "fsync")};

  g_state = s;
  g_in_trace = false;
}

__attribute__((destructor)) void interpose_fini() {
  State* s = g_state;
  g_state = nullptr;
  if (s == nullptr) return;
  g_in_trace = true;
  delete s->sink;  // flushes and closes
}

}  // namespace

// Each wrapper resolves the real symbol once, times the call, and emits unless we are already inside
// the tracer (g_in_trace) or the wrapper is disabled.
#define DC_WRAP(ret, name, proto, args, flag)            \
  extern "C" ret name proto {                            \
    static ret (*real) proto = nullptr;                  \
    if (real == nullptr) real = (ret(*) proto)dlsym(RTLD_NEXT, #name); \
    if (g_in_trace || g_state == nullptr || !g_state->on.flag) return real args; \
    const unsigned long long t0 = mono_ns();             \
    ret r = real args;                                   \
    emit(#name, t0, mono_ns());                          \
    return r;                                            \
  }

DC_WRAP(ssize_t, read, (int fd, void* buf, size_t n), (fd, buf, n), read)
DC_WRAP(ssize_t, write, (int fd, const void* buf, size_t n), (fd, buf, n), write)
DC_WRAP(ssize_t, pread64, (int fd, void* buf, size_t n, off_t o), (fd, buf, n, o), pread)
DC_WRAP(ssize_t, pwrite64, (int fd, const void* buf, size_t n, off_t o), (fd, buf, n, o), pwrite)
DC_WRAP(int, close, (int fd), (fd), close)
DC_WRAP(int, fsync, (int fd), (fd), fsync)
