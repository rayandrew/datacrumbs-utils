// LD_PRELOAD interposition client. It wraps a configured set of libc I/O calls and writes
// complete .pfw records directly, on the global timeline. This is the cheap userspace path,
// with no uprobe and no server round-trip. Its trace merges with the server's .pfw at collect
// time. Enable a subset with DATACRUMBS_INTERPOSE=read,write,... (default: all below).

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/posix/library.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <gotcha/gotcha.h>
#include <limits.h>
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
#include <unordered_map>
#include <unordered_set>

namespace {
// cat groups records by library surface, type names the instrumentation. Declared per module.
// Macros, not constants: they fold into the format string at compile time. An %s argument would
// cost a strlen and a copy on every record.
#define DC_CAT "POSIX"
#define DC_TYPE "libc_io"

using datacrumbs::client::mono_ns;

// Reentrancy guard: our own writer does I/O (fwrite -> write), which would re-enter these wrappers.
thread_local bool g_in_trace = false;

// Set once teardown has run. Wrappers outlive teardown and reach for function-local statics that
// exit may already have destroyed, so after this flag is set they only forward the call. close
// must also stop touching the descriptor map once teardown has run.
bool g_torn_down = false;

// State lives on the heap behind a POD pointer set in the constructor. A std::string global would
// be wiped by its own dynamic initializer running after the constructor attribute runs.
struct State {
  datacrumbs::client::PfwSink sink;
  struct {
    bool read, write, pread, pwrite, close, fsync;
  } on{};
  // Whether each call aggregates rather than records, resolved when the module starts so a
  // wrapped call reads a bool instead of matching a pattern.
  struct {
    bool read, write, pread, pwrite, close, fsync;
  } agg{};

  /// @p tag names the trace file. /tmp is shared, so it carries the user.
  explicit State(const char* tag) : sink(tag, nullptr) {}
};

/// Borrowed, so a wrapped call pays no reference counting. Null before init and after fini, which
/// is what the wrappers check: a call can arrive before the constructor attribute has run.
inline State* state() {
  return datacrumbs::Singleton<State>::get();
}

// Function-local for the same reason State lives on the heap: a wrapped call can arrive before this
// unit's dynamic initializers run, and a zeroed unordered_map has bucket_count 0, so the first
// lookup divides by zero and the process takes SIGFPE.
std::unordered_map<int, std::string>& fd_hashes() {
  static std::unordered_map<int, std::string> m;
  return m;
}

std::unordered_set<std::string>& seen_paths() {
  static std::unordered_set<std::string> s;
  return s;
}

std::mutex& fd_mu() {
  static std::mutex m;
  return m;
}

/// Hash for @p fd, emitting the FH record the first time that path is seen. Empty when the
/// descriptor cannot be resolved, so the record then carries no fhash.
std::string fd_hash(State* s, int fd) {
  if (fd < 0) return {};
  {
    std::lock_guard<std::mutex> lock(fd_mu());
    auto it = fd_hashes().find(fd);
    if (it != fd_hashes().end()) return it->second;
  }
  char link[64];
  std::snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  char target[PATH_MAX];
  const ssize_t n = readlink(link, target, sizeof(target) - 1);
  if (n <= 0) return {};
  target[n] = '\0';
  const std::string hash = datacrumbs::pfw::hhash(target);
  bool fresh = false;
  {
    std::lock_guard<std::mutex> lock(fd_mu());
    fresh = seen_paths().insert(hash).second;
    fd_hashes()[fd] = hash;
  }
  if (fresh) {
    char line[PATH_MAX + 256];
    const int m = std::snprintf(
        line, sizeof(line),
        R"({"name":"FH","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
        "\n",
        s->sink.hhash().c_str(), target, hash.c_str());
    if (m > 0) s->sink.write(line, static_cast<std::size_t>(m));
  }
  return hash;
}

void forget_fd(int fd) {
  std::lock_guard<std::mutex> lock(fd_mu());
  fd_hashes().erase(fd);
}

// Cites fhash, never the path: the FH record carries that mapping once.
void emit_closed(const char* name, bool aggregate, unsigned long long t0_mono,
                 unsigned long long t1_mono, int fd, const std::string& fh) {
  State* s = state();
  if (s == nullptr) return;
  g_in_trace = true;
  const unsigned long long dur_ns = t1_mono > t0_mono ? t1_mono - t0_mono : 0;
  if (aggregate) {
    s->sink.aggregate(name, DC_CAT, DC_TYPE, t0_mono, dur_ns);
    g_in_trace = false;
    return;
  }
  datacrumbs::client::NumArg args[2];
  int n = 0;
  if (!fh.empty()) {
    args[n].key = "fhash";
    args[n].kind = datacrumbs::client::NumKind::STR;
    std::snprintf(args[n].s, sizeof(args[n].s), "%s", fh.c_str());
    ++n;
  }
  args[n].key = "fd";
  args[n].kind = datacrumbs::client::NumKind::INT;
  args[n].i = fd;
  ++n;
  s->sink.record(s->sink.site_cached(name, DC_CAT, DC_TYPE), t0_mono, dur_ns, args, n);
  g_in_trace = false;
}

/// Resolves the descriptor, then records. close cannot use this: it resolves before the call.
void emit(const char* name, bool aggregate, unsigned long long t0_mono, unsigned long long t1_mono,
          int fd) {
  State* s = state();
  if (s == nullptr) return;
  g_in_trace = true;
  const std::string fh = fd_hash(s, fd);
  g_in_trace = false;
  emit_closed(name, aggregate, t0_mono, t1_mono, fd, fh);
}

// Cites fhash, never the path, as emit_closed does. "size" is what the caller asked to move;
// "ret" is the raw return value.
void emit_io_closed(const char* name, bool aggregate, unsigned long long t0_mono,
                    unsigned long long t1_mono, int fd, const std::string& fh, size_t requested,
                    ssize_t ret) {
  State* s = state();
  if (s == nullptr) return;
  g_in_trace = true;
  const unsigned long long dur_ns = t1_mono > t0_mono ? t1_mono - t0_mono : 0;
  const unsigned long long size = static_cast<unsigned long long>(requested);
  const long long ret_ll = static_cast<long long>(ret);
  if (aggregate) {
    // fd/fhash identify the file, not a quantity, so they are not passed here: summing a
    // descriptor number or a hash is meaningless.
    datacrumbs::client::NumArg nums[2];
    nums[0].key = "size";
    nums[0].kind = datacrumbs::client::NumKind::UINT;
    nums[0].u = size;
    nums[1].key = "ret";
    nums[1].kind = datacrumbs::client::NumKind::INT;
    nums[1].i = ret_ll;
    s->sink.aggregate(name, DC_CAT, DC_TYPE, t0_mono, dur_ns, nums, 2);
    g_in_trace = false;
    return;
  }
  // No separate error field: ret is the raw signed return, so a negative value carries the failure.
  datacrumbs::client::NumArg args[4];
  int n = 0;
  if (!fh.empty()) {
    args[n].key = "fhash";
    args[n].kind = datacrumbs::client::NumKind::STR;
    std::snprintf(args[n].s, sizeof(args[n].s), "%s", fh.c_str());
    ++n;
  }
  args[n].key = "fd";
  args[n].kind = datacrumbs::client::NumKind::INT;
  args[n++].i = fd;
  args[n].key = "size";
  args[n].kind = datacrumbs::client::NumKind::UINT;
  args[n++].u = size;
  args[n].key = "ret";
  args[n].kind = datacrumbs::client::NumKind::INT;
  args[n++].i = ret_ll;
  s->sink.record(s->sink.site_cached(name, DC_CAT, DC_TYPE), t0_mono, dur_ns, args, n);
  g_in_trace = false;
}

/// Resolves the descriptor, then records a call that moves bytes: read, write, pread64, pwrite64.
void emit_io(const char* name, bool aggregate, unsigned long long t0_mono,
             unsigned long long t1_mono, int fd, size_t requested, ssize_t ret) {
  State* s = state();
  if (s == nullptr) return;
  g_in_trace = true;
  const std::string fh = fd_hash(s, fd);
  g_in_trace = false;
  emit_io_closed(name, aggregate, t0_mono, t1_mono, fd, fh, requested, ret);
}

bool enabled(const char* env, const char* name) {
  if (env == nullptr || *env == '\0') return true;  // default: all wrappers on
  // Other client shims switch on with =1, so a reader may pass that value here too. As a wrapper
  // list it matches no wrapper name and turns the whole shim off, while still producing a trace
  // file. That looks like a workload that did no I/O instead of a configuration mistake.
  const std::string list(env);
  if (list == "1" || list == "all" || list == "on") return true;
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

}  // namespace

void datacrumbs::client::posix::fini() {
  g_torn_down = true;
  if (state() == nullptr) return;
  g_in_trace = true;
  datacrumbs::Singleton<State>::finalize();  // destroys the sink, which flushes and closes
}

// Uses GOTCHA, not dlsym chaining, for the same reason other client shims do. GOTCHA rewrites
// the caller's GOT entry, while a plain preload definition claims the symbol at load time. Mixing
// both mechanisms for the same symbol in one process lets each one resolve a pointer the other
// has already redirected, which crashes the process.
#define DC_WRAP(ret, name, proto, args, flag)                                               \
  gotcha_wrappee_handle_t g_h_##name;                                                       \
  static ret name##_dcwrap proto {                                                          \
    auto real = reinterpret_cast<ret(*) proto>(gotcha_get_wrappee(g_h_##name));             \
    if (real == nullptr) return ret();                                                      \
    State* _dc_s = state();                                                                 \
    if (g_torn_down || g_in_trace || _dc_s == nullptr || !_dc_s->on.flag) return real args; \
    const unsigned long long t0 = mono_ns();                                                \
    ret r = real args;                                                                      \
    emit(#name, _dc_s->agg.flag, t0, mono_ns(), fd);                                        \
    return r;                                                                               \
  }

// Same shape as DC_WRAP, but for the four calls that move bytes. It keeps the return value to
// pass to emit_io as what actually moved, separate from n as what was requested. DC_WRAP's
// caller never needs r for anything but the return statement. Every use below names its size_t
// parameter n, the requested count emit_io wants.
#define DC_WRAP_IO(name, proto, args, flag)                                                 \
  gotcha_wrappee_handle_t g_h_##name;                                                       \
  static ssize_t name##_dcwrap proto {                                                      \
    auto real = reinterpret_cast<ssize_t(*) proto>(gotcha_get_wrappee(g_h_##name));         \
    if (real == nullptr) return 0;                                                          \
    State* _dc_s = state();                                                                 \
    if (g_torn_down || g_in_trace || _dc_s == nullptr || !_dc_s->on.flag) return real args; \
    const unsigned long long t0 = mono_ns();                                                \
    ssize_t r = real args;                                                                  \
    emit_io(#name, _dc_s->agg.flag, t0, mono_ns(), fd, n, r);                               \
    return r;                                                                               \
  }

DC_WRAP_IO(read, (int fd, void* buf, size_t n), (fd, buf, n), read)
DC_WRAP_IO(write, (int fd, const void* buf, size_t n), (fd, buf, n), write)
DC_WRAP_IO(pread64, (int fd, void* buf, size_t n, off_t o), (fd, buf, n, o), pread)
DC_WRAP_IO(pwrite64, (int fd, const void* buf, size_t n, off_t o), (fd, buf, n, o), pwrite)
DC_WRAP(int, fsync, (int fd), (fd), fsync)

// Resolves before the call, since readlink on a closed descriptor fails, and forgets after: the
// kernel reuses the lowest free number, so a stale entry would mislabel the next file's IO.
gotcha_wrappee_handle_t g_h_close;
static int close_dcwrap(int fd) {
  auto real = reinterpret_cast<int (*)(int)>(gotcha_get_wrappee(g_h_close));
  if (real == nullptr) return -1;
  if (g_torn_down) return real(fd);  // nothing below is safe to touch after teardown
  State* cs = state();
  if (g_in_trace || cs == nullptr || !cs->on.close) {
    forget_fd(fd);
    return real(fd);
  }
  g_in_trace = true;
  const std::string fh = fd_hash(state(), fd);
  g_in_trace = false;
  const unsigned long long t0 = mono_ns();
  const int r = real(fd);
  emit_closed("close", cs->agg.close, t0, mono_ns(), fd, fh);
  forget_fd(fd);
  return r;
}

// Wrapping happens here, not in a second constructor: two constructors in one file are not
// ordered by where they appear in the file. A wrap constructor could run first, find a null
// state, and bind nothing.
void datacrumbs::client::posix::init() {
  // Off unless asked for: inside a client that is always preloaded, every traced process would
  // otherwise pay for I/O tracing it never asked for. Tracing adds measurable overhead per call,
  // so it stays opt-in.
  if (!datacrumbs::ConfigurationManager::runtime().posix_enabled) return;
  g_in_trace = true;  // suppress tracing of our own setup I/O

  // $USER stays in the file name: /tmp is shared, so two users tracing at once would collide.
  // System variable, not ours: routed through env_text so no call site reads it directly.
  const std::string user_env = datacrumbs::ConfigurationManager::env_text("USER");
  const char* user = user_env.empty() ? "unknown" : user_env.c_str();
  char tag[128];
  std::snprintf(tag, sizeof(tag), "interpose-%s", user);
  State* s = datacrumbs::Singleton<State>::get_instance(tag).get();
  if (s == nullptr) {
    g_in_trace = false;  // else this thread stays suppressed and traces nothing, silently
    return;
  }

  static const char* kWrappers[] = {"read", "write", "pread64", "pwrite64", "close", "fsync"};
  const char* env = datacrumbs::ConfigurationManager::runtime().posix_calls.c_str();
  s->on = {enabled(env, "read"),     enabled(env, "write"), enabled(env, "pread64"),
           enabled(env, "pwrite64"), enabled(env, "close"), enabled(env, "fsync")};
  const auto& rt = datacrumbs::ConfigurationManager::runtime();
  const auto agg_for = [&rt](const char* n) {
    return datacrumbs::ConfigurationManager::mode_for(rt.posix_mode, rt.posix_select, n) ==
           datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE;
  };
  s->agg = {agg_for("read"),     agg_for("write"), agg_for("pread64"),
            agg_for("pwrite64"), agg_for("close"), agg_for("fsync")};
  // A selection that switches nothing on still writes a trace, which reads as a workload that did
  // no I/O rather than as a configuration mistake.
  if (env != nullptr && *env != '\0') {
    bool any = false;
    for (const char* w : kWrappers) any = any || enabled(env, w);
    if (!any)
      DC_LOG_WARN(
          "[interpose] DATACRUMBS_INTERPOSE='%s' names no wrapper, so nothing is traced; expected "
          "1, or a comma separated subset of read,write,pread64,pwrite64,close,fsync",
          env);
  }

  static gotcha_binding_t bindings[] = {
      {"read", reinterpret_cast<void*>(read_dcwrap), &g_h_read},
      {"write", reinterpret_cast<void*>(write_dcwrap), &g_h_write},
      {"pread64", reinterpret_cast<void*>(pread64_dcwrap), &g_h_pread64},
      {"pwrite64", reinterpret_cast<void*>(pwrite64_dcwrap), &g_h_pwrite64},
      {"fsync", reinterpret_cast<void*>(fsync_dcwrap), &g_h_fsync},
      {"close", reinterpret_cast<void*>(close_dcwrap), &g_h_close},
  };
  const gotcha_error_t rc = ::gotcha_wrap(bindings, 6, "datacrumbs_posix");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[posix] gotcha_wrap failed: %d", static_cast<int>(rc));
  // A shim that binds nothing looks exactly like a workload that did no IO, so the count is
  // reported rather than inferred from an empty trace.
  if (datacrumbs::ConfigurationManager::runtime().posix_debug) {
    int bound = 0;
    for (const auto& b : bindings)
      if (b.function_handle != nullptr && gotcha_get_wrappee(*b.function_handle) != nullptr)
        ++bound;
    DC_LOG_INFO("[posix] gotcha_wrap rc=%d bound=%d of 6", static_cast<int>(rc), bound);
  }
  g_in_trace = false;
}
