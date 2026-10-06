// SPDX-License-Identifier: MIT

// Buffered I/O, traced alongside the descriptor calls the posix module covers. fwrite
// bypasses write's symbol interposition inside libc, so a wrapper on write alone misses
// it. Records carry the descriptor behind the stream, so fopen and open land on the
// same identity.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/stdio/library.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <gotcha/gotcha.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {
// cat groups records by library surface, type names the instrumentation. Declared per module,
// as dftracer does in brahma/posix.cpp.
// Macros, not constants: they fold into the format string at compile time. An %s argument would
// cost a strlen and a copy on every record.
#define DC_CAT "STDIO"
#define DC_TYPE "libc_io"

/// The module's sink, held by the singleton. A type of its own because Singleton keys on the type
/// and every module has a sink of its own, which must not be shared.
struct StdioSink {
  datacrumbs::client::PfwSink sink{"stdio", DATACRUMBS_ENV_STDIO_OUT};
};

/// Borrowed, so a wrapped call pays no reference counting. Null before init and after fini.
inline datacrumbs::client::PfwSink* sink() {
  StdioSink* s = datacrumbs::Singleton<StdioSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}
// Set once teardown has run. The wrappers stay installed for the rest of the process and must not
// reach a sink that exit has already destroyed.
bool g_torn_down = false;

// Whether each call aggregates rather than records, resolved when the module starts so a wrapped
// call reads a bool instead of matching a pattern. A POD of bools is zero initialised statically,
// so it is safe to touch before the constructor attribute has run.
struct {
  bool fopen, fopen64, fclose, fread, fwrite, fseek, fflush;
} g_agg{};
thread_local int g_in_trace = 0;

gotcha_wrappee_handle_t g_h_fopen;
gotcha_wrappee_handle_t g_h_fopen64;
gotcha_wrappee_handle_t g_h_fclose;
gotcha_wrappee_handle_t g_h_fread;
gotcha_wrappee_handle_t g_h_fwrite;
gotcha_wrappee_handle_t g_h_fseek;
gotcha_wrappee_handle_t g_h_fflush;

long tid() {
  return datacrumbs::client::self_tid();
}

/// The descriptor behind a stream, or -1 before it has one. fileno is cheap and does not flush.
int stream_fd(FILE* f) {
  return f != nullptr ? fileno(f) : -1;
}

void emit(const char* name, bool aggregate, unsigned long long t0, unsigned long long t1, int fd,
          unsigned long long bytes) {
  // Loaded once: every sink() re-checks the function-local static's initialisation guard, and this
  // runs per wrapped call.
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  if (aggregate) {
    // bytes is the one quantity a stdio record carries beyond duration. fd is an identity, not
    // aggregated. Key matches the recorded form's "bytes" field.
    datacrumbs::client::NumArg nums[1];
    nums[0].key = "bytes";
    nums[0].kind = datacrumbs::client::NumKind::UINT;
    nums[0].u = bytes;
    s->aggregate(name, DC_CAT, DC_TYPE, t0, t1 - t0, nums, 1);
    return;
  }
  datacrumbs::client::NumArg args[2];
  args[0].key = "fd";
  args[0].kind = datacrumbs::client::NumKind::INT;
  args[0].i = fd;
  args[1].key = "bytes";
  args[1].kind = datacrumbs::client::NumKind::UINT;
  args[1].u = bytes;
  s->record(s->site_cached(name, DC_CAT, DC_TYPE, "stdio"), t0, t1 - t0, args, 2);
}

// Enter the wrapper, or say the call must simply be forwarded. One place so every wrapper answers
// teardown, re-entry and the switch the same way.
bool tracing() {
  return !g_torn_down && g_in_trace == 0 && sink() != nullptr &&
         !datacrumbs::client::g_in_datacrumbs_io;
}

FILE* fopen_dcwrap(const char* path, const char* mode) {
  auto real = reinterpret_cast<FILE* (*)(const char*, const char*)>(gotcha_get_wrappee(g_h_fopen));
  if (real == nullptr) return nullptr;
  if (!tracing()) return real(path, mode);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  FILE* f = real(path, mode);
  g_in_trace = 1;
  emit("fopen", g_agg.fopen, t0, datacrumbs::client::mono_ns(), stream_fd(f), 0);
  g_in_trace = 0;
  return f;
}

FILE* fopen64_dcwrap(const char* path, const char* mode) {
  auto real =
      reinterpret_cast<FILE* (*)(const char*, const char*)>(gotcha_get_wrappee(g_h_fopen64));
  if (real == nullptr) return nullptr;
  if (!tracing()) return real(path, mode);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  FILE* f = real(path, mode);
  g_in_trace = 1;
  emit("fopen64", g_agg.fopen64, t0, datacrumbs::client::mono_ns(), stream_fd(f), 0);
  g_in_trace = 0;
  return f;
}

int fclose_dcwrap(FILE* f) {
  auto real = reinterpret_cast<int (*)(FILE*)>(gotcha_get_wrappee(g_h_fclose));
  if (real == nullptr) return -1;
  if (!tracing()) return real(f);
  // Read before the call: the descriptor is gone once the stream closes.
  const int fd = stream_fd(f);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const int r = real(f);
  g_in_trace = 1;
  emit("fclose", g_agg.fclose, t0, datacrumbs::client::mono_ns(), fd, 0);
  g_in_trace = 0;
  return r;
}

size_t fread_dcwrap(void* p, size_t sz, size_t n, FILE* f) {
  auto real =
      reinterpret_cast<size_t (*)(void*, size_t, size_t, FILE*)>(gotcha_get_wrappee(g_h_fread));
  if (real == nullptr) return 0;
  if (!tracing()) return real(p, sz, n, f);
  const int fd = stream_fd(f);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const size_t got = real(p, sz, n, f);
  g_in_trace = 1;
  emit("fread", g_agg.fread, t0, datacrumbs::client::mono_ns(), fd,
       static_cast<unsigned long long>(got) * sz);
  g_in_trace = 0;
  return got;
}

size_t fwrite_dcwrap(const void* p, size_t sz, size_t n, FILE* f) {
  auto real = reinterpret_cast<size_t (*)(const void*, size_t, size_t, FILE*)>(
      gotcha_get_wrappee(g_h_fwrite));
  if (real == nullptr) return 0;
  if (!tracing()) return real(p, sz, n, f);
  const int fd = stream_fd(f);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const size_t put = real(p, sz, n, f);
  g_in_trace = 1;
  emit("fwrite", g_agg.fwrite, t0, datacrumbs::client::mono_ns(), fd,
       static_cast<unsigned long long>(put) * sz);
  g_in_trace = 0;
  return put;
}

int fseek_dcwrap(FILE* f, long off, int whence) {
  auto real = reinterpret_cast<int (*)(FILE*, long, int)>(gotcha_get_wrappee(g_h_fseek));
  if (real == nullptr) return -1;
  if (!tracing()) return real(f, off, whence);
  const int fd = stream_fd(f);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const int r = real(f, off, whence);
  g_in_trace = 1;
  emit("fseek", g_agg.fseek, t0, datacrumbs::client::mono_ns(), fd, 0);
  g_in_trace = 0;
  return r;
}

int fflush_dcwrap(FILE* f) {
  auto real = reinterpret_cast<int (*)(FILE*)>(gotcha_get_wrappee(g_h_fflush));
  if (real == nullptr) return -1;
  if (!tracing()) return real(f);
  const int fd = stream_fd(f);
  const unsigned long long t0 = datacrumbs::client::mono_ns();
  const int r = real(f);
  g_in_trace = 1;
  emit("fflush", g_agg.fflush, t0, datacrumbs::client::mono_ns(), fd, 0);
  g_in_trace = 0;
  return r;
}

}  // namespace

void datacrumbs::client::stdio::init() {
  if (!datacrumbs::ConfigurationManager::runtime().stdio_enabled) return;
  g_in_trace = 1;  // the sink opens a file of its own
  datacrumbs::Singleton<StdioSink>::get_instance();
  const auto& rt = datacrumbs::ConfigurationManager::runtime();
  const auto agg_for = [&rt](const char* n) {
    return datacrumbs::ConfigurationManager::mode_for(rt.stdio_mode, rt.stdio_select, n) ==
           datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE;
  };
  g_agg = {agg_for("fopen"),  agg_for("fopen64"), agg_for("fclose"), agg_for("fread"),
           agg_for("fwrite"), agg_for("fseek"),   agg_for("fflush")};
  g_in_trace = 0;
  static gotcha_binding_t bindings[] = {
      {"fopen", reinterpret_cast<void*>(fopen_dcwrap), &g_h_fopen},
      {"fopen64", reinterpret_cast<void*>(fopen64_dcwrap), &g_h_fopen64},
      {"fclose", reinterpret_cast<void*>(fclose_dcwrap), &g_h_fclose},
      {"fread", reinterpret_cast<void*>(fread_dcwrap), &g_h_fread},
      {"fwrite", reinterpret_cast<void*>(fwrite_dcwrap), &g_h_fwrite},
      {"fseek", reinterpret_cast<void*>(fseek_dcwrap), &g_h_fseek},
      {"fflush", reinterpret_cast<void*>(fflush_dcwrap), &g_h_fflush},
  };
  const gotcha_error_t rc = ::gotcha_wrap(bindings, 7, "datacrumbs_stdio");
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[stdio] gotcha_wrap failed: %d", static_cast<int>(rc));
}

void datacrumbs::client::stdio::fini() {
  g_torn_down = true;
  g_in_trace = 1;
  datacrumbs::Singleton<StdioSink>::finalize();  // destroys the sink, which flushes and closes
}
