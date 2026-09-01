// SPDX-License-Identifier: MIT

// Traces the classified ibverbs and mlx5 API surface with GOTCHA. Enable with DC_API_TRACE=1.
//
// GOTCHA rather than uprobes: a uprobe traps on the first instruction inside the function, and on
// BlueField that breaks libmlx5's write-combining doorbell burst, so the first send returns
// IO_FAILED. Rewriting the GOT redirects at the call boundary and leaves the body alone.

// The wrap list names ibverbs and mlx5 types, and mlx5dv.h uses uapi enums that cannot be
// forward-declared in a parameter list, so both headers must be in scope before it expands.
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/utils/client/wrap/library.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <infiniband/mlx5dv.h>
#include <infiniband/verbs.h>
// For the trampoline entry and exit contract, whose implementations live here.
#include <datacrumbs/utils/client/wrap/variadic_tramp.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <sys/mman.h>
#include <yaml-cpp/yaml.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

// Ahead of check_version, which tests DC_BUILT_AGAINST_* with #ifdef: included after it, every
// guard is false and the version records vanish without a diagnostic. The wrap list only defines
// macros and decoder functions here, so nothing expands until DC_WRAPPED_FUNCS is used below.
// One list per library rather than one holding all of them, so a build without a library never
// carries its surface. Each header defines its own macro; the arrays below concatenate whichever
// are present.
#include "datacrumbs/utils/client/doca/api.h"
#include "datacrumbs/utils/client/flexio/api.h"
#include "datacrumbs/utils/client/ibverbs/api.h"
#include "datacrumbs/utils/client/mlx5/api.h"
#include "datacrumbs/utils/client/other/api.h"
#include "datacrumbs/utils/client/pka/api.h"

#define DC_WRAPPED_FUNCS(X)   \
  DC_WRAPPED_FUNCS_DOCA(X)    \
  DC_WRAPPED_FUNCS_IBVERBS(X) \
  DC_WRAPPED_FUNCS_MLX5(X)    \
  DC_WRAPPED_FUNCS_FLEXIO(X)  \
  DC_WRAPPED_FUNCS_PKA(X)     \
  DC_WRAPPED_FUNCS_OTHER(X)

namespace {
// The labels this module puts on every record it writes: cat groups by the library surface,
// type names the instrumentation that produced it. Declared here rather than centrally so a
// module owns its own, as dftracer does in brahma/posix.cpp.
// Macros, not constants: folded into the format string at compile time they cost nothing,
// where passing them as %s arguments costs a strlen and a copy on every record.
#define DC_CAT "IBVERBS"
// The generated wrappers put each symbol's own operation class in cat, which is what
// groups a surface of two thousand names; a constant would group nothing. These two are
// trampolined symbols that no header declares, so this is their class.
#define DC_CAT_VARIADIC "variadic"
#define DC_TYPE "ibverbs"

/// The module's sink, held by the singleton. A type of its own because Singleton keys on the type
/// and every module has a sink of its own, which must not be shared.
struct ApiSink {
  datacrumbs::client::PfwSink sink{"api", DATACRUMBS_ENV_API_OUT};
};
std::once_flag g_once;

/// Borrowed, so a wrapped call pays no reference counting. Null before init and after fini.
datacrumbs::client::PfwSink* sink() {
  ApiSink* s = datacrumbs::Singleton<ApiSink>::get();
  return s != nullptr ? &s->sink : nullptr;
}

bool enabled() {
  return datacrumbs::ConfigurationManager::runtime().api_enabled;
}

/// Record the libraries this build decoded against, and say so when the running one differs.
///
/// Opcode and flag names are compiled in from the headers, so a mismatch decodes to a plausible
/// wrong name rather than failing. DOCA is the only one of the three with a runtime accessor;
/// ibverbs and mlx5 are covered by the per-library build ids the sink already records.
void check_version() {
#if defined(DC_BUILT_AGAINST_DOCA) || defined(DC_BUILT_AGAINST_IBVERBS) || \
    defined(DC_BUILT_AGAINST_MLX5)
  auto meta = [](const char* name, const char* value) {
    char line[512];
    const int n = std::snprintf(
        line, sizeof(line),
        R"({"name":"BV","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
        "\n",
        sink()->hhash().c_str(), name, value);
    if (n > 0) sink()->write(line, static_cast<std::size_t>(n));
  };
#endif
#ifdef DC_BUILT_AGAINST_DOCA
  meta("doca.built", DC_BUILT_AGAINST_DOCA);
  auto runtime = reinterpret_cast<const char* (*)()>(dlsym(RTLD_DEFAULT, "doca_version_runtime"));
  if (runtime != nullptr) {
    const char* rv = runtime();
    meta("doca.runtime", rv != nullptr ? rv : "unknown");
    if (rv != nullptr && std::strcmp(rv, DC_BUILT_AGAINST_DOCA) != 0)
      DC_LOG_WARN("[api] DOCA built %s but running %s; decoded names may be wrong",
                  DC_BUILT_AGAINST_DOCA, rv);
  }
#endif
#ifdef DC_BUILT_AGAINST_IBVERBS
  meta("ibverbs.built", DC_BUILT_AGAINST_IBVERBS);
#endif
#ifdef DC_BUILT_AGAINST_MLX5
  meta("mlx5.built", DC_BUILT_AGAINST_MLX5);
#endif
}

}  // namespace

#define DC_GOTCHA_SINK sink()
#define DC_GOTCHA_STACK "ibverbs"

#include <datacrumbs/utils/client/wrap/gotcha_wrap.h>

DC_WRAPPED_FUNCS(DC_GOTCHA_DECL)
DC_WRAPPED_FUNCS(DC_GOTCHA_WRAPPER)

namespace {

gotcha_binding_t g_bindings[] = {DC_WRAPPED_FUNCS(DC_GOTCHA_BINDING)};
// Parallel to g_bindings: same order, same length.
const char* g_classes[] = {DC_WRAPPED_FUNCS(DC_GOTCHA_CLASS)};

/// Bindings named by the selection at @p path, or all of them if it selects nothing.
///
/// Full visibility is the default and reduction is a runtime choice, so a sweep that turns out to
/// need fewer probes does not need a rebuild to get them. Selection is per symbol rather than per
/// library, because the symbols worth keeping rarely share one.
///
/// include runs first and defaults to everything; exclude runs after it and wins. `classes` matches
/// the role recorded in the wrap list, so a selection can say `submit` instead of naming every
/// symbol that submits. Patterns are globs, matched with fnmatch.
std::vector<gotcha_binding_t> select_bindings(const char* path, int n) {
  std::vector<std::string> include, exclude, classes;
  try {
    const YAML::Node root = YAML::LoadFile(path);
    const YAML::Node sel = root["api_trace"] ? root["api_trace"] : root;
    for (const auto& v : sel["include"]) include.push_back(v.as<std::string>());
    for (const auto& v : sel["exclude"]) exclude.push_back(v.as<std::string>());
    for (const auto& v : sel["classes"]) classes.push_back(v.as<std::string>());
  } catch (const std::exception& e) {
    // Loud, and no silent fallback to everything: a typo in the path would otherwise read as a
    // selection that happened to match the whole surface.
    DC_LOG_ERROR("[api] cannot read selection %s: %s", path, e.what());
    std::abort();
  }
  std::vector<gotcha_binding_t> out;
  for (int i = 0; i < n; ++i) {
    const char* name = g_bindings[i].name;
    bool want = include.empty();
    for (const auto& p : include)
      if (fnmatch(p.c_str(), name, 0) == 0) want = true;
    if (want && !classes.empty()) {
      want = false;
      for (const auto& c : classes)
        if (c == g_classes[i]) want = true;
    }
    for (const auto& p : exclude)
      if (fnmatch(p.c_str(), name, 0) == 0) want = false;
    if (want) out.push_back(g_bindings[i]);
  }
  return out;
}

}  // namespace

void datacrumbs::client::wrap::init() {
  // Idempotent: the standalone library initialises itself below, and a build that compiles this
  // surface into the client calls init from datacrumbs_init as well. Wrapping twice through GOTCHA
  // would chain the wrapper onto itself.
  static bool ran = false;
  if (ran) return;
  ran = true;
  if (!enabled()) return;
  std::call_once(g_once, [] { datacrumbs::Singleton<ApiSink>::get_instance(); });
  check_version();
  const int all = static_cast<int>(sizeof(g_bindings) / sizeof(g_bindings[0]));
  const std::string& api_cfg = datacrumbs::ConfigurationManager::runtime().api_config;
  const char* cfg = api_cfg.empty() ? nullptr : api_cfg.c_str();
  static std::vector<gotcha_binding_t> chosen;
  if (cfg != nullptr) chosen = select_bindings(cfg, all);
  const int n = cfg != nullptr ? static_cast<int>(chosen.size()) : all;
  gotcha_binding_t* table = cfg != nullptr ? chosen.data() : g_bindings;
  if (cfg != nullptr) DC_LOG_INFO("[api] %s selects %d of %d", cfg, n, all);
  // The list covers the whole classified surface and any one process links a fraction of it, so
  // GOTCHA_FUNCTION_NOT_FOUND is the normal case here rather than a failure.
  const gotcha_error_t rc = n > 0 ? ::gotcha_wrap(table, n, "datacrumbs") : GOTCHA_SUCCESS;
  if (rc != GOTCHA_SUCCESS && rc != GOTCHA_FUNCTION_NOT_FOUND)
    DC_LOG_ERROR("[api] gotcha_wrap failed: %d", static_cast<int>(rc));
  // How many of the list this process actually links. A shim that binds nothing looks exactly like
  // a workload that called nothing, so the count is reported rather than inferred from an empty
  // trace.
  if (datacrumbs::ConfigurationManager::runtime().api_debug) {
    int bound = 0;
    for (int i = 0; i < n; ++i)
      if (table[i].function_handle != nullptr &&
          gotcha_get_wrappee(*table[i].function_handle) != nullptr)
        ++bound;
    DC_LOG_INFO("[api] gotcha_wrap rc=%d bound=%d of %d", static_cast<int>(rc), bound, n);
  }
}

// Resolves the real symbol on first call and records the entry. Returning the target rather than
// relying on an installer removes the window where the interposing symbol exists but its slot is
// still null.
//
// Entry only: a trampoline tail-jumps, so there is no return to time. The record therefore carries
// no duration, which is why it is a ph:2 instant rather than a complete event.
namespace {

/// One hooked call in flight on this thread.
///
/// @p sp is the stack pointer at entry, which is what identifies the frame on the way back: a
/// longjmp or an unwinding exception abandons frames without returning through them, so the top of
/// this stack is not necessarily the call that is returning.
struct ShadowFrame {
  const char* name;
  void* ret;
  std::uintptr_t sp;
  std::uint64_t t0;
};

// Grown on demand rather than fixed: a call arriving with the stack full still has to be forwarded,
// and forwarding it without a frame loses its duration silently. The ceiling exists only so a
// runaway recursion cannot consume the address space.
constexpr int kShadowStart = 1024;
constexpr int kShadowHardMax = 1 << 20;
thread_local ShadowFrame* g_shadow = nullptr;
thread_local int g_capacity = 0;
thread_local int g_depth = 0;

/// Releases this thread's shadow stack. Threads come and go, and the mapping is per thread.
struct ShadowRelease {
  ~ShadowRelease() {
    if (g_shadow != nullptr) {
      munmap(g_shadow, static_cast<std::size_t>(g_capacity) * sizeof(ShadowFrame));
      g_shadow = nullptr;
      g_capacity = 0;
    }
  }
};
thread_local ShadowRelease g_shadow_release;

/// Makes room for one more frame. False when the ceiling is reached or the mapping fails.
///
/// mmap rather than the allocator: priv_doca_malloc is one of the trampolined symbols, so
/// allocating here would re-enter the very path being recorded.
bool shadow_reserve() {
  if (g_depth < g_capacity) return true;
  const int want = g_capacity == 0 ? kShadowStart : g_capacity * 2;
  if (want > kShadowHardMax) return false;
  const std::size_t bytes = static_cast<std::size_t>(want) * sizeof(ShadowFrame);
  void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return false;
  if (g_shadow != nullptr) {
    std::memcpy(p, g_shadow, static_cast<std::size_t>(g_depth) * sizeof(ShadowFrame));
    munmap(g_shadow, static_cast<std::size_t>(g_capacity) * sizeof(ShadowFrame));
  }
  g_shadow = static_cast<ShadowFrame*>(p);
  g_capacity = want;
  (void)&g_shadow_release;  // referenced so the thread-exit destructor is registered
  return true;
}

void emit_tramp(const char* name, std::uint64_t t0, std::uint64_t dur_ns) {
  // Loaded once: every sink() re-checks the function-local static's initialisation guard,
  // and this runs per wrapped call.
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  // Per call, not cached in a static: this function is shared by every trampolined symbol, so a
  // static would classify them all as whichever arrived first. With no exception list configured
  // the check is two empty-string tests, and only a run that uses one pays for the match.
  if (datacrumbs::client::gotcha_wrap::aggregates(name)) {
    s->aggregate(name, DC_CAT_VARIADIC, DC_TYPE, t0, dur_ns);
    return;
  }
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":")" DC_CAT_VARIADIC R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s","tool":"tramp"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()), name, static_cast<long>(datacrumbs::client::self_pid()),
      static_cast<int>(datacrumbs::client::self_tid()),
      static_cast<unsigned long long>(s->clock().remap(t0) / DATACRUMBS_TIME_DIVISOR_NS),
      static_cast<unsigned long long>(dur_ns / DATACRUMBS_TIME_DIVISOR_NS), s->hhash().c_str());
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

void emit_tramp_entry(const char* name) {
  // Loaded once: every sink() re-checks the function-local static's initialisation guard,
  // and this runs per wrapped call.
  datacrumbs::client::PfwSink* s = sink();
  if (s == nullptr) return;
  const std::uint64_t now = datacrumbs::client::gotcha_wrap::mono_ns();
  // Per call, not cached in a static: this function is shared by every trampolined symbol, so a
  // static would classify them all as whichever arrived first. With no exception list configured
  // the check is two empty-string tests, and only a run that uses one pays for the match.
  if (datacrumbs::client::gotcha_wrap::aggregates(name)) {
    // A trampoline tail-jumps, so there is no return to time. Counted with a zero duration: the
    // call count is real, and a made-up duration would not be.
    s->aggregate(name, DC_CAT_VARIADIC, DC_TYPE, now, 0);
    return;
  }
  char line[512];
  const int n = std::snprintf(
      line, sizeof(line),
      R"({"id":%llu,"name":"%s","cat":")" DC_CAT_VARIADIC R"(","type":")" DC_TYPE
      R"(","pid":%ld,"tid":%d,"ts":%llu,"ph":2,"args":{"hhash":"%s","tool":"tramp"}})"
      "\n",
      static_cast<unsigned long long>(s->next_id()), name, static_cast<long>(datacrumbs::client::self_pid()),
      static_cast<int>(datacrumbs::client::self_tid()),
      static_cast<unsigned long long>(s->clock().remap(datacrumbs::client::gotcha_wrap::mono_ns()) /
                                      DATACRUMBS_TIME_DIVISOR_NS),
      s->hhash().c_str());
  if (n > 0) s->write(line, static_cast<std::size_t>(n));
}

}  // namespace

/// Resolves the real symbol on first call, opens a shadow frame, and says where to jump.
///
/// @p lr_out receives the link register to install: the return thunk when the call was recorded, or
/// the caller's own return address when it was not, so an unrecordable call still returns
/// correctly.
extern "C" void* dc_tramp_enter(const char* name, void** slot, void* ret, void* sp, void** lr_out) {
  void* target = __atomic_load_n(slot, __ATOMIC_ACQUIRE);
  if (target == nullptr) {
    target = dlsym(RTLD_NEXT, name);
    // Nothing to jump to means the process would branch to null. Naming the symbol here beats
    // dying at address zero with no context.
    if (target == nullptr) {
      DC_LOG_ERROR("[api] no next definition of %s to trampoline to", name);
      std::abort();
    }
    __atomic_store_n(slot, target, __ATOMIC_RELEASE);
  }
  if (lr_out != nullptr) *lr_out = ret;  // no hook unless a frame is opened below

  // The sink formats and writes, which can re-enter through a symbol that is itself trampolined.
  // doca_log is in this set, so the guard is load-bearing rather than defensive.
  static thread_local int in_tramp = 0;
  if (in_tramp != 0 || sink() == nullptr) return target;

  if (lr_out != nullptr && shadow_reserve()) {
    g_shadow[g_depth].name = name;
    g_shadow[g_depth].ret = ret;
    g_shadow[g_depth].sp = reinterpret_cast<std::uintptr_t>(sp);
    g_shadow[g_depth].t0 = datacrumbs::client::gotcha_wrap::mono_ns();
    ++g_depth;
    *lr_out = reinterpret_cast<void*>(&dc_tramp_return_thunk);
    return target;
  }
  // Entry only: the shadow stack could not grow, so this call is forwarded without a duration
  // rather than with a return address that cannot be given back.
  in_tramp = 1;
  emit_tramp_entry(name);
  in_tramp = 0;
  return target;
}

/// Closes the frame the returning call opened and hands back its return address.
///
/// Pops until the recorded stack pointer matches, because frames abandoned by a longjmp or an
/// unwinding exception never return through here and would otherwise sit on the stack forever,
/// shifting every later return onto the wrong address.
extern "C" void* dc_tramp_exit(void* sp) {
  const auto here = reinterpret_cast<std::uintptr_t>(sp);
  while (g_depth > 0 && g_shadow[g_depth - 1].sp < here) --g_depth;
  if (g_depth == 0) {
    // Nothing left to return to. Continuing would branch to whatever happened to be in the
    // register, so stop here where the cause is still visible.
    DC_LOG_ERROR("[api] trampoline shadow stack empty on return; frame lost");
    std::abort();
  }
  --g_depth;
  const ShadowFrame f = g_shadow[g_depth];
  static thread_local int in_tramp = 0;
  if (in_tramp == 0) {
    in_tramp = 1;
    emit_tramp(f.name, f.t0, datacrumbs::client::gotcha_wrap::mono_ns() - f.t0);
    in_tramp = 0;
  }
  return f.ret;
}

void datacrumbs::client::wrap::fini() {
  // Flush without unbinding. GOTCHA's order is stop producers, unbind, flush; at exit there is no
  // producer left to stop, and unbinding first truncated dftracer's output on 11 of 16 ranks.
  if (sink() != nullptr) sink()->flush();
}

#if !DATACRUMBS_UTILS_HAVE_API_WRAP
// Standalone build: this surface is its own preloaded library and the client's datacrumbs_init
// does not know it exists, so preloading it did nothing at all - the trace simply had no api tier
// and looked like a workload that never called the API. Everything init touches is safe this
// early: the configuration and the sink are both built on first use.
__attribute__((constructor)) static void datacrumbs_api_trace_ctor(void) {
  datacrumbs::client::wrap::init();
}
#endif
