// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_GOTCHA_WRAP_H
#define DATACRUMBS_UTILS_CLIENT_GOTCHA_WRAP_H

#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/pfw_sink.h>
#include <dlfcn.h>
#include <gotcha/gotcha.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <type_traits>

/**
 * @brief Wraps the classified API surface with GOTCHA, one wrapper per symbol.
 * Expand DC_WRAPPED_FUNCS with DC_GOTCHA_DECL, _WRAPPER, then _BINDING, in that order, after
 * defining DC_GOTCHA_SINK and DC_GOTCHA_STACK. ibv_post_send and ibv_poll_cq are static inline with
 * no symbol to bind; see rdma_hwts.cpp instead.
 */

namespace datacrumbs::client::gotcha_wrap {

using datacrumbs::client::mono_ns;

inline thread_local int g_in_wrapper = 0;

/// Suppresses recording while inside a wrapper, since the sink formats and writes and can
/// re-enter. Also suppresses on a thread TracerThread marked (pfw_sink.h), so datacrumbs' own
/// vendor-API calls are never recorded as if the traced application had made them.
struct Guard {
  bool entered;
  Guard() : entered(g_in_wrapper == 0 && !datacrumbs::client::g_tracer_thread) {
    if (entered) g_in_wrapper = 1;
  }
  ~Guard() {
    if (entered) g_in_wrapper = 0;
  }
};

/// How @p name is captured under this module's mode and its exception lists. Called from a
/// function-local static in each generated wrapper, so the match runs once per symbol rather
/// than once per call.
inline ConfigurationManager::CaptureMode mode_of(const char* name) {
  const auto& rt = ConfigurationManager::runtime();
  return ConfigurationManager::mode_for(rt.api_mode, rt.api_select, name);
}

inline bool aggregates(const char* name) {
  return mode_of(name) == ConfigurationManager::CaptureMode::AGGREGATE;
}

/// The function a wrapper forwards to. GOTCHA's wrappee is wrong for a library loaded after
/// the wrap: it points back into this shim and the wrapper calls itself until the stack is gone.
/// Then the next definition past the shim is the real one.
inline void* real_of(gotcha_wrappee_handle_t handle, const char* name, void* self) {
  void* r = gotcha_get_wrappee(handle);
  if (r == nullptr || r == self) return r == self ? dlsym(RTLD_NEXT, name) : nullptr;
  Dl_info here, there;
  if (dladdr(self, &here) != 0 && dladdr(r, &there) != 0 && here.dli_fbase == there.dli_fbase)
    return dlsym(RTLD_NEXT, name);
  return r;
}

/// The site handle every wrapper resolves once, in its function-local static.
inline AggSite* site_for(PfwSink* sink, const char* name, const char* cls, const char* stack) {
  if (sink == nullptr) return nullptr;
  return sink->site(name, cls, stack, "gotcha");
}

/// Nothing is formatted here: an aggregate adds the numeric args into the thread's tally, and a
/// record is a binary copy into the thread's ring for the write worker.
inline void emit(PfwSink* sink, AggSite* site, bool aggregate, std::uint64_t start_ns,
                 std::uint64_t dur_ns, const NumArg* args, int nargs) {
  if (sink == nullptr || site == nullptr) return;
  if (aggregate)
    sink->tally(site, start_ns + dur_ns, dur_ns, args, nargs);
  else
    sink->record(site, start_ns, dur_ns, args, nargs);
}

/// Records a wrapped call's return as a "ret" arg, but only where the return is a quantity: a
/// byte count (ssize_t, size_t), not a status or an identity. Templated so the untaken branches
/// are never compiled for a mismatched Ret. A negative ssize_t is recorded as 0, not as a corrupt
/// huge unsigned value.
template <typename Ret>
inline void capture_ret([[maybe_unused]] Ret r, [[maybe_unused]] NumArg* args,
                        [[maybe_unused]] int& n) {
  if constexpr (std::is_same_v<Ret, ssize_t>) {
    if (n < kMaxAggArgs) {
      args[n].key = "ret";
      args[n].kind = NumKind::INT;
      args[n].i = r > 0 ? static_cast<long long>(r) : 0;
      ++n;
    }
  } else if constexpr (std::is_same_v<Ret, size_t>) {
    if (n < kMaxAggArgs) {
      args[n].key = "ret";
      args[n].kind = NumKind::UINT;
      args[n].u = static_cast<unsigned long long>(r);
      ++n;
    }
  }
}

}  // namespace datacrumbs::client::gotcha_wrap

// Each DC_A_* stores one NumArg. No decoder and no snprintf runs on the calling thread: the write
// worker formats a record, and an aggregate keeps only the numeric kinds. A pointer is recorded as
// an identity, not dereferenced.
#define DC_A_PUSH(k, key_, field, value, fn_field, fn)     \
  if (_dc_n < datacrumbs::client::kMaxAggArgs) {           \
    _dc_args[_dc_n].key = key_;                            \
    _dc_args[_dc_n].kind = datacrumbs::client::NumKind::k; \
    _dc_args[_dc_n].field = value;                         \
    _dc_args[_dc_n].fn_field = fn;                         \
    ++_dc_n;                                               \
  }
#define DC_A_INT(x) DC_A_PUSH(INT, #x, i, static_cast<long long>(x), enum_fn, nullptr)
#define DC_A_PTR(x) DC_A_PUSH(PTR, #x, p, reinterpret_cast<const void*>(x), enum_fn, nullptr)
// An enum records its constant name; a value the header does not name falls back to the number.
#define DC_A_ENUM(x, decoder) \
  DC_A_PUSH(ENUM, #x, i, static_cast<long long>(x), enum_fn, dc_enum_##decoder)
// A flag word decodes to the constants it sets, joined by |, with the raw value alongside.
#define DC_A_FLAGS(x, decoder) \
  DC_A_PUSH(FLAGS, #x, i, static_cast<long long>(x), flags_fn, dc_flags_##decoder)
// The opcode inside a command buffer: mlx5 puts it in the first two bytes, big endian. Bounds
// checked, since a caller may pass a short buffer.
#define DC_A_CMD(buf, len, decoder)                                                       \
  if ((buf) != nullptr && (len) >= 2) {                                                   \
    const auto* _dc_b = reinterpret_cast<const unsigned char*>(buf);                      \
    DC_A_PUSH(CMD, "cmd", i, (static_cast<long long>(_dc_b[0]) << 8) | _dc_b[1], enum_fn, \
              dc_enum_##decoder)                                                          \
  }
// An op carried in an attribute struct: the field at a machine-computed offset, read at its own
// width. The pointer is checked, since an optional attribute may be null.
#define DC_A_FIELD(ptr, off, width, label, decoder)                                         \
  if ((ptr) != nullptr) {                                                                   \
    unsigned long long _dc_v = 0;                                                           \
    __builtin_memcpy(&_dc_v, reinterpret_cast<const unsigned char*>(ptr) + (off), (width)); \
    DC_A_PUSH(FIELD, #label, u, _dc_v, enum_fn, dc_enum_##decoder)                          \
  }

#define DC_GOTCHA_DECL(name, cls, ret, params, vargs, argrecs, is_void) \
  typedef ret(*name##_fptr) params;                                     \
  static gotcha_wrappee_handle_t name##_handle;

#define DC_GOTCHA_RECORD(name, cls, argrecs, retcap)                                              \
  datacrumbs::client::NumArg _dc_args[datacrumbs::client::kMaxAggArgs];                           \
  [[maybe_unused]] int _dc_n = 0;                                                                 \
  static datacrumbs::client::AggSite* const _dc_site =                                            \
      datacrumbs::client::gotcha_wrap::site_for(DC_GOTCHA_SINK, #name, #cls, DC_GOTCHA_STACK);    \
  argrecs retcap datacrumbs::client::gotcha_wrap::emit(                                           \
      DC_GOTCHA_SINK, _dc_site,                                                                   \
      _dc_mode == datacrumbs::ConfigurationManager::CaptureMode::AGGREGATE, _dc_t0,               \
      _dc_t1 - _dc_t0, _dc_args, _dc_n);

// Once per symbol, not once per call. A symbol the selection turns off forwards before the
// guard and the clock: the trampoline is then the whole cost. Measured on a 4 KiB ping-pong,
// 24 wrapped calls per round trip: timing them all cost 2 us whether or not they were recorded.
#define DC_GOTCHA_MODE(name)                                                     \
  static const datacrumbs::ConfigurationManager::CaptureMode _dc_mode =          \
      datacrumbs::client::gotcha_wrap::mode_of(#name);

// _dc_r is declared before the null check so the early return has a value; `ret()` cannot be
// written for a pointer return without parsing as a function type.
#define DC_GOTCHA_WRAPPER_0(name, cls, ret, params, vargs, argrecs)                         \
  static ret name##_dcwrap params {                                                         \
    ret _dc_r{};                                                                            \
    static name##_fptr _dc_real = nullptr;                                                  \
    if (_dc_real == nullptr)                                                                \
      _dc_real = reinterpret_cast<name##_fptr>(datacrumbs::client::gotcha_wrap::real_of(    \
          name##_handle, #name, reinterpret_cast<void*>(&name##_dcwrap)));                  \
    auto real = _dc_real;                                                                   \
    if (real == nullptr) return _dc_r;                                                      \
    DC_GOTCHA_MODE(name)                                                                    \
    if (_dc_mode == datacrumbs::ConfigurationManager::CaptureMode::OFF) return real vargs;  \
    datacrumbs::client::gotcha_wrap::Guard _dc_g;                                           \
    if (!_dc_g.entered) return real vargs;                                                  \
    const std::uint64_t _dc_t0 = datacrumbs::client::gotcha_wrap::mono_ns();                \
    _dc_r = real vargs;                                                                     \
    const std::uint64_t _dc_t1 = datacrumbs::client::gotcha_wrap::mono_ns();                \
    DC_GOTCHA_RECORD(name, cls, argrecs,                                                    \
                     datacrumbs::client::gotcha_wrap::capture_ret(_dc_r, _dc_args, _dc_n);) \
    return _dc_r;                                                                           \
  }

#define DC_GOTCHA_WRAPPER_1(name, cls, ret, params, vargs, argrecs)               \
  static void name##_dcwrap params {                                              \
    static name##_fptr _dc_real = nullptr;                                        \
    if (_dc_real == nullptr)                                                      \
      _dc_real = reinterpret_cast<name##_fptr>(datacrumbs::client::gotcha_wrap::real_of( \
          name##_handle, #name, reinterpret_cast<void*>(&name##_dcwrap)));        \
    auto real = _dc_real;                                                         \
    if (real == nullptr) return;                                                  \
    DC_GOTCHA_MODE(name)                                                          \
    if (_dc_mode == datacrumbs::ConfigurationManager::CaptureMode::OFF) {         \
      real vargs;                                                                 \
      return;                                                                     \
    }                                                                             \
    datacrumbs::client::gotcha_wrap::Guard _dc_g;                                 \
    if (!_dc_g.entered) {                                                         \
      real vargs;                                                                 \
      return;                                                                     \
    }                                                                             \
    const std::uint64_t _dc_t0 = datacrumbs::client::gotcha_wrap::mono_ns();      \
    real vargs;                                                                   \
    const std::uint64_t _dc_t1 = datacrumbs::client::gotcha_wrap::mono_ns();      \
    DC_GOTCHA_RECORD(name, cls, argrecs, )                                        \
  }

#define DC_GOTCHA_WRAPPER_PICK(is_void) DC_GOTCHA_WRAPPER_##is_void
#define DC_GOTCHA_WRAPPER(name, cls, ret, params, vargs, argrecs, is_void) \
  DC_GOTCHA_WRAPPER_PICK(is_void)(name, cls, ret, params, vargs, argrecs)

#define DC_GOTCHA_BINDING(name, cls, ret, params, vargs, argrecs, is_void) \
  {#name, reinterpret_cast<void*>(name##_dcwrap), &name##_handle},

// The class of each binding, in the same order, so a selection can name a role rather than listing
// every symbol that plays it.
#define DC_GOTCHA_CLASS(name, cls, ret, params, vargs, argrecs, is_void) #cls,

#endif  // DATACRUMBS_UTILS_CLIENT_GOTCHA_WRAP_H
