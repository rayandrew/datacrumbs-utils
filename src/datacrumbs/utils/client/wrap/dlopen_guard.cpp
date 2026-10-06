// SPDX-License-Identifier: MIT

// GOTCHA (LLNL/GOTCHA, src/gotcha_dl.c, LGPL-2.1) wraps dlopen as tool "gotcha" and, after every
// call, retries prepare_symbol for each binding in notfound_binding_table and rewalks the GOTs.
// The API shim leaves most of its names unresolved in any one process, so each such call is slow,
// and DOCA device open makes RTLD_NOLOAD calls of its own.
//
// What the guard relies on, read in GOTCHA 1.0.10 (master 38592ba, libgotcha.so.2.6.2):
// - a binding of a tool with a higher priority number goes ahead of the existing head
//   (rewrite_wrapper_orders), and "gotcha" keeps the unset priority, -1;
// - prepare_symbol searches every object on _r_debug.r_map whatever its RTLD_LOCAL/GLOBAL scope,
//   so a rescan can only find something new after an object is added to the map;
// - GOTCHA wraps dlsym and answers "dlopen" with a wrapper, but not dlvsym, which is how the
//   real dlopen is resolved here.

#include <datacrumbs/common/logging.h>
#include <datacrumbs/utils/client/wrap/dlopen_guard.h>
#include <dlfcn.h>
#include <gotcha/gotcha.h>
#include <link.h>

#include <atomic>
#include <cstddef>
#include <mutex>

namespace {

using DlopenFn = void* (*)(const char*, int);

constexpr int kGuardPriority = 1;

gotcha_wrappee_handle_t g_h_dlopen = nullptr;
std::atomic<DlopenFn> g_real{nullptr};
// glibc's count of objects ever added to the link map, as of the last GOTCHA rescan.
std::atomic<unsigned long long> g_scanned{0};

int read_adds(dl_phdr_info* info, std::size_t size, void* out) {
  if (size < offsetof(dl_phdr_info, dlpi_adds) + sizeof(info->dlpi_adds)) return -1;
  *static_cast<unsigned long long*>(out) = info->dlpi_adds;
  return 1;
}

/// 0 when this libc does not report the count.
unsigned long long loads() {
  unsigned long long n = 0;
  dl_iterate_phdr(read_adds, &n);
  return n;
}

// Reentered from library constructors during a load and called from any thread. A load by
// another path (a constructor, another thread) also moves the count, so the next dlopen rescans.
void* dlopen_front(const char* file, int flags) {
  const auto chain = reinterpret_cast<DlopenFn>(gotcha_get_wrappee(g_h_dlopen));
  const DlopenFn real = g_real.load(std::memory_order_acquire);
  if (real == nullptr) return chain(file, flags);
  void* handle = real(file, flags);
  // A failed dlopen returns before any rescan, which would replace the caller's dlerror text.
  if (handle == nullptr) return handle;
  const unsigned long long now = loads();
  if (now == g_scanned.load(std::memory_order_acquire)) return handle;
  g_scanned.store(now, std::memory_order_release);
  // Reopened without loading: GOTCHA rescans and patches the new objects and maps nothing.
  void* again = chain(file, flags | RTLD_NOLOAD);
  if (again != nullptr) dlclose(again);
  return handle;
}

// glibc 2.34 moved dlopen into libc under a new version node; the older nodes are per arch.
constexpr const char* kDlopenVersions[] = {"GLIBC_2.34", "GLIBC_2.2.5", "GLIBC_2.17"};

void* real_dlopen() {
  for (const char* v : kDlopenVersions)
    if (void* f = dlvsym(RTLD_NEXT, "dlopen", v)) return f;
  return nullptr;
}

gotcha_binding_t g_binding[] = {
    {"dlopen", reinterpret_cast<void*>(dlopen_front), &g_h_dlopen},
};

}  // namespace

bool datacrumbs::client::wrap::install_dlopen_guard() {
  static bool active = false;
  static std::once_flag once;
  std::call_once(once, [] {
    if (loads() == 0) {
      DC_LOG_WARN("[api] libc reports no dlpi_adds; every dlopen rescans through GOTCHA");
      return;
    }
    gotcha_set_priority("datacrumbs_dlopen", kGuardPriority);
    const gotcha_error_t rc = ::gotcha_wrap(g_binding, 1, "datacrumbs_dlopen");
    if (rc != GOTCHA_SUCCESS) {
      DC_LOG_ERROR("[api] gotcha_wrap(dlopen) failed: %d", static_cast<int>(rc));
      return;
    }
    void* real = real_dlopen();
    void* next = gotcha_get_wrappee(g_h_dlopen);
    if (real == nullptr || real == reinterpret_cast<void*>(dlopen_front) || real == next) {
      DC_LOG_WARN("[api] cannot resolve the real dlopen past GOTCHA; every dlopen rescans");
      return;
    }
    g_scanned.store(loads(), std::memory_order_release);
    g_real.store(reinterpret_cast<DlopenFn>(real), std::memory_order_release);
    active = true;
  });
  return active;
}
