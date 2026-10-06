// Test for the dlopen guard: no device, no daemon. A counting dlopen wrapper sits between the
// guard and GOTCHA's own, so every call it sees is one GOTCHA rescan.

#include <datacrumbs/utils/client/wrap/dlopen_guard.h>
#include <dlfcn.h>
#include <gotcha/gotcha.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr int kSkip = 77;
// Many not-found bindings, as the API shim leaves in any one process.
constexpr int kBogusBindings = 256;
// Between the guard (1) and GOTCHA's own dlopen wrapper (unset, -1).
constexpr int kCounterPriority = 0;

int g_failures = 0;

void check(bool ok, const char* what) {
  std::fprintf(stderr, "%s %s\n", ok ? "ok  " : "FAIL", what);
  if (!ok) ++g_failures;
}

using DlopenFn = void* (*)(const char*, int);
using VersionFn = const char* (*)();

gotcha_wrappee_handle_t g_h_counter = nullptr;
int g_rescans = 0;

void* counting_dlopen(const char* file, int flags) {
  ++g_rescans;
  return reinterpret_cast<DlopenFn>(gotcha_get_wrappee(g_h_counter))(file, flags);
}

struct Candidate {
  const char* soname;
  const char* symbol;
};

// Libraries a test process does not load on its own; the first one present and not yet loaded
// is the first-time load. Each symbol takes no argument and returns a version string.
constexpr Candidate kCandidates[] = {
    {"libbz2.so.1.0", "BZ2_bzlibVersion"}, {"liblzma.so.5", "lzma_version_string"},
    {"libzstd.so.1", "ZSTD_versionString"}, {"libexpat.so.1", "XML_ExpatVersion"},
    {"libz.so.1", "zlibVersion"},
};
constexpr std::size_t kNumCandidates = sizeof(kCandidates) / sizeof(kCandidates[0]);

gotcha_wrappee_handle_t g_h_version[kNumCandidates];
int g_version_calls = 0;
std::size_t g_target = kNumCandidates;

const char* version_wrap() {
  ++g_version_calls;
  return reinterpret_cast<VersionFn>(gotcha_get_wrappee(g_h_version[g_target]))();
}

int rescans_during(const char* file, int flags, void** handle) {
  const int before = g_rescans;
  *handle = dlopen(file, flags);
  return g_rescans - before;
}

}  // namespace

int main() {
  bool not_loaded[kNumCandidates];
  std::size_t first_not_loaded = kNumCandidates;
  for (std::size_t i = 0; i < kNumCandidates; ++i) {
    not_loaded[i] = dlopen(kCandidates[i].soname, RTLD_NOW | RTLD_NOLOAD) == nullptr;
    if (not_loaded[i] && first_not_loaded == kNumCandidates) first_not_loaded = i;
  }
  if (first_not_loaded == kNumCandidates) {
    std::fprintf(stderr, "skip: every candidate library is already loaded\n");
    return kSkip;
  }

  std::vector<std::string> names;
  std::vector<gotcha_wrappee_handle_t> handles(kBogusBindings);
  std::vector<gotcha_binding_t> bindings;
  for (int i = 0; i < kBogusBindings; ++i) names.push_back("dc_dlguard_test_absent_" + std::to_string(i));
  for (int i = 0; i < kBogusBindings; ++i)
    bindings.push_back({names[i].c_str(), reinterpret_cast<void*>(version_wrap), &handles[i]});
  for (std::size_t i = 0; i < kNumCandidates; ++i)
    if (not_loaded[i])
      bindings.push_back({kCandidates[i].symbol, reinterpret_cast<void*>(version_wrap), &g_h_version[i]});
  gotcha_wrap(bindings.data(), static_cast<int>(bindings.size()), "dlguard_test");

  gotcha_binding_t counter[] = {
      {"dlopen", reinterpret_cast<void*>(counting_dlopen), &g_h_counter},
  };
  gotcha_set_priority("dlguard_test_counter", kCounterPriority);
  check(gotcha_wrap(counter, 1, "dlguard_test_counter") == GOTCHA_SUCCESS, "counter wraps dlopen");

  void* h = nullptr;
  check(rescans_during("libc.so.6", RTLD_NOW | RTLD_NOLOAD, &h) == 1 && h != nullptr,
        "control: without the guard a NOLOAD dlopen reaches GOTCHA");
  if (h != nullptr) dlclose(h);

  check(datacrumbs::client::wrap::install_dlopen_guard(), "guard installs");

  check(rescans_during("libc.so.6", RTLD_NOW | RTLD_NOLOAD, &h) == 0 && h != nullptr,
        "NOLOAD of a loaded library skips the rescan");
  if (h != nullptr) dlclose(h);
  check(rescans_during(kCandidates[first_not_loaded].soname, RTLD_NOW | RTLD_NOLOAD, &h) == 0 &&
            h == nullptr,
        "NOLOAD of a library not loaded skips the rescan");

  // A candidate absent from this system fails to load and, as checked below, does not rescan.
  void* first = nullptr;
  int first_rescans = 0;
  for (std::size_t i = 0; i < kNumCandidates && first == nullptr; ++i) {
    if (!not_loaded[i]) continue;
    first_rescans = rescans_during(kCandidates[i].soname, RTLD_NOW, &first);
    if (first != nullptr) g_target = i;
  }
  if (first == nullptr) {
    std::fprintf(stderr, "skip: no candidate library could be loaded\n");
    return kSkip;
  }
  const Candidate& lib = kCandidates[g_target];
  std::fprintf(stderr, "first-time load: %s (%s)\n", lib.soname, lib.symbol);
  check(first_rescans == 1, "first-time load rescans once");
  void* sym = dlsym(first, lib.symbol);
  check(sym == reinterpret_cast<void*>(version_wrap), "dlsym of the new library returns the wrapper");
  check(gotcha_get_wrappee(g_h_version[g_target]) != nullptr, "the binding resolved after the load");
  if (sym != nullptr) {
    const char* v = reinterpret_cast<VersionFn>(sym)();
    check(g_version_calls == 1 && v != nullptr && *v != '\0', "the wrapped call reaches the library");
  }

  int reopen_rescans = 0;
  for (int i = 0; i < 20; ++i) {
    void* a = nullptr;
    void* b = nullptr;
    reopen_rescans += rescans_during(lib.soname, RTLD_NOW | RTLD_NOLOAD, &a);
    reopen_rescans += rescans_during(lib.soname, RTLD_NOW, &b);
    if (a != nullptr) dlclose(a);
    if (b != nullptr) dlclose(b);
  }
  check(reopen_rescans == 0, "NOLOAD and reopen of the loaded library skip the rescan");

  dlerror();
  void* bad = nullptr;
  check(rescans_during("libdc-dlguard-test-absent.so", RTLD_NOW, &bad) == 0 && bad == nullptr,
        "a failed dlopen skips the rescan");
  const char* err = dlerror();
  check(err != nullptr && std::strstr(err, "libdc-dlguard-test-absent.so") != nullptr,
        "dlerror names the library after a failed dlopen");
  std::fprintf(stderr, "dlerror: %s\n", err != nullptr ? err : "(null)");

  std::fprintf(stderr, "%d failure(s)\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
