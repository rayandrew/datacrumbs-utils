// The sweep's fault guard, on memory this test maps and unmaps itself: no device, no sweep.
// Faults outside a guard run in a forked child, since they must still end the process.

#include <datacrumbs/utils/client/doca/walk_guard.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

namespace walk = datacrumbs::utils::doca_walk;

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL %s\n", what);
    ++g_failures;
  }
}

/// A page that was mapped and then unmapped, so any read of it faults.
volatile unsigned char* dead_page() {
  void* p = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) std::abort();
  munmap(p, 4096);
  return static_cast<volatile unsigned char*>(p);
}

/// Runs @p body in a child and returns its wait status. The child writes no core.
template <class F>
int in_child(F&& body) {
  const pid_t pid = fork();
  if (pid == 0) {
    const struct rlimit none {0, 0};
    setrlimit(RLIMIT_CORE, &none);
    body();
    _exit(0);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return status;
}

void prior_handler(int, siginfo_t*, void*) { _exit(42); }

void guarded_read_of_live_memory_succeeds() {
  unsigned char live[64] = {7};
  unsigned char got = 0;
  check(walk::guarded([&] { got = static_cast<volatile unsigned char*>(live)[0]; }),
        "a walk over mapped memory reports success");
  check(got == 7, "a walk over mapped memory reads its bytes");
}

void guarded_read_of_unmapped_memory_fails() {
  volatile unsigned char* p = dead_page();
  check(!walk::guarded([&] { (void)p[3]; }), "a walk over unmapped memory reports failure");
  check(!walk::guarded([&] { (void)p[0]; }), "a second fault on the same thread is caught too");
  check(walk::guarded([] {}), "a walk after a fault runs normally");
}

void fault_outside_a_guard_still_kills() {
  const int status = in_child([] { (void)dead_page()[0]; });
  check(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV,
        "an unguarded fault ends the process with SIGSEGV");
}

void fault_outside_a_guard_reaches_the_prior_handler() {
  const int status = in_child([] {
    struct sigaction sa {};
    sa.sa_sigaction = prior_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    walk::install();
    (void)dead_page()[0];
  });
  check(WIFEXITED(status) && WEXITSTATUS(status) == 42,
        "an unguarded fault goes to the handler installed before ours");
}

void installed_reports_a_later_handler() {
  const int status = in_child([] {
    if (!walk::installed()) _exit(1);
    struct sigaction sa {};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    _exit(walk::installed() ? 2 : 0);
  });
  check(WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "installed() is true for ours and false once another handler replaces it");
}

}  // namespace

int main() {
  walk::install();
  guarded_read_of_live_memory_succeeds();
  guarded_read_of_unmapped_memory_fails();
  fault_outside_a_guard_still_kills();
  fault_outside_a_guard_reaches_the_prior_handler();
  installed_reports_a_later_handler();
  if (g_failures != 0) {
    std::fprintf(stderr, "%d failure(s)\n", g_failures);
    return 1;
  }
  std::puts("walk_guard: all checks passed");
  return 0;
}
