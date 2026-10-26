#ifndef DATACRUMBS_UTILS_CLIENT_DOCA_WALK_GUARD_H
#define DATACRUMBS_UTILS_CLIENT_DOCA_WALK_GUARD_H

#include <setjmp.h>
#include <signal.h>

/// Lets a sweep read memory the application owns and may unmap at any moment. An application can
/// unmap a registered region without a dereg, for instance a buffer freed when main returns while
/// the sweep still runs. A fault inside a guarded walk then fails that walk instead of killing the
/// process. A fault anywhere else goes to the handler that was there before.
namespace datacrumbs::utils::doca_walk {

// Initial-exec TLS, since the handler must not allocate.
inline thread_local sigjmp_buf* t_jmp __attribute__((tls_model("initial-exec"))) = nullptr;
inline struct sigaction g_prev_segv {};
inline struct sigaction g_prev_bus {};

inline void on_fault(int sig, siginfo_t* si, void* uc) {
  if (sigjmp_buf* j = t_jmp) {
    t_jmp = nullptr;
    siglongjmp(*j, 1);
  }
  const struct sigaction& prev = sig == SIGBUS ? g_prev_bus : g_prev_segv;
  if ((prev.sa_flags & SA_SIGINFO) != 0 && prev.sa_sigaction != nullptr) {
    prev.sa_sigaction(sig, si, uc);
    return;
  }
  if ((prev.sa_flags & SA_SIGINFO) == 0 && prev.sa_handler != SIG_DFL &&
      prev.sa_handler != SIG_IGN) {
    prev.sa_handler(sig);
    return;
  }
  // Returning re-runs the faulting instruction under the default action, so the process still
  // dies with the original signal and its core.
  struct sigaction dfl {};
  dfl.sa_handler = SIG_DFL;
  sigemptyset(&dfl.sa_mask);
  sigaction(sig, &dfl, nullptr);
}

/// Install the handler for SIGSEGV and SIGBUS. Call once, before the first guarded walk.
inline void install() {
  struct sigaction sa {};
  sa.sa_sigaction = on_fault;
  // SA_NODEFER: the jump leaves the handler without restoring the mask, so the signal must not
  // stay blocked, or the next fault on this thread would kill the process outright.
  sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, &g_prev_segv);
  sigaction(SIGBUS, &sa, &g_prev_bus);
}

/// Whether the SIGSEGV handler is still ours. A library that installs its own handler later takes
/// the fault first, and a walk is then unguarded.
inline bool installed() {
  struct sigaction cur {};
  if (sigaction(SIGSEGV, nullptr, &cur) != 0) return false;
  return (cur.sa_flags & SA_SIGINFO) != 0 && cur.sa_sigaction == on_fault;
}

/// Run @p walk with faults caught. Returns false if it faulted. A fault leaves through
/// siglongjmp, so the walk may touch application memory only where it holds no lock and owns no
/// object with a destructor.
template <class F>
bool guarded(F&& walk) {
  sigjmp_buf j;
  if (sigsetjmp(j, 0) != 0) return false;
  t_jmp = &j;
  walk();
  t_jmp = nullptr;
  return true;
}

}  // namespace datacrumbs::utils::doca_walk

#endif  // DATACRUMBS_UTILS_CLIENT_DOCA_WALK_GUARD_H
