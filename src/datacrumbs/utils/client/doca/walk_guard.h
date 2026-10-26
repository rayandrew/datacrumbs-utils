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

inline bool is_ours(const struct sigaction& a) {
  return (a.sa_flags & SA_SIGINFO) != 0 && a.sa_sigaction == on_fault;
}

/// Put our handler on @p sig unless it is already there. Whatever was there becomes the handler a
/// fault outside a walk goes to.
inline void take(int sig, struct sigaction* prev) {
  struct sigaction cur {};
  if (sigaction(sig, nullptr, &cur) != 0 || is_ours(cur)) return;
  struct sigaction sa {};
  sa.sa_sigaction = on_fault;
  // SA_NODEFER: the jump leaves the handler without restoring the mask, so the signal must not
  // stay blocked, or the next fault on this thread would kill the process outright.
  sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
  sigemptyset(&sa.sa_mask);
  *prev = cur;
  sigaction(sig, &sa, nullptr);
}

/// Install the handler for SIGSEGV and SIGBUS, before the first guarded walk. Call it again
/// later: a library that installs its own handler afterwards (UCX at MPI_Init) takes the fault
/// first, and this puts ours back in front of it.
inline void install() {
  take(SIGSEGV, &g_prev_segv);
  take(SIGBUS, &g_prev_bus);
}

/// Whether the SIGSEGV handler is still ours.
inline bool installed() {
  struct sigaction cur {};
  return sigaction(SIGSEGV, nullptr, &cur) == 0 && is_ours(cur);
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
