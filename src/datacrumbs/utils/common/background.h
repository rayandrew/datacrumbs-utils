// SPDX-License-Identifier: MIT

// The client's two background threads, shared by every module. A module registers a tick, not
// a thread. The scan worker runs only work that must keep pace with hardware, and sweeps again
// while busy. The write worker runs everything that tolerates a millisecond stall: formatting,
// sink writes, DPA bursts, samplers. Both are tracer threads: nothing they do appears in a trace.

#ifndef DATACRUMBS_UTILS_COMMON_BACKGROUND_H
#define DATACRUMBS_UTILS_COMMON_BACKGROUND_H

#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/tracer_thread.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace datacrumbs::client {

class Background {
 public:
  /// A tick returns true when it found work, which keeps its worker awake for another round.
  using Tick = std::function<bool()>;

  struct Task {
    Tick tick;
    std::atomic<bool> live{true};
    std::mutex running;
  };

  /// Heap, never destroyed: a static with a destructor runs before the library's fini and a
  /// joinable std::thread destroyed there terminates the process. fini() calls stop() instead.
  static Background& get() {
    static Background& b = *new Background;
    return b;
  }

  /// Registers on the scan worker. Returns a handle for remove().
  std::shared_ptr<Task> add_scan(Tick tick) { return add(scan_, std::move(tick)); }
  /// Registers on the write worker.
  std::shared_ptr<Task> add_write(Tick tick) { return add(write_, std::move(tick)); }

  /// A removed task is never called again once remove() returns.
  void remove(const std::shared_ptr<Task>& t) {
    if (t == nullptr) return;
    t->live.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lk(t->running);  // waits out a call in progress
  }

  /// Joins both workers. After this every sink falls back to writing on the caller's thread.
  void stop() {
    stopping_.store(true, std::memory_order_release);
    if (scan_.thread.joinable()) scan_.thread.join();
    if (write_.thread.joinable()) write_.thread.join();
    stopped_.store(true, std::memory_order_release);
  }

  static bool stopped() { return get().stopped_.load(std::memory_order_acquire); }

 private:
  struct Worker {
    std::mutex mu;
    std::vector<std::shared_ptr<Task>> tasks;
    std::thread thread;
    bool started = false;
  };

  Background() = default;

  std::shared_ptr<Task> add(Worker& w, Tick tick) {
    auto t = std::make_shared<Task>();
    t->tick = std::move(tick);
    std::lock_guard<std::mutex> lk(w.mu);
    w.tasks.push_back(t);
    if (!w.started) {
      w.started = true;
      w.thread = std::thread([this, &w] { run(w); });
    }
    return t;
  }

  void run(Worker& w) {
    TracerThread mark;
    pin_worker(ConfigurationManager::runtime().worker_cpus);
    std::vector<std::shared_ptr<Task>> snapshot;
    while (!stopping_.load(std::memory_order_acquire)) {
      {
        std::lock_guard<std::mutex> lk(w.mu);
        snapshot = w.tasks;
      }
      bool busy = false;
      for (auto& t : snapshot) {
        if (!t->live.load(std::memory_order_acquire)) continue;
        std::lock_guard<std::mutex> lk(t->running);
        if (t->live.load(std::memory_order_acquire) && t->tick()) busy = true;
      }
      if (!busy) std::this_thread::sleep_for(std::chrono::microseconds(kIdleSleepUs));
    }
  }

  static constexpr unsigned kIdleSleepUs = 100;
  Worker scan_;
  Worker write_;
  std::atomic<bool> stopping_{false};
  std::atomic<bool> stopped_{false};
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_COMMON_BACKGROUND_H
