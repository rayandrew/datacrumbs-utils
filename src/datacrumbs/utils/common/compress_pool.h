// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_COMMON_COMPRESS_POOL_H
#define DATACRUMBS_UTILS_COMMON_COMPRESS_POOL_H

#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/tracer_thread.h>

#include <atomic>
#include <condition_variable>
#if DATACRUMBS_HAVE_LIBDEFLATE
#include <libdeflate.h>
#endif
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace datacrumbs::client {

/// One gzip member from one block. libdeflate when the build has it, else zlib; the file is the
/// same either way. The compressor object is per thread: it is not thread-safe and costs to make.
inline std::vector<uint8_t> gzip_member(const std::string& block, int level) {
#if DATACRUMBS_HAVE_LIBDEFLATE
  thread_local struct libdeflate_compressor* c = nullptr;
  thread_local int c_level = -1;
  if (c == nullptr || c_level != level) {
    if (c != nullptr) libdeflate_free_compressor(c);
    c = libdeflate_alloc_compressor(level < 1 ? 1 : level);
    c_level = level;
  }
  if (c != nullptr) {
    std::vector<uint8_t> out(libdeflate_gzip_compress_bound(c, block.size()));
    const std::size_t n =
        libdeflate_gzip_compress(c, block.data(), block.size(), out.data(), out.size());
    if (n != 0) {
      out.resize(n);
      return out;
    }
  }
#endif
  return datacrumbs::pfw::gzip_block(block, level);
}

/// Compresses text blocks on a few threads shared by every sink. Compression dominates the cost
/// of writing a record, so it runs on dedicated threads instead of inline. Each block calls back
/// with its member; the sink keeps its own order. Heap, never destroyed: fini() calls stop().
class CompressPool {
 public:
  using Done = std::function<void(std::vector<uint8_t>)>;
  using Produce = std::function<std::string()>;

  static CompressPool& get() {
    static CompressPool& p = *new CompressPool;
    return p;
  }

  /// False when the pool has no threads, and the caller compresses inline.
  bool running() const { return started_.load(std::memory_order_acquire) && !stopping_; }

  /// A block of text, or a function that makes one on the pool thread: formatting is most of a
  /// record's cost after compression, so a job may carry the raw records and format them here.
  /// @p bytes is the text size, or an estimate of it, for the pending bound.
  void submit(Produce produce, std::size_t bytes, int level, Done done) {
    {
      std::unique_lock<std::mutex> lk(mu_);
      // Bounded: a submitter that outruns the pool waits here rather than growing memory without
      // limit. The write worker is the only submitter, so its rings absorb the pause.
      cv_.wait(lk, [this] { return bytes_ < kMaxPendingBytes || stopping_; });
      bytes_ += bytes;
      jobs_.push_back(Job{std::move(produce), bytes, level, std::move(done)});
    }
    cv_.notify_one();
  }

  void submit(std::string block, int level, Done done) {
    const std::size_t n = block.size();
    auto text = std::make_shared<std::string>(std::move(block));
    submit([text] { return std::move(*text); }, n, level, std::move(done));
  }

  /// Starts the configured threads once. Zero threads leaves the pool off.
  void start() {
    bool expect = false;
    if (!started_.compare_exchange_strong(expect, true)) return;
    const unsigned n = ConfigurationManager::runtime().compress_threads;
    for (unsigned i = 0; i < n; ++i) threads_.emplace_back([this] { run(); });
    if (n == 0) started_.store(false);
  }

  /// Finishes every pending block, then joins. Sinks destroyed afterwards compress inline.
  void stop() {
    {
      std::lock_guard<std::mutex> lk(mu_);
      stopping_ = true;
    }
    cv_.notify_all();
    for (auto& t : threads_) t.join();
    threads_.clear();
    started_.store(false);
  }

 private:
  struct Job {
    Produce produce;
    std::size_t bytes;
    int level;
    Done done;
  };

  void run() {
    TracerThread mark;
    pin_worker(ConfigurationManager::runtime().worker_cpus);
    for (;;) {
      Job job;
      {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [this] { return !jobs_.empty() || stopping_; });
        if (jobs_.empty()) return;
        job = std::move(jobs_.front());
        jobs_.pop_front();
        bytes_ -= job.bytes;
      }
      cv_.notify_all();
      job.done(gzip_member(job.produce(), job.level));
    }
  }

  static constexpr std::size_t kMaxPendingBytes = 256u * 1024 * 1024;
  std::mutex mu_;
  std::condition_variable cv_;
  std::deque<Job> jobs_;
  std::size_t bytes_ = 0;
  bool stopping_ = false;
  std::atomic<bool> started_{false};
  std::vector<std::thread> threads_;
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_COMMON_COMPRESS_POOL_H
