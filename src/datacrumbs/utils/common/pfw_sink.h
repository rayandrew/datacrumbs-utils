// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_PFW_SINK_H
#define DATACRUMBS_UTILS_CLIENT_PFW_SINK_H

#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/datacrumbs_config.h>
#include <datacrumbs/utils/common/clock.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/common/constants.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>

namespace datacrumbs::client {

/// This process, cached. getpid is a syscall on glibc 2.25 and later and the interposer called it
/// once per record: 6.9 percent of a measured instrument, on the application's own threads where no
/// server-side gate can tell them from the application's own calls.
inline pid_t& cached_pid() {
  static pid_t pid = 0;
  return pid;
}

inline pid_t self_pid() {
  static std::once_flag once;
  std::call_once(once, [] { pthread_atfork(nullptr, nullptr, [] { cached_pid() = 0; }); });
  pid_t& pid = cached_pid();
  if (pid == 0) pid = ::getpid();
  return pid;
}

inline pid_t self_tid() {
  static thread_local pid_t tid = static_cast<pid_t>(::syscall(SYS_gettid));
  return tid;
}

/// A record's args can carry more than duration. dftracer aggregates every numeric arg as
/// <key>_sum/_min/_max and only counts a string-valued one, so a string never reaches here: the
/// wrapper that would emit "qp":"0x..." as an identity string does not build a NumArg for it.
///
/// kind is stable for a given key: the same call site always passes the same C++ type for the
/// same argument name.
enum class NumKind : unsigned char { INT, UINT, REAL };

/// One captured number, keyed by the arg's name. key is a string literal from the DC_A_* macro
/// expansion, not copied: the same call site produces the same pointer on every call, which is
/// what lets the sink find a tally's slot by pointer instead of a string compare or map lookup.
struct NumArg {
  const char* key;
  NumKind kind;
  union {
    long long i;
    unsigned long long u;
    double d;
  };
};

/// Capacity for distinct numeric-arg keys tallied per (name, cat, type, interval) bucket entry.
/// A call presenting more is not an error: the first kMaxAggArgs keys are kept, the rest dropped.
inline constexpr int kMaxAggArgs = 8;

/// One categorical arg a call site opts into aggregating. Unlike NumArg, this is not summed: it
/// becomes part of the bucket key, so each distinct value gets its own series. key and value are
/// not copied, same as NumArg's key: every call site passes a string literal or a pointer into a
/// static table, so the pointer outlives the sink.
struct CatArg {
  const char* key;
  const char* value;
};

/// Capacity for distinct categorical args carried in a bucket Key. Kept small: a categorical arg
/// is meant to be low-cardinality and few in number, not a general args bag.
inline constexpr int kMaxCatArgs = 2;

/// True while this thread is inside datacrumbs' own I/O.
///
/// The sink writes its trace with fwrite, so a module wrapping stdio traces the tracer: a program
/// doing ten fwrite calls produced eleven records, the extra one being the sink flushing. A
/// per-call guard is not enough because the sink drains on a worker thread of its own, and the
/// guard is per thread. The worker sets this for its whole life and every wrapper checks it.
inline thread_local bool g_in_datacrumbs_io = false;

/// Sets the bypass for as long as it is in scope.
struct IoBypass {
  bool prev = g_in_datacrumbs_io;
  IoBypass() { g_in_datacrumbs_io = true; }
  ~IoBypass() { g_in_datacrumbs_io = prev; }
};

}  // namespace datacrumbs::client

/// Announce a thread that only does datacrumbs' own sink I/O, so kernel probes can exclude it.
///
/// g_in_datacrumbs_io covers the userspace wrappers, but a kprobe on ext4 or the block layer cannot
/// read a thread_local, and by then no fd survives to gate on either. The server uprobes these two
/// symbols and keys a map on the tid. Call once per worker, never per write: the pair costs two
/// uprobe hits for the life of the thread.
///
/// Defined here rather than in one .cpp: every binary that owns a sink needs them, and the ones
/// that do not link the client library (window_mark) would otherwise fail to link. noinline and a
/// non-empty body keep the symbol alive for the uprobe to attach to.
extern "C" inline __attribute__((visibility("default"), noinline)) void
datacrumbs_io_thread_begin() {
  asm volatile("");
}
extern "C" inline __attribute__((visibility("default"), noinline)) void
datacrumbs_io_thread_end() {
  asm volatile("");
}

namespace datacrumbs::client {

/// Marks the calling thread as a sink worker for as long as it is in scope.
struct IoThreadMark {
  IoThreadMark() { datacrumbs_io_thread_begin(); }
  ~IoThreadMark() { datacrumbs_io_thread_end(); }
};

/**
 * @brief Per-process .pfw.gz sink for records a client emits from userspace.
 *
 * Buffers NDJSON lines and writes one gzip member per flush. Remap timestamps through clock() to
 * put them on the dc_timesync global epoch, which is what merges these records with the server
 * trace. Thread-safe. A record is not durable until flush() or the 256 KB threshold.
 */
class PfwSink {
 public:
  /// Writes <dir>/trace-<tag>-<pid>-<host>.pfw.gz, taking <dir> from @p dir_env, else
  /// DATACRUMBS_LOG_DIR, else /tmp. Terminates the process if the file cannot be opened: capture is
  /// opt-in, so a sink that silently drops every record is indistinguishable from an empty run.
  PfwSink(const char* tag, const char* dir_env) : tag_(tag) {
    reader_.map();
    char host[256] = {0};
    gethostname(host, sizeof(host) - 1);
    hhash_ = datacrumbs::pfw::hhash(host);

    // dir_env names a per-sink override chosen by the caller, so the lookup is by name rather
    // than a field; everything with a fixed name comes off the manager.
    std::string dir = dir_env != nullptr ? ConfigurationManager::env_text(dir_env) : std::string();
    if (dir.empty()) dir = ConfigurationManager::runtime().log_dir;
    if (dir.empty()) dir = "/tmp";
    mkdir(dir.c_str(), 0755);  // callers pass a per-run dir; without this fopen just fails

    char path[1024];
    std::snprintf(path, sizeof(path), "%s/trace-%s-%d-%s.pfw.gz", dir.c_str(), tag, getpid(), host);
    file_ = std::fopen(path, "wb");
    if (file_ == nullptr) {
      DC_LOG_ERROR("[%s] cannot open %s: %s", tag, path, std::strerror(errno));
      _exit(1);
    }

    declare(path);

    char hh[512];
    const int n = std::snprintf(
        hh, sizeof(hh),
        R"({"name":"HH","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
        "\n",
        hhash_.c_str(), host, hhash_.c_str());
    buf_.append(hh, static_cast<std::size_t>(n));

    // ts and dur are microseconds, which every reader has had to assume so far. dftracer states it
    // instead, so a reader never has to, and a future change of unit cannot silently rescale a
    // whole trace. The *_ns args on an aggregated record are not affected: they name their unit.
    char tm[256];
    const int tn = std::snprintf(
        tm, sizeof(tm),
        R"({"name":"time_metric","cat":"dftracer","type":"metadata","ph":4,)"
        R"("args":{"hhash":"%s","name":"time_metric","value":")" DATACRUMBS_TIME_UNIT R"("}})"
        "\n",
        hhash_.c_str());
    if (tn > 0) buf_.append(tm, static_cast<std::size_t>(tn));

    declare_libraries();
    if (async_) {
      // A forked child inherits the queue but not the worker thread, so it would enqueue into a
      // drain that never runs and block forever once the queue filled. Fall back to sync there.
      pthread_atfork(nullptr, nullptr, [] { forked() = true; });
      worker_ = std::thread([this] {
        IoBypass bypass;      // everything this thread writes is ours
        IoThreadMark marked;  // and the kernel probes need telling separately
        drain();
      });
    }
    flush_locked();  // HH as its own member, matching the server writer's layout
  }

  ~PfwSink() {
    flush_buckets();
    flush();
    if (async_) {
      {
        std::lock_guard<std::mutex> lock(qmu_);
        stop_ = true;
      }
      qcv_.notify_all();
      if (worker_.joinable()) worker_.join();
    }
    if (file_ != nullptr) std::fclose(file_);
  }

  PfwSink(const PfwSink&) = delete;
  PfwSink& operator=(const PfwSink&) = delete;

  void write(const char* line, std::size_t n) {
    std::lock_guard<std::mutex> lock(mu_);
    buf_.append(line, n);
    if (buf_.size() >= kFlushBytes) flush_locked();
  }

  void flush() {
    std::lock_guard<std::mutex> lock(mu_);
    flush_locked();
  }

  /// Aggregates one call instead of writing a record for it, into the same (name, interval)
  /// buckets the kernel path uses, so a reader cannot tell where a name was aggregated.
  ///
  /// @p cat and @p type must be what this call would have carried as a record, and must outlive
  /// the sink: they are stored, not copied, and every caller passes a literal. @p name is copied,
  /// so a caller may pass a buffer it is about to reuse.
  ///
  /// The saving is the record, not the interception: the call is still wrapped and still timed,
  /// but a per-call line is a few hundred bytes to format, buffer and compress, and this is one
  /// add. Aggregating over the whole run would be cheaper still and would say nothing about when
  /// a workload changed, which is the question a trace exists to answer.
  void aggregate(const char* name, const char* cat, const char* type, std::uint64_t start_ns,
                 std::uint64_t dur_ns, const NumArg* args = nullptr, int nargs = 0,
                 const CatArg* cats = nullptr, int ncats = 0) {
    const std::uint64_t bucket = start_ns / DATACRUMBS_TIME_INTERVAL_NS;
    Key key{name, cat, type, {}, 0};
    for (int i = 0; i < ncats && i < kMaxCatArgs; ++i) key.cats[key.ncats++] = cats[i];
    std::lock_guard<std::mutex> lock(tally_mu_);
    Tally& t = buckets_[bucket][key];
    ++t.count;
    t.sum_ns += dur_ns;
    t.sum_sq_ns2 += static_cast<unsigned long long>(dur_ns) * dur_ns;
    if (dur_ns < t.min_ns) t.min_ns = dur_ns;
    if (dur_ns > t.max_ns) t.max_ns = dur_ns;
    for (int i = 0; i < nargs; ++i) {
      const NumArg& a = args[i];
      NumTally* nt = nullptr;
      // Linear scan over at most kMaxAggArgs entries, by pointer: cheaper than the map lookup
      // it would take to avoid, since a key is a string literal fixed at its call site.
      for (int j = 0; j < t.nnums; ++j) {
        if (t.nums[j].key == a.key) {
          nt = &t.nums[j];
          break;
        }
      }
      if (nt == nullptr) {
        if (t.nnums >= kMaxAggArgs) continue;  // beyond capacity: drop the key, do not crash
        nt = &t.nums[t.nnums++];
        nt->key = a.key;
        nt->kind = a.kind;
      }
      if (nt->kind != a.kind)
        continue;  // kind is stable per key; a mismatch is dropped, not merged
      ++nt->count;
      switch (a.kind) {
        case NumKind::INT:
          nt->sum_i += a.i;
          nt->sum_sq_i +=
              static_cast<unsigned long long>(a.i) * static_cast<unsigned long long>(a.i);
          if (a.i < nt->min_i) nt->min_i = a.i;
          if (a.i > nt->max_i) nt->max_i = a.i;
          break;
        case NumKind::UINT:
          nt->sum_u += a.u;
          nt->sum_sq_u += a.u * a.u;
          if (a.u < nt->min_u) nt->min_u = a.u;
          if (a.u > nt->max_u) nt->max_u = a.u;
          break;
        case NumKind::REAL:
          nt->sum_d += a.d;
          nt->sum_sq_d += a.d * a.d;
          if (a.d < nt->min_d) nt->min_d = a.d;
          if (a.d > nt->max_d) nt->max_d = a.d;
          break;
      }
    }
    // A bucket the clock has moved past takes no more calls, so it is written now. Held to the
    // end instead, a run that is killed loses everything it aggregated.
    while (!buckets_.empty() && buckets_.begin()->first < bucket) {
      const auto closed = buckets_.begin();
      emit_bucket(closed->first, closed->second);
      buckets_.erase(closed);
    }
  }

  std::uint64_t next_id() { return id_.fetch_add(1); }
  const std::string& hhash() const { return hhash_; }
  const datacrumbs::timesync::Reader& clock() const { return reader_; }

 private:
  /// One name's totals inside one interval. Nanoseconds, not the microseconds a reader's `dur`
  /// uses: a call under a microsecond floors to zero there, and a minimum of zero says nothing.
  /// What makes one series: the same call, in the same role, on the same stack. Ordered so the
  /// bucket is a std::map and the records come out grouped.
  struct Key {
    // name is owned because a caller may build it in a buffer it then reuses. cat and type are
    // not: every caller passes a literal, so copying them per call bought nothing and cost two
    // string constructions on the path aggregation exists to make cheap.
    std::string name;
    const char* cat;
    const char* type;
    // Fixed array, no allocation: a call site opts a categorical arg in explicitly, so the count
    // is always small and known at the call. Compared by strcmp on key then value, not by
    // pointer: two call sites may pass distinct literals with equal content (e.g. "global"), and
    // those must land in the same bucket. This differs from NumTally's per-call pointer compare,
    // which is a hot linear scan inside one Tally; Key comparison runs on the bucket map path,
    // which already strcmp's cat and type, so this is consistent with what is there.
    CatArg cats[kMaxCatArgs];
    int ncats;
    bool operator<(const Key& o) const {
      if (const int c = name.compare(o.name)) return c < 0;
      if (const int c = std::strcmp(cat, o.cat)) return c < 0;
      if (const int c = std::strcmp(type, o.type)) return c < 0;
      if (ncats != o.ncats) return ncats < o.ncats;
      for (int i = 0; i < ncats; ++i) {
        if (const int c = std::strcmp(cats[i].key, o.cats[i].key)) return c < 0;
        if (const int c = std::strcmp(cats[i].value, o.cats[i].value)) return c < 0;
      }
      return false;
    }
  };

  /// One numeric arg's totals inside one Tally. Three separate int/uint/double fields rather than
  /// a union: kind picks which set is live, and a plain field avoids re-deriving a sum through a
  /// type it was never in (a u64 losing precision through double, or a double truncating to int).
  struct NumTally {
    const char* key = nullptr;
    NumKind kind = NumKind::INT;
    std::uint64_t count = 0;
    long long sum_i = 0;
    long long min_i = std::numeric_limits<long long>::max();
    long long max_i = std::numeric_limits<long long>::min();
    unsigned long long sum_u = 0;
    unsigned long long min_u = std::numeric_limits<unsigned long long>::max();
    unsigned long long max_u = 0;
    double sum_d = 0;
    double min_d = std::numeric_limits<double>::infinity();
    double max_d = -std::numeric_limits<double>::infinity();
    // Same reason duration carries sum_sq_ns2: without it a reader cannot recompute a deviation
    // or merge two windows. INT and UINT both accumulate in unsigned long long, the widest
    // natural type for either: a square is never negative, so int gains nothing from staying
    // signed, and casting through double would lose precision a 64-bit sum need not lose.
    unsigned long long sum_sq_i = 0;
    unsigned long long sum_sq_u = 0;
    double sum_sq_d = 0;
  };

  struct Tally {
    std::uint64_t count = 0;
    std::uint64_t sum_ns = 0;
    unsigned long long sum_sq_ns2 = 0;
    std::uint64_t min_ns = std::numeric_limits<std::uint64_t>::max();
    std::uint64_t max_ns = 0;
    NumTally nums[kMaxAggArgs];
    int nnums = 0;
  };

  /// Appends a formatted fragment at buf[pos], never past cap, returning the new pos. A named
  /// helper carrying the printf format attribute, not a local lambda: a lambda's call operator has
  /// no format attribute, so -Wformat=2 cannot check a fmt/args mismatch through one, and that
  /// check is exactly what a past bug here cost us.
  static std::size_t append_fmt(char* buf, std::size_t cap, std::size_t pos, const char* fmt, ...)
      __attribute__((format(printf, 4, 5))) {
    if (pos >= cap) return pos;
    va_list ap;
    va_start(ap, fmt);
    const int m = std::vsnprintf(buf + pos, cap - pos, fmt, ap);
    va_end(ap);
    if (m <= 0) return pos;
    const std::size_t room = cap - pos;
    return pos + (static_cast<std::size_t>(m) < room ? static_cast<std::size_t>(m) : room - 1);
  }

  /// Writes one AGGREGATED record (ph 3) per name in a closed bucket.
  ///
  /// Keys follow dftracer's aggregation convention: dft_cnt for the count and <key>_sum/_min/_max
  /// for a numeric key, here the duration. Values are in the unit the trace declares in its
  /// time_metric record, microseconds, so nothing has to carry a unit in its name. dur_sum_sq is
  /// ours and dftracer has no equivalent: without it a reader cannot recover the deviation or
  /// merge two windows. A numeric arg beyond duration follows the same convention, its own
  /// <key>_sum/_min/_max/_sum_sq; dft_cnt already covers what a string-valued arg would have
  /// added.
  ///
  /// No id: an aggregate is a series point rather than one event, and dftracer's aggregated
  /// records carry none either. Timestamped at the bucket's own start rather than at the moment of
  /// writing, so the record sits where the work happened.
  ///
  /// Caller holds tally_mu_.
  void emit_bucket(std::uint64_t bucket, const std::map<Key, Tally>& names) {
    const std::uint64_t ts_us =
        reader_.remap(bucket * DATACRUMBS_TIME_INTERVAL_NS) / DATACRUMBS_TIME_DIVISOR_NS;
    for (const auto& [key, t] : names) {
      // Base fields plus up to kMaxAggArgs "<key>_sum/_min/_max/_sum_sq" quadruples; a key itself
      // has no fixed bound (it is whatever the DC_A_INT macro's argument is named), so this is
      // generous rather than exact. append_fmt() never writes past the buffer regardless.
      char line[1024 + kMaxAggArgs * 400];
      std::size_t pos = append_fmt(
          line, sizeof(line), 0,
          R"({"name":"%s","cat":"%s","type":"%s","pid":%ld,"tid":%d,"ts":%llu,"ph":3,)"
          R"("args":{"hhash":"%s","dft_cnt":%llu,"dur_sum":%llu,"dur_min":%llu,"dur_max":%llu,)"
          R"("dur_sum_sq":%llu)",
          key.name.c_str(), key.cat, key.type, static_cast<long>(self_pid()),
          static_cast<int>(self_tid()), static_cast<unsigned long long>(ts_us),
          hhash_.c_str(), static_cast<unsigned long long>(t.count),
          static_cast<unsigned long long>(t.sum_ns / DATACRUMBS_TIME_DIVISOR_NS),
          static_cast<unsigned long long>(t.count != 0 ? t.min_ns / DATACRUMBS_TIME_DIVISOR_NS : 0),
          static_cast<unsigned long long>(t.max_ns / DATACRUMBS_TIME_DIVISOR_NS),
          static_cast<unsigned long long>(
              t.sum_sq_ns2 / (DATACRUMBS_TIME_DIVISOR_NS * DATACRUMBS_TIME_DIVISOR_NS)));
      // Values are known clean identifiers from a call site's own literal or static table (e.g.
      // "global"/"software"), never user data, so no JSON escaping machinery is needed here.
      for (int i = 0; i < key.ncats; ++i)
        pos = append_fmt(line, sizeof(line), pos, R"(,"%s":"%s")", key.cats[i].key,
                         key.cats[i].value);
      for (int i = 0; i < t.nnums; ++i) {
        const NumTally& nt = t.nums[i];
        switch (nt.kind) {
          case NumKind::INT:
            pos =
                append_fmt(line, sizeof(line), pos,
                           R"(,"%s_sum":%lld,"%s_min":%lld,"%s_max":%lld,"%s_sum_sq":%llu)", nt.key,
                           nt.sum_i, nt.key, nt.min_i, nt.key, nt.max_i, nt.key, nt.sum_sq_i);
            break;
          case NumKind::UINT:
            pos =
                append_fmt(line, sizeof(line), pos,
                           R"(,"%s_sum":%llu,"%s_min":%llu,"%s_max":%llu,"%s_sum_sq":%llu)", nt.key,
                           nt.sum_u, nt.key, nt.min_u, nt.key, nt.max_u, nt.key, nt.sum_sq_u);
            break;
          case NumKind::REAL:
            // %.17g round-trips a double exactly and is never an integer specifier over a
            // double, the mismatch -Wformat=2 exists to catch.
            pos = append_fmt(line, sizeof(line), pos,
                             R"(,"%s_sum":%.17g,"%s_min":%.17g,"%s_max":%.17g,"%s_sum_sq":%.17g)",
                             nt.key, nt.sum_d, nt.key, nt.min_d, nt.key, nt.max_d, nt.key,
                             nt.sum_sq_d);
            break;
        }
      }
      pos = append_fmt(line, sizeof(line), pos, "}}\n");
      if (pos > 0) write(line, pos);
    }
  }

  /// Writes whatever buckets are still open, on the way down.
  void flush_buckets() {
    std::lock_guard<std::mutex> lock(tally_mu_);
    for (const auto& [bucket, names] : buckets_) emit_bucket(bucket, names);
    buckets_.clear();
  }

  static constexpr std::size_t kFlushBytes = 256 * 1024;

  // Level 2 over zlib's default 6: 1.10 vs 2.66 us per record, for output 22 percent larger.
  // The flush dominated the ~4 us per-record capture cost; everything else together is 0.7 us.
  static int compression_level() { return ConfigurationManager::runtime().pfw_level; }

  void flush_locked() {
    if (buf_.empty() || file_ == nullptr) return;
    if (!async_ || forked()) {
      // No worker to hand this to, so this compresses and writes on the application's thread;
      // mark it as the worker is marked. Once per full buffer, not per record.
      IoThreadMark marked;
      IoBypass bypass;
      emit(buf_);
      buf_.clear();
      return;
    }
    std::unique_lock<std::mutex> lock(qmu_);
    // Backpressure: an app that outruns the compressor must wait rather than grow the queue without
    // bound. Blocking here is the point; dropping records would silently corrupt the trace.
    qcv_.wait(lock, [this] { return qbytes_ < kMaxQueueBytes || stop_; });
    qbytes_ += buf_.size();
    queue_.push_back(std::move(buf_));
    buf_.clear();
    lock.unlock();
    qcv_.notify_all();
  }

  /// One worker keeps members in submission order, which the concatenated gzip stream requires.
  void drain() {
    for (;;) {
      std::unique_lock<std::mutex> lock(qmu_);
      qcv_.wait(lock, [this] { return !queue_.empty() || stop_; });
      if (queue_.empty()) {
        if (stop_) return;
        continue;
      }
      std::string block = std::move(queue_.front());
      queue_.pop_front();
      lock.unlock();

      emit(block);

      lock.lock();
      qbytes_ -= block.size();
      lock.unlock();
      qcv_.notify_all();
    }
  }

  void emit(const std::string& block) {
    static const int level = compression_level();
    const std::vector<uint8_t> member = datacrumbs::pfw::gzip_block(block, level);
    IoBypass bypass;  // covers the synchronous path, where there is no worker thread
    std::fwrite(member.data(), 1, member.size(), file_);
    std::fflush(file_);
  }

  /// Append this sink's absolute path to the per-run index named by DATACRUMBS_SINK_INDEX, so the
  /// collector reads where traces actually are instead of guessing. Without this the writer picks
  /// the path and the reader searches for it, and a sink pointed somewhere the search does not
  /// reach is collected as silence rather than an error. One O_APPEND write under the pipe-buffer
  /// size, so concurrent processes interleave whole lines. Best-effort: a run with no index set
  /// still writes its trace.
  static void declare(const char* path) {
    const std::string& index = ConfigurationManager::runtime().sink_index;
    if (index.empty()) return;
    const char* idx = index.c_str();
    char abs[PATH_MAX];
    const char* full = realpath(path, abs) != nullptr ? abs : path;
    char line[PATH_MAX + 2];
    const int n = std::snprintf(line, sizeof(line), "%s\n", full);
    if (n <= 0) return;
    const int fd = ::open(idx, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;
    const ssize_t w = ::write(fd, line, static_cast<std::size_t>(n));
    (void)w;
    ::close(fd);
  }

  /// One LV record per loaded shared object: its path and its GNU build id.
  ///
  /// Opcode and flag names are hardcoded from the headers, so a trace is only interpretable against
  /// the library it was taken from. Recording the build id makes that checkable rather than assumed
  /// when a DOCA or rdma-core upgrade renumbers something.
  void declare_libraries() {
    dl_iterate_phdr(
        [](struct dl_phdr_info* info, std::size_t, void* self) {
          if (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0') return 0;
          char id[41] = "unknown";
          for (int i = 0; i < info->dlpi_phnum; ++i) {
            const ElfW(Phdr)& ph = info->dlpi_phdr[i];
            if (ph.p_type != PT_NOTE) continue;
            const auto* p = reinterpret_cast<const unsigned char*>(info->dlpi_addr + ph.p_vaddr);
            const auto* end = p + ph.p_memsz;
            while (p + sizeof(ElfW(Nhdr)) <= end) {
              const auto* nh = reinterpret_cast<const ElfW(Nhdr)*>(p);
              const unsigned char* desc = p + sizeof(ElfW(Nhdr)) + ((nh->n_namesz + 3) & ~3u);
              if (nh->n_type == NT_GNU_BUILD_ID && nh->n_descsz > 0) {
                const unsigned n = nh->n_descsz > 20 ? 20 : nh->n_descsz;
                for (unsigned k = 0; k < n; ++k) std::snprintf(id + k * 2, 3, "%02x", desc[k]);
                break;
              }
              p = desc + ((nh->n_descsz + 3) & ~3u);
            }
            if (id[0] != 'u') break;
          }
          char line[1400];
          const int m = std::snprintf(
              line, sizeof(line),
              R"({"name":"LV","cat":"dftracer","type":"metadata","ph":4,"args":{"hhash":"%s","name":"%s","value":"%s"}})"
              "\n",
              static_cast<PfwSink*>(self)->hhash_.c_str(), info->dlpi_name, id);
          if (m > 0) static_cast<PfwSink*>(self)->buf_.append(line, static_cast<std::size_t>(m));
          return 0;
        },
        this);
  }

  static bool& forked() {
    static bool v = false;
    return v;
  }

  static bool async_enabled() { return ConfigurationManager::runtime().pfw_async; }

  static constexpr std::size_t kMaxQueueBytes = 16 * 1024 * 1024;

  const std::string tag_;
  std::mutex tally_mu_;
  std::map<std::uint64_t, std::map<Key, Tally>> buckets_;
  datacrumbs::timesync::Reader reader_;
  std::string hhash_;
  std::mutex mu_;
  std::string buf_;
  std::FILE* file_ = nullptr;
  std::atomic<std::uint64_t> id_{0};

  const bool async_ = async_enabled();
  std::thread worker_;
  std::mutex qmu_;
  std::condition_variable qcv_;
  std::deque<std::string> queue_;
  std::size_t qbytes_ = 0;
  bool stop_ = false;
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_CLIENT_PFW_SINK_H
