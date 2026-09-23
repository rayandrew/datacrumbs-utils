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

#include <algorithm>
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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace datacrumbs::client {

/// This process's id, cached. getpid is a syscall, so caching it avoids that cost on every record.
/// The interposer runs on the application's own threads, where no server-side gate can tell its
/// calls apart from the application's own calls.
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

/// A record's args can carry more than duration. dftracer aggregates numeric args as
/// <key>_sum/_min/_max and only counts string-valued ones, so a string never reaches here.
/// kind is stable per key: the same call site always passes the same C++ type for the same name.
/// INT, UINT and REAL are tallied by an aggregate. The rest are record-only: the writer formats
/// them, so the calling thread never runs a decoder or snprintf.
enum class NumKind : unsigned char { INT, UINT, REAL, PTR, ENUM, FLAGS, FIELD, CMD, STR };

/// One captured arg, keyed by its name. key is a string literal from the call site, not copied:
/// the same site produces the same pointer on every call, which is what lets the sink find a
/// tally's slot by pointer. ENUM, FIELD and CMD carry the decoder, FLAGS the flag formatter; STR is
/// the one kind copied at capture, since the source may not outlive the call.
struct NumArg {
  const char* key;
  NumKind kind;
  union {
    long long i;
    unsigned long long u;
    double d;
    const void* p;
    char s[32];
  };
  union {
    const char* (*enum_fn)(long long);
    int (*flags_fn)(long long, char*, int);
  };
};

/// Capacity for distinct numeric-arg keys tallied per (name, cat, type, interval) bucket entry.
/// A call presenting more is not an error: the first kMaxAggArgs keys are kept, the rest dropped.
inline constexpr int kMaxAggArgs = 12;

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

/// A call site that aggregates, resolved once per site by PfwSink::site(). Its index addresses the
/// per-thread tally slots, so the hot path never hashes or compares a name.
struct AggSite {
  std::string name;
  const char* cat;
  const char* type;
  const char* tool;  // "tool" arg on a record, or nullptr
  unsigned index;
};

/// Capacity for distinct aggregating call sites per sink. The wrap list is ~2100 symbols.
inline constexpr unsigned kMaxAggSites = 8192;

}  // namespace datacrumbs::client

#include <datacrumbs/utils/common/background.h>
#include <datacrumbs/utils/common/compress_pool.h>
#include <datacrumbs/utils/common/tracer_thread.h>

namespace datacrumbs::client {

/**
 * Per-process .pfw.gz sink for records a client emits from userspace. Thread-safe; remap()
 * puts timestamps on the global epoch. A record is not durable until flush() or 256 KB.
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

    // ts and dur are microseconds; this record states that unit so a future change cannot
    // silently rescale a whole trace. The *_ns args on an aggregated record name their own unit.
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
      // A forked child inherits the queue but not the worker, so it would enqueue into a drain
      // that never runs and block forever once the queue filled. Fall back to sync there.
      pthread_atfork(nullptr, nullptr, [] { forked() = true; });
      task_ = Background::get().add_write([this] { return drain_once(); });
      sweep_task_ = Background::get().add_write([this] { return sweep_tallies(false); });
      drain_task_ = Background::get().add_write([this] { return drain_records(false); });
      CompressPool::get().start();
    }
    flush_locked();  // HH as its own member, matching the server writer's layout
  }

  ~PfwSink() {
    if (async_) {
      Background::get().remove(drain_task_);
      Background::get().remove(sweep_task_);
      drain_records(true);
      sweep_tallies(true);
      write_dropped();
    }
    flush_buckets();
    if (async_) {
      Background::get().remove(task_);  // no call in progress after this
      IoBypass bypass;
      while (drain_once()) {
      }
      {
        std::lock_guard<std::mutex> lock(qmu_);
        stop_ = true;
      }
    }
    flush();
    if (file_ != nullptr) {
      wait_members();
      std::fclose(file_);
    }
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

  /// Aggregates one call into the same (name, interval) buckets the kernel path uses, so a
  /// reader cannot tell where a name was aggregated. @p cat and @p type must outlive the sink:
  /// they are stored, not copied, and every caller passes a literal. @p name is copied.
  void aggregate(const char* name, const char* cat, const char* type, std::uint64_t start_ns,
                 std::uint64_t dur_ns, const NumArg* args = nullptr, int nargs = 0,
                 const CatArg* cats = nullptr, int ncats = 0) {
    const std::uint64_t bucket = start_ns / DATACRUMBS_TIME_INTERVAL_NS;
    Key key{name, cat, type, {}, 0};
    for (int i = 0; i < ncats && i < kMaxCatArgs; ++i) key.cats[key.ncats++] = cats[i];
    std::lock_guard<std::mutex> lock(tally_mu_);
    add(buckets_[bucket][key], dur_ns, args, nargs);
    close_buckets_before(bucket);
  }

  /// The call site handle for tally(). nullptr once the sink holds kMaxAggSites, and the caller
  /// falls back to aggregate().
  AggSite* site(const char* name, const char* cat, const char* type, const char* tool = nullptr) {
    std::lock_guard<std::mutex> lock(site_mu_);
    if (sites_.size() >= kMaxAggSites) return nullptr;
    sites_.push_back(std::make_unique<AggSite>(
        AggSite{name, cat, type, tool, static_cast<unsigned>(sites_.size())}));
    return sites_.back().get();
  }

  /// site() for a caller that has the name as a literal but no per-site static: keyed by the
  /// literal's address, so a hit is one probe of a small table and no string compare.
  AggSite* site_cached(const char* name, const char* cat, const char* type,
                       const char* tool = nullptr) {
    const std::size_t h = (reinterpret_cast<std::uintptr_t>(name) >> 3) & (kSiteCache - 1);
    for (std::size_t k = 0; k < kSiteCache; ++k) {
      const std::size_t idx = (h + k) & (kSiteCache - 1);
      AggSite* st = site_cache_[idx].site.load(std::memory_order_acquire);
      if (st == nullptr) break;
      if (site_cache_[idx].name == name) return st;
    }
    AggSite* st = site(name, cat, type, tool);
    if (st == nullptr) return nullptr;
    std::lock_guard<std::mutex> lock(site_mu_);
    for (std::size_t k = 0; k < kSiteCache; ++k) {
      const std::size_t idx = (h + k) & (kSiteCache - 1);
      if (site_cache_[idx].site.load(std::memory_order_relaxed) == nullptr) {
        site_cache_[idx].name = name;
        site_cache_[idx].site.store(st, std::memory_order_release);
        break;
      }
    }
    return st;
  }

  /// One record, off the calling thread: a fixed-size copy into the thread's ring, formatted and
  /// written by the write worker. A full ring drops the record and counts it; the count is written
  /// as metadata at exit. The synchronous fallback formats here, as the worker would.
  void record(AggSite* site, std::uint64_t t0_ns, std::uint64_t dur_ns, const NumArg* args,
              int nargs) {
    record_ex(site, t0_ns, dur_ns, args, nargs, 1, false);
  }

  /// record() with the record's phase and clock chosen by the caller. @p ph 2 is a point: no dur.
  /// @p global says t0_ns is already on the global axis (a hardware stamp the caller remapped),
  /// so the writer must not remap it again.
  void record_ex(AggSite* site, std::uint64_t t0_ns, std::uint64_t dur_ns, const NumArg* args,
                 int nargs, unsigned char ph, bool global) {
    if (nargs > kMaxAggArgs) nargs = kMaxAggArgs;
    if (!async_ || forked()) {
      RawRecord r{};
      fill(r, site, t0_ns, dur_ns, args, nargs, ph, global);
      char line[kRecordLine];
      const std::size_t n = format_record(line, sizeof(line), r);
      if (n > 0) write(line, n);
      return;
    }
    ThreadTallies* block = thread_block();
    RecordRing* ring = block->ring.load(std::memory_order_acquire);
    if (ring == nullptr) {
      ring = new RecordRing;
      block->ring.store(ring, std::memory_order_release);
    }
    const std::uint64_t head = ring->head.load(std::memory_order_relaxed);
    if (head - ring->tail.load(std::memory_order_acquire) > ring->mask) {
      block->dropped.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    fill(ring->slot[head & ring->mask], site, t0_ns, dur_ns, args, nargs, ph, global);
    ring->head.store(head + 1, std::memory_order_release);
  }

  /// aggregate() without the lock and the two map lookups: the calling thread adds into its own
  /// slot, and the write worker sweeps closed windows into the buckets. Two slots per site, by
  /// window parity, so the sweep normally touches a slot no call is adding to; the compare-exchange
  /// on seq covers the rare overlap. @p end_ns is the call's end, which is now for the caller.
  void tally(AggSite* site, std::uint64_t end_ns, std::uint64_t dur_ns, const NumArg* args,
             int nargs) {
    if (!async_ || forked()) {
      aggregate(site->name.c_str(), site->cat, site->type, end_ns - dur_ns, dur_ns, args, nargs);
      return;
    }
    ThreadTallies* block = thread_block();
    SiteSlots* slots = block->slots[site->index].load(std::memory_order_acquire);
    if (slots == nullptr) {
      slots = new SiteSlots;
      block->slots[site->index].store(slots, std::memory_order_release);
    }
    const std::uint64_t bucket = end_ns / DATACRUMBS_TIME_INTERVAL_NS;
    SiteTally& st = slots->s[bucket & 1];
    lock_slot(st);
    if (st.bucket != bucket) {
      // The sweep is more than a window late; fold the old content the slow way rather than lose
      // it.
      if (st.t.count != 0) {
        std::lock_guard<std::mutex> lock(tally_mu_);
        merge(buckets_[st.bucket][Key{site->name, site->cat, site->type, {}, 0}], st.t);
      }
      st.t = Tally{};
      st.bucket = bucket;
    }
    add(st.t, dur_ns, args, nargs);
    unlock_slot(st);
  }

 private:
  struct Key;
  struct NumTally;
  struct Tally;

  static void add(Tally& t, std::uint64_t dur_ns, const NumArg* args, int nargs) {
    ++t.count;
    t.sum_ns += dur_ns;
    t.sum_sq_ns2 += static_cast<unsigned long long>(dur_ns) * dur_ns;
    if (dur_ns < t.min_ns) t.min_ns = dur_ns;
    if (dur_ns > t.max_ns) t.max_ns = dur_ns;
    for (int i = 0; i < nargs; ++i) {
      const NumArg& a = args[i];
      if (a.kind != NumKind::INT && a.kind != NumKind::UINT && a.kind != NumKind::REAL) continue;
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
  }

  static void merge(Tally& into, const Tally& from) {
    into.count += from.count;
    into.sum_ns += from.sum_ns;
    into.sum_sq_ns2 += from.sum_sq_ns2;
    if (from.min_ns < into.min_ns) into.min_ns = from.min_ns;
    if (from.max_ns > into.max_ns) into.max_ns = from.max_ns;
    for (int i = 0; i < from.nnums; ++i) {
      const NumTally& f = from.nums[i];
      NumTally* nt = nullptr;
      for (int j = 0; j < into.nnums; ++j) {
        if (into.nums[j].key == f.key) {
          nt = &into.nums[j];
          break;
        }
      }
      if (nt == nullptr) {
        if (into.nnums >= kMaxAggArgs) continue;
        into.nums[into.nnums++] = f;
        continue;
      }
      if (nt->kind != f.kind) continue;
      nt->count += f.count;
      nt->sum_i += f.sum_i;
      nt->sum_u += f.sum_u;
      nt->sum_d += f.sum_d;
      nt->sum_sq_i += f.sum_sq_i;
      nt->sum_sq_u += f.sum_sq_u;
      nt->sum_sq_d += f.sum_sq_d;
      if (f.min_i < nt->min_i) nt->min_i = f.min_i;
      if (f.max_i > nt->max_i) nt->max_i = f.max_i;
      if (f.min_u < nt->min_u) nt->min_u = f.min_u;
      if (f.max_u > nt->max_u) nt->max_u = f.max_u;
      if (f.min_d < nt->min_d) nt->min_d = f.min_d;
      if (f.max_d > nt->max_d) nt->max_d = f.max_d;
    }
  }

  /// A bucket the clock has moved past takes no more calls, so it is written now. Held to the end
  /// instead, a run that is killed loses everything it aggregated. Caller holds tally_mu_.
  void close_buckets_before(std::uint64_t bucket) {
    while (!buckets_.empty() && buckets_.begin()->first < bucket) {
      const auto closed = buckets_.begin();
      emit_bucket(closed->first, closed->second);
      buckets_.erase(closed);
    }
  }

  struct SiteTally;
  struct SiteSlots;
  struct ThreadTallies;
  struct RawRecord;
  struct RecordRing;
  static constexpr std::size_t kSiteCache = 1024;
  static constexpr std::size_t kRecordLine = 2048;
  static constexpr std::uint64_t kBatchRecords = 4096;  // about 1 MB of text per gzip member

  static void lock_slot(SiteTally& st) {
    for (;;) {
      std::uint32_t e = st.seq.load(std::memory_order_relaxed) & ~1u;
      if (st.seq.compare_exchange_weak(e, e + 1, std::memory_order_acquire,
                                       std::memory_order_relaxed))
        return;
    }
  }
  static void unlock_slot(SiteTally& st) {
    st.seq.store(st.seq.load(std::memory_order_relaxed) + 1, std::memory_order_release);
  }

  /// This thread's block for this sink, registered with the sink on first use. Never freed: a
  /// thread that exits leaves its last windows for the sweep, and the blocks are one per thread.
  ThreadTallies* thread_block() {
    struct Entry {
      PfwSink* sink;
      ThreadTallies* block;
    };
    thread_local Entry entries[8];
    thread_local int n = 0;
    for (int i = 0; i < n; ++i)
      if (entries[i].sink == this) return entries[i].block;
    auto* block = new ThreadTallies;
    {
      std::lock_guard<std::mutex> lock(site_mu_);
      threads_.push_back(block);
    }
    if (n < 8) entries[n++] = Entry{this, block};
    return block;
  }

  /// Write-worker tick: move every closed window out of the threads' slots into the buckets, then
  /// write the buckets the clock has passed. @p all sweeps the current windows too, on the way
  /// down.
  bool sweep_tallies(bool all) {
    const std::uint64_t now_bucket = datacrumbs::client::mono_ns() / DATACRUMBS_TIME_INTERVAL_NS;
    if (!all && now_bucket == last_swept_) return false;
    last_swept_ = now_bucket;
    std::vector<ThreadTallies*> blocks;
    std::size_t nsites = 0;
    {
      std::lock_guard<std::mutex> lock(site_mu_);
      blocks = threads_;
      nsites = sites_.size();
    }
    bool moved = false;
    for (ThreadTallies* block : blocks) {
      for (std::size_t i = 0; i < nsites; ++i) {
        SiteSlots* slots = block->slots[i].load(std::memory_order_acquire);
        if (slots == nullptr) continue;
        for (SiteTally& st : slots->s) {
          if (st.t.count == 0) continue;  // racy read; a false zero is caught on the next tick
          if (!all && st.bucket + 2 > now_bucket) continue;
          lock_slot(st);
          const std::uint64_t bucket = st.bucket;
          const Tally t = st.t;
          st.t = Tally{};
          unlock_slot(st);
          if (t.count == 0) continue;
          const AggSite& site = *sites_[i];
          std::lock_guard<std::mutex> lock(tally_mu_);
          merge(buckets_[bucket][Key{site.name, site.cat, site.type, {}, 0}], t);
          moved = true;
        }
      }
    }
    std::lock_guard<std::mutex> lock(tally_mu_);
    close_buckets_before(all ? std::numeric_limits<std::uint64_t>::max() : now_bucket - 1);
    return moved;
  }

 public:
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
    // Fixed array, no allocation: a call site opts in explicitly, so the count is always small.
    // Compared by strcmp, not pointer: two call sites may pass distinct literals with equal
    // content (e.g. "global"), and those must land in the same bucket.
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

  /// One thread's tally of one site in one window. seq is even when free; the owner and the sweep
  /// each take it odd with a compare-exchange.
  struct SiteTally {
    std::atomic<std::uint32_t> seq{0};
    std::uint64_t bucket = 0;
    Tally t;
  };
  struct alignas(64) SiteSlots {
    SiteTally s[2];
  };
  /// One recorded call, binary. The writer formats it; the record carries no text but STR args.
  struct RawRecord {
    AggSite* site;
    std::uint64_t t0_ns;
    std::uint64_t dur_ns;
    pid_t tid;
    int nargs;
    unsigned char ph;  // 1 complete, 2 point
    bool global;       // t0_ns already remapped by the caller
    NumArg args[kMaxAggArgs];
  };
  /// Single producer (the owning thread), single consumer (the write worker).
  struct RecordRing {
    alignas(64) std::atomic<std::uint64_t> head{0};
    alignas(64) std::atomic<std::uint64_t> tail{0};
    RawRecord* slot;
    std::uint64_t mask;  // capacity - 1; capacity is the power of two under DATACRUMBS_RING_MB
    RecordRing() {
      const std::uint64_t want =
          (static_cast<std::uint64_t>(ConfigurationManager::runtime().ring_mb) << 20) /
          sizeof(RawRecord);
      std::uint64_t cap = 1024;
      while (cap * 2 <= want) cap *= 2;
      slot = new RawRecord[cap];
      mask = cap - 1;
    }
  };
  /// One thread's slots, one pointer per site, allocated on the thread's first call to the site,
  /// and its record ring, allocated on its first record.
  struct ThreadTallies {
    std::atomic<SiteSlots*> slots[kMaxAggSites];
    std::atomic<RecordRing*> ring{nullptr};
    std::atomic<std::uint64_t> dropped{0};
    ThreadTallies() {
      for (auto& p : slots) p.store(nullptr, std::memory_order_relaxed);
    }
  };

  static void fill(RawRecord& r, AggSite* site, std::uint64_t t0_ns, std::uint64_t dur_ns,
                   const NumArg* args, int nargs, unsigned char ph = 1, bool global = false) {
    r.site = site;
    r.t0_ns = t0_ns;
    r.dur_ns = dur_ns;
    r.tid = self_tid();
    r.nargs = nargs;
    r.ph = ph;
    r.global = global;
    for (int i = 0; i < nargs; ++i) r.args[i] = args[i];
  }

  /// Formats one record into a single output line.
  std::size_t format_record(char* line, std::size_t cap, const RawRecord& r) {
    const AggSite& site = *r.site;
    const std::uint64_t ts = (r.global ? r.t0_ns : reader_.remap(r.t0_ns)) / DATACRUMBS_TIME_DIVISOR_NS;
    std::size_t pos =
        r.ph == 2
            ? append_fmt(
                  line, cap, 0,
                  R"({"id":%llu,"name":"%s","cat":"%s","type":"%s","pid":%ld,"tid":%d,"ts":%llu,"ph":2,"args":{"hhash":"%s")",
                  static_cast<unsigned long long>(next_id()), site.name.c_str(), site.cat,
                  site.type, static_cast<long>(self_pid()), static_cast<int>(r.tid),
                  static_cast<unsigned long long>(ts), hhash_.c_str())
            : append_fmt(
                  line, cap, 0,
                  R"({"id":%llu,"name":"%s","cat":"%s","type":"%s","pid":%ld,"tid":%d,"ts":%llu,"dur":%llu,"ph":1,"args":{"hhash":"%s")",
                  static_cast<unsigned long long>(next_id()), site.name.c_str(), site.cat,
                  site.type, static_cast<long>(self_pid()), static_cast<int>(r.tid),
                  static_cast<unsigned long long>(ts),
                  static_cast<unsigned long long>(r.dur_ns / DATACRUMBS_TIME_DIVISOR_NS),
                  hhash_.c_str());
    for (int i = 0; i < r.nargs; ++i) {
      const NumArg& a = r.args[i];
      switch (a.kind) {
        case NumKind::INT:
          pos = append_fmt(line, cap, pos, R"(,"%s":%lld)", a.key, a.i);
          break;
        case NumKind::UINT:
          pos = append_fmt(line, cap, pos, R"(,"%s":%llu)", a.key, a.u);
          break;
        case NumKind::REAL:
          pos = append_fmt(line, cap, pos, R"(,"%s":%.17g)", a.key, a.d);
          break;
        case NumKind::PTR:
          pos = append_fmt(line, cap, pos, R"(,"%s":"%p")", a.key, a.p);
          break;
        case NumKind::STR:
          pos = append_fmt(line, cap, pos, R"(,"%s":"%s")", a.key, a.s);
          break;
        case NumKind::ENUM: {
          const char* e = a.enum_fn != nullptr ? a.enum_fn(a.i) : nullptr;
          pos = e != nullptr ? append_fmt(line, cap, pos, R"(,"%s":"%s")", a.key, e)
                             : append_fmt(line, cap, pos, R"(,"%s":%lld)", a.key, a.i);
          break;
        }
        case NumKind::FIELD: {
          const char* e = a.enum_fn != nullptr ? a.enum_fn(static_cast<long long>(a.u)) : nullptr;
          pos = e != nullptr ? append_fmt(line, cap, pos, R"(,"%s":"%s")", a.key, e)
                             : append_fmt(line, cap, pos, R"(,"%s":%llu)", a.key, a.u);
          break;
        }
        case NumKind::CMD: {
          const char* e = a.enum_fn != nullptr ? a.enum_fn(a.i) : nullptr;
          pos = e != nullptr ? append_fmt(line, cap, pos, R"(,"cmd":"%s")", e)
                             : append_fmt(line, cap, pos, R"(,"cmd":"0x%llx")",
                                          static_cast<unsigned long long>(a.i));
          break;
        }
        case NumKind::FLAGS: {
          char f[256];
          const int fn =
              a.flags_fn != nullptr ? a.flags_fn(a.i, f, static_cast<int>(sizeof(f))) : 0;
          pos = append_fmt(line, cap, pos, R"(,"%s":"%s")", a.key, fn > 0 ? f : "0");
          pos = append_fmt(line, cap, pos, R"(,"%s_raw":%lld)", a.key, a.i);
          break;
        }
      }
    }
    if (site.tool != nullptr) pos = append_fmt(line, cap, pos, R"(,"tool":"%s")", site.tool);
    pos = append_fmt(line, cap, pos, "}}\n");
    return pos;
  }

  /// Write-worker tick: every thread's ring, in batches of raw records, to the pool, which
  /// formats and compresses them; the worker only copies. @p all takes everything, on the way down.
  bool drain_records(bool all) {
    std::vector<ThreadTallies*> blocks;
    {
      std::lock_guard<std::mutex> lock(site_mu_);
      blocks = threads_;
    }
    bool moved = false;
    for (ThreadTallies* block : blocks) {
      RecordRing* ring = block->ring.load(std::memory_order_acquire);
      if (ring == nullptr) continue;
      std::uint64_t tail = ring->tail.load(std::memory_order_relaxed);
      const std::uint64_t head = ring->head.load(std::memory_order_acquire);
      while (tail != head) {
        const std::uint64_t n = std::min<std::uint64_t>(head - tail, kBatchRecords);
        std::vector<RawRecord> batch(n);
        for (std::uint64_t i = 0; i < n; ++i) batch[i] = ring->slot[(tail + i) & ring->mask];
        tail += n;
        ring->tail.store(tail, std::memory_order_release);  // the slots are free again
        emit_batch(std::move(batch));
        moved = true;
        if (!all) break;
      }
    }
    return moved;
  }

  std::string format_batch(const std::vector<RawRecord>& batch) {
    std::string out;
    out.reserve(batch.size() * 240);
    char line[kRecordLine];
    for (const RawRecord& r : batch) {
      const std::size_t n = format_record(line, sizeof(line), r);
      out.append(line, n);
    }
    return out;
  }

  /// One batch to one gzip member, formatted on the pool when it runs, else here.
  void emit_batch(std::vector<RawRecord> batch) {
    static const int level = compression_level();
    const std::uint64_t seq = next_seq_++;
    {
      std::lock_guard<std::mutex> lk(fmu_);
      ++pending_;
    }
    if (!forked() && CompressPool::get().running()) {
      auto b = std::make_shared<std::vector<RawRecord>>(std::move(batch));
      CompressPool::get().submit(
          [this, b] { return format_batch(*b); }, b->size() * 240, level,
          [this, seq](std::vector<uint8_t> m) { write_member(seq, std::move(m)); });
      return;
    }
    write_member(seq, gzip_member(format_batch(batch), level));
  }

  /// Records the rings dropped, as one metadata line, so a reader can see the trace is short.
  void write_dropped() {
    std::uint64_t dropped = 0;
    {
      std::lock_guard<std::mutex> lock(site_mu_);
      for (ThreadTallies* block : threads_) dropped += block->dropped.load();
    }
    if (dropped == 0) return;
    DC_LOG_WARN("[%s] %llu records dropped: the writer fell behind", tag_.c_str(),
                static_cast<unsigned long long>(dropped));
    char line[256];
    const int n = std::snprintf(
        line, sizeof(line),
        R"({"name":"dropped","cat":"datacrumbs","type":"metadata","ph":4,"args":{"hhash":"%s","name":"dropped","value":"%llu"}})"
        "\n",
        hhash_.c_str(), static_cast<unsigned long long>(dropped));
    if (n > 0) write(line, static_cast<std::size_t>(n));
  }

  /// Appends a formatted fragment at buf[pos], never past cap, returning the new pos. A named
  /// helper, not a local lambda: a lambda's call operator carries no printf format attribute, so
  /// -Wformat=2 cannot check a fmt/args mismatch through one.
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

  /// Writes one AGGREGATED record (ph 3) per name in a closed bucket, following dftracer's
  /// convention: dft_cnt for the count, <key>_sum/_min/_max/_sum_sq per numeric key (duration
  /// and any numeric arg). No id, since an aggregate is a series point, not one event. Caller
  /// holds tally_mu_.
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
          static_cast<int>(self_tid()), static_cast<unsigned long long>(ts_us), hhash_.c_str(),
          static_cast<unsigned long long>(t.count),
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

  // A lower compression level trades a somewhat larger output for much less CPU time than
  // zlib's default level. This keeps compression from dominating the cost of capturing a record.
  static int compression_level() { return ConfigurationManager::runtime().pfw_level; }

  void flush_locked() {
    if (buf_.empty() || file_ == nullptr) return;
    const bool sync = !async_ || forked() || stop_ || Background::stopped();
    // The write worker is a tracer thread and is also the queue's consumer, so it must never wait
    // on the queue: it hands the block to the pool here. With no worker the caller compresses.
    if (sync || g_tracer_thread) {
      IoThreadMark marked;
      emit(std::move(buf_), !sync);
      buf_ = std::string();
      return;
    }
    std::unique_lock<std::mutex> lock(qmu_);
    // Backpressure: an app that outruns the compressor must wait rather than grow the queue without
    // bound. Only metadata comes this way; records go through the rings.
    qcv_.wait(lock, [this] { return qbytes_ < kMaxQueueBytes || stop_; });
    qbytes_ += buf_.size();
    queue_.push_back(std::move(buf_));
    buf_ = std::string();
    lock.unlock();
    qcv_.notify_all();
  }

  /// One worker keeps members in submission order, which the concatenated gzip stream requires.
  /// One block from the queue to the file. The write worker's tick; true when there was one.
  bool drain_once() {
    std::unique_lock<std::mutex> lock(qmu_);
    if (queue_.empty()) return false;
    std::string block = std::move(queue_.front());
    queue_.pop_front();
    lock.unlock();

    const std::size_t n = block.size();
    emit(std::move(block), true);

    lock.lock();
    qbytes_ -= n;
    lock.unlock();
    qcv_.notify_all();
    return true;
  }

  /// One text block to one gzip member, on the pool when it runs, else here. Members carry a
  /// sequence so the file keeps submission order whichever thread finishes first.
  void emit(std::string block, bool pool) {
    static const int level = compression_level();
    const std::uint64_t seq = next_seq_++;
    {
      std::lock_guard<std::mutex> lk(fmu_);
      ++pending_;
    }
    if (pool && !forked() && CompressPool::get().running()) {
      CompressPool::get().submit(std::move(block), level, [this, seq](std::vector<uint8_t> m) {
        write_member(seq, std::move(m));
      });
      return;
    }
    write_member(seq, gzip_member(block, level));
  }

  void write_member(std::uint64_t seq, std::vector<uint8_t> member) {
    std::unique_lock<std::mutex> lk(fmu_);
    stash_[seq] = std::move(member);
    while (!stash_.empty() && stash_.begin()->first == next_write_) {
      const std::vector<uint8_t>& m = stash_.begin()->second;
      IoBypass bypass;  // covers the synchronous path, where there is no worker thread
      std::fwrite(m.data(), 1, m.size(), file_);
      stash_.erase(stash_.begin());
      ++next_write_;
      --pending_;
    }
    lk.unlock();
    fcv_.notify_all();
  }

  /// Every submitted member is in the file. Called before the file closes.
  void wait_members() {
    std::unique_lock<std::mutex> lk(fmu_);
    fcv_.wait(lk, [this] { return pending_ == 0; });
    std::fflush(file_);
  }

  /// Appends this sink's absolute path to the per-run index named by DATACRUMBS_SINK_INDEX, so
  /// the collector reads where traces are instead of guessing. A sink missing from the index is
  /// collected as silence, not an error. One O_APPEND write under the pipe-buffer size, so
  /// concurrent processes interleave whole lines; best-effort, a run with no index still writes.
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

  /// One LV record per loaded shared object: its path and its GNU build id. Opcode and flag names
  /// are hardcoded from the headers, so a trace is only interpretable against the library it was
  /// taken from; the build id makes that checkable when a DOCA or rdma-core upgrade renumbers
  /// something.
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
  std::mutex site_mu_;
  std::vector<std::unique_ptr<AggSite>> sites_;
  std::vector<ThreadTallies*> threads_;
  std::uint64_t last_swept_ = 0;
  std::shared_ptr<Background::Task> sweep_task_;
  std::shared_ptr<Background::Task> drain_task_;
  struct SiteCacheEntry {
    const char* name = nullptr;
    std::atomic<AggSite*> site{nullptr};
  };
  SiteCacheEntry site_cache_[kSiteCache];
  datacrumbs::timesync::Reader reader_;
  std::string hhash_;
  std::mutex mu_;
  std::string buf_;
  std::FILE* file_ = nullptr;
  std::atomic<std::uint64_t> id_{0};

  const bool async_ = async_enabled();
  std::shared_ptr<Background::Task> task_;
  std::mutex qmu_;
  std::condition_variable qcv_;
  std::deque<std::string> queue_;
  std::size_t qbytes_ = 0;
  bool stop_ = false;
  std::mutex fmu_;
  std::condition_variable fcv_;
  std::map<std::uint64_t, std::vector<uint8_t>> stash_;
  std::uint64_t next_seq_ = 0;
  std::uint64_t next_write_ = 0;
  std::uint64_t pending_ = 0;
};

}  // namespace datacrumbs::client

#endif  // DATACRUMBS_UTILS_CLIENT_PFW_SINK_H
