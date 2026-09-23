#ifndef DATACRUMBS_UTILS_TIMESYNC_READER_H
#define DATACRUMBS_UTILS_TIMESYNC_READER_H

#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/timesync/timesync_raw_convert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

// Read-only view of the dc_timesync snapshot, shared by consumers that put events on the global
// cross-node timeline (the server timesync plugin, the interposition client).

using datacrumbs::ConfigurationManager;

namespace datacrumbs::timesync {

class Reader {
 public:
  /// Map the snapshot, from the configured path or the compiled-in default. False if it is absent
  /// or was written by another build.
  bool map() {
    const std::string& configured = ConfigurationManager::runtime().timesync_snapshot;
    const char* path = configured.empty() ? DC_TIMESYNC_DEFAULT_PATH : configured.c_str();
    const int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    void* p = mmap(nullptr, sizeof(dc_timesync_snapshot), PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return false;
    auto* s = static_cast<const dc_timesync_snapshot*>(p);
    if (s->magic != DC_TIMESYNC_MAGIC) {
      munmap(p, sizeof(dc_timesync_snapshot));
      return false;
    }
    snapshot_ = s;
    return true;
  }

  // Remap a CLOCK_MONOTONIC ns onto the global epoch; returns t_mono unchanged when unmapped or the
  // fit is not yet valid.
  unsigned long long remap(unsigned long long t_mono) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.valid) return t_mono;
    const long long t_phc = static_cast<long long>(t_mono) + s.bridge_mono_to_phc_ns;
    return apply_fit(s, t_phc);
  }

  // Remap a NIC hardware timestamp taken on PHC `phc` onto the global epoch. Crosses to the synced
  // PHC via that clock's delta, then applies the fit. Returns 0 when the PHC is unknown or there
  // is no valid fit. Callers must NOT treat 0 as an aligned time.
  unsigned long long remap_hw(unsigned long long hw_ns, int phc) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.valid) return 0;
    long long delta = 0;
    bool found = false;
    for (uint32_t i = 0; i < s.n_clocks && i < DC_TIMESYNC_MAX_CLOCKS; ++i) {
      if (s.clocks[i].valid && s.clocks[i].phc_index == phc) {
        delta = s.clocks[i].delta_to_synced_ns;
        found = true;
        break;
      }
    }
    if (!found) return 0;
    return apply_fit(s, static_cast<long long>(hw_ns) + delta);
  }

  // Remap an HCA free-running raw timestamp, for example a DOCA/ibverbs CQE hw ts, onto the global
  // epoch. Converts raw device cycles to nanoseconds using the daemon's snapshotted clock_info, not
  // an assumed 1 cycle == 1 ns, then applies the published raw->synced-PHC fit. Returns 0 when no
  // raw fit or clock_info snapshot is published. Callers must NOT treat 0 as an aligned time.
  unsigned long long remap_raw(unsigned long long raw_cycles) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.valid || !s.raw_valid || !s.raw_clock_info_valid) return 0;
    const unsigned long long raw_ns = raw_ts_to_ns(s, raw_cycles);
    const long long drift =
        static_cast<long long>(static_cast<__int128>(s.raw_skew_ppb) *
                               (static_cast<long long>(raw_ns) - s.raw_anchor_ns) / 1000000000LL);
    return apply_fit(s, static_cast<long long>(raw_ns) + s.raw_to_synced_ns + drift);
  }

  // The clock_info snapshot currently backing remap_raw, for the plugin that audits it into the
  // trace. False when the daemon has not published one yet.
  struct RawClockInfo {
    uint64_t nsec = 0;
    uint64_t last_cycles = 0;
    uint64_t frac = 0;
    uint32_t mult = 0;
    uint32_t shift = 0;
    uint64_t mask = 0;
    uint64_t updated_mono_ns = 0;
  };
  bool raw_clock_info(RawClockInfo* out) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.raw_clock_info_valid) return false;
    *out = RawClockInfo{s.raw_clock_info_nsec,           s.raw_clock_info_last_cycles,
                        s.raw_clock_info_frac,           s.raw_clock_info_mult,
                        s.raw_clock_info_shift,          s.raw_clock_info_mask,
                        s.raw_clock_info_updated_mono_ns};
    return true;
  }

  // The fit remap() applies, for the record that lets a reader undo it. False until it is valid.
  struct MonoFit {
    int64_t bridge_mono_to_phc_ns = 0;
    int64_t anchor_phc_ns = 0;
    int64_t offset_ns = 0;
    int64_t skew_ppb = 0;
    uint32_t self_id = 0;
    uint32_t ref_id = 0;
  };
  bool mono_fit(MonoFit* out) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.valid) return false;
    *out = MonoFit{
        s.bridge_mono_to_phc_ns, s.anchor_phc_ns, s.offset_ns, s.skew_ppb, s.self_id, s.ref_id};
    return true;
  }

  // Fit of the DPA clock onto the synced PHC. Unlike the HCA raw clock, the daemon cannot publish
  // this itself: sampling the DPA clock needs a kernel launch and a live DOCA DPA context, both too
  // costly to do on every publish cycle. The fit is owned by whoever launches kernels and passed in.
  // It carries a skew term, not a fixed offset, because the DPA clock drifts against the host at a
  // rate well above the HCA's own drift.
  struct DpaFit {
    unsigned long long anchor_dpa_us = 0;  // DPA clock at the anchor
    long long to_synced_ns = 0;            // synced-PHC ns minus anchor, at the anchor
    long long skew_ppb = 0;                // DPA rate error against the synced PHC
    bool valid = false;
  };

  // Remap a DPA in-kernel timestamp onto the global epoch. `dpa_us` is MICROSECONDS since chip
  // reset, as returned by __dpa_thread_time(). Every other clock here is nanoseconds. Returns 0
  // when there is no valid fit. Callers must NOT treat 0 as an aligned time.
  unsigned long long remap_dpa(unsigned long long dpa_us, const DpaFit& fit) const {
    dc_timesync_snapshot s;
    if (!fit.valid || !read(&s) || !s.valid) return 0;
    const long long dpa_ns = static_cast<long long>(dpa_us) * 1000;
    const long long since_anchor = dpa_ns - static_cast<long long>(fit.anchor_dpa_us) * 1000;
    const long long drift =
        static_cast<long long>(static_cast<__int128>(fit.skew_ppb) * since_anchor / 1000000000LL);
    return apply_fit(s, dpa_ns + fit.to_synced_ns + drift);
  }

 private:
  // offset + skew*(t - anchor) about the synced-PHC value t.
  static unsigned long long apply_fit(const dc_timesync_snapshot& s, long long synced) {
    const long long drift = static_cast<long long>(static_cast<__int128>(s.skew_ppb) *
                                                   (synced - s.anchor_phc_ns) / 1000000000LL);
    const long long t_ref = synced + s.offset_ns + drift;
    return t_ref < 0 ? 0 : static_cast<unsigned long long>(t_ref);
  }

  // Seqlock read: retry while a write is in progress (odd seq) or seq moved under us.
  bool read(dc_timesync_snapshot* out) const {
    const dc_timesync_snapshot* s = snapshot_;
    if (s == nullptr) return false;
    for (;;) {
      const uint32_t seq1 = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
      if (seq1 & 1u) continue;
      std::memcpy(out, s, sizeof(*out));
      __atomic_thread_fence(__ATOMIC_ACQUIRE);
      if (__atomic_load_n(&s->seq, __ATOMIC_ACQUIRE) == seq1) return true;
    }
  }

  const dc_timesync_snapshot* snapshot_ = nullptr;
};

}  // namespace datacrumbs::timesync

#endif  // DATACRUMBS_UTILS_TIMESYNC_READER_H
