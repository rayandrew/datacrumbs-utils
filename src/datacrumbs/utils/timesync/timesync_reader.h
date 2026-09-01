#ifndef DATACRUMBS_UTILS_TIMESYNC_READER_H
#define DATACRUMBS_UTILS_TIMESYNC_READER_H

#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/common/dc_timesync_snapshot.h>
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

  // Remap a NIC hardware timestamp taken on PHC `phc` onto the global epoch: cross to the synced PHC
  // via that clock's delta, then apply the fit. Returns 0 when the PHC is unknown or there is no
  // valid fit - callers must NOT treat 0 as an aligned time.
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

  // Remap an HCA free-running raw timestamp (e.g. a DOCA fabric CQE ts) onto the global epoch via the
  // daemon's published raw->synced-PHC fit. Drift-free (the fit's skew absorbs the HCA<->PHC servo),
  // so no local anchor is needed. Returns 0 when no raw fit is published or no valid fit - callers
  // must NOT treat 0 as an aligned time.
  unsigned long long remap_raw(unsigned long long raw_ns) const {
    dc_timesync_snapshot s;
    if (!read(&s) || !s.valid || !s.raw_valid) return 0;
    const long long drift = static_cast<long long>(static_cast<__int128>(s.raw_skew_ppb) *
                                                   (static_cast<long long>(raw_ns) - s.raw_anchor_ns) /
                                                   1000000000LL);
    return apply_fit(s, static_cast<long long>(raw_ns) + s.raw_to_synced_ns + drift);
  }

  // Fit of the DPA clock onto the synced PHC.
  //
  // Unlike the HCA raw clock, this cannot be published by the daemon: sampling the DPA clock costs
  // a kernel launch, about 18 ms even with the launch call bracketed rather than the process, and
  // needs a DOCA DPA context the daemon has no reason to hold. So the fit is owned by whoever
  // launches kernels and handed in here.
  //
  // A fit rather than a fixed offset because the DPA clock was measured drifting **-6.21 ppm**
  // against the host, which is 22.4 ms per hour and 3.5x the HCA's -1.79 ppm. The previously
  // recorded "stable ~3.50 s offset, one anchor per boot" is wrong for any trace beyond a few
  // minutes.
  struct DpaFit {
    unsigned long long anchor_dpa_us = 0;  // DPA clock at the anchor
    long long to_synced_ns = 0;            // synced-PHC ns minus anchor, at the anchor
    long long skew_ppb = 0;                // DPA rate error against the synced PHC
    bool valid = false;
  };

  // Remap a DPA in-kernel timestamp onto the global epoch. `dpa_us` is MICROSECONDS since chip
  // reset, which is what __dpa_thread_time() returns; every other clock here is nanoseconds, and
  // mixing them is the obvious way to get this wrong. Returns 0 when there is no valid fit -
  // callers must NOT treat 0 as an aligned time.
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
    const long long drift = static_cast<long long>(
        static_cast<__int128>(s.skew_ppb) * (synced - s.anchor_phc_ns) / 1000000000LL);
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
