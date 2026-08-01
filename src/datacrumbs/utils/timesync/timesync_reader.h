#ifndef DATACRUMBS_UTILS_TIMESYNC_READER_H
#define DATACRUMBS_UTILS_TIMESYNC_READER_H

#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

// Read-only view of the dc_timesync snapshot, shared by consumers that put events on the global
// cross-node timeline (the server timesync plugin, the interposition client).

namespace datacrumbs::timesync {

class Reader {
 public:
  // Map the snapshot (DC_TIMESYNC_SNAPSHOT or the default path). Returns false if absent/foreign.
  bool map() {
    const char* path = std::getenv("DC_TIMESYNC_SNAPSHOT");
    if (path == nullptr || *path == '\0') path = DC_TIMESYNC_DEFAULT_PATH;
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
