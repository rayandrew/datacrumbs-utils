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
    const long long drift = static_cast<long long>(
        static_cast<__int128>(s.skew_ppb) * (t_phc - s.anchor_phc_ns) / 1000000000LL);
    const long long t_ref = t_phc + s.offset_ns + drift;
    return t_ref < 0 ? 0 : static_cast<unsigned long long>(t_ref);
  }

 private:
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
