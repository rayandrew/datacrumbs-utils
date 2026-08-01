// Plugin: remap each event's CLOCK_MONOTONIC ts onto the cross-node global timeline published by
// the dc_timesync daemon, so traces from different nodes share one epoch. No-op (ts unchanged) when
// no snapshot is mapped or the fit is not yet valid. Loaded via DATACRUMBS_PLUGINS.

#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

namespace {

const dc_timesync_snapshot* g_snapshot = nullptr;

bool map_snapshot() {
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
  g_snapshot = s;
  return true;
}

// Seqlock read: retry while a write is in progress (odd seq) or seq moved under us.
bool read_snapshot(dc_timesync_snapshot* out) {
  const dc_timesync_snapshot* s = g_snapshot;
  if (s == nullptr) return false;
  for (;;) {
    const uint32_t seq1 = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
    if (seq1 & 1u) continue;
    std::memcpy(out, s, sizeof(*out));
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&s->seq, __ATOMIC_ACQUIRE) == seq1) return true;
  }
}

unsigned long long remap_mono_to_global(unsigned long long t_mono) {
  dc_timesync_snapshot s;
  if (!read_snapshot(&s) || !s.valid) return t_mono;
  const long long t_phc = static_cast<long long>(t_mono) + s.bridge_mono_to_phc_ns;
  const long long drift =
      static_cast<long long>(static_cast<__int128>(s.skew_ppb) * (t_phc - s.anchor_phc_ns) /
                             1000000000LL);
  const long long t_ref = t_phc + s.offset_ns + drift;
  return t_ref < 0 ? 0 : static_cast<unsigned long long>(t_ref);
}

}  // namespace

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  if (!map_snapshot()) {
    DC_LOG_WARN("timesync plugin: no valid snapshot; events stay on CLOCK_MONOTONIC");
  }
  api->register_event_enricher(
      [](datacrumbs::EventWithId* e) { e->ts = remap_mono_to_global(e->ts); });
  return true;
}
