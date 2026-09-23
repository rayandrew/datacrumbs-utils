// Plugin: remap each event's CLOCK_MONOTONIC ts onto the cross-node global timeline published by
// the dc_timesync daemon, so traces from different nodes share one epoch. No-op (ts unchanged) when
// no snapshot is mapped or the fit is not yet valid. Loaded via DATACRUMBS_PLUGINS.
//
// Also audits the daemon's raw HCA clock_info snapshot into the trace on its own cadence
// (DATACRUMBS_TIMESYNC_CLOCK_INFO_INTERVAL_MS, default 60000): remap_raw() converts a raw CQE
// timestamp through this same snapshot live, so recording it lets a reader redo or verify that
// conversion after the fact instead of trusting it happened correctly.

#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>

#include <algorithm>
#include <ctime>

namespace {
datacrumbs::timesync::Reader g_reader;
uint64_t g_clock_info_event_id = 0;
uint64_t g_clock_domain_event_id = 0;

uint64_t mono_ns() {
  timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec) * 1000000000ull + static_cast<uint64_t>(t.tv_nsec);
}

void sample_clock_info(const datacrumbs::PluginEmit& emit) {
  datacrumbs::timesync::Reader::RawClockInfo ci;
  if (!g_reader.raw_clock_info(&ci)) return;
  auto* args = new DataCrumbsArgs();
  (*args)["clock_info.nsec"] = ci.nsec;
  (*args)["clock_info.last_cycles"] = ci.last_cycles;
  (*args)["clock_info.frac"] = ci.frac;
  (*args)["clock_info.mult"] = static_cast<unsigned long long>(ci.mult);
  (*args)["clock_info.shift"] = static_cast<unsigned long long>(ci.shift);
  (*args)["clock_info.mask"] = ci.mask;
  emit(g_clock_info_event_id, mono_ns(), args);
}

/// One record per second with the three clocks a reader may want an event on: the fit remap()
/// applies (so `mono = global - offset - skew * (global - anchor)` undoes it, the "raw" arm), and
/// CLOCK_REALTIME beside CLOCK_MONOTONIC at one instant (the "NTP" arm). The record's own ts is
/// remapped like every other event.
void sample_clock_domain(const datacrumbs::PluginEmit& emit) {
  timespec m, r;
  clock_gettime(CLOCK_MONOTONIC, &m);
  clock_gettime(CLOCK_REALTIME, &r);
  const uint64_t mono = static_cast<uint64_t>(m.tv_sec) * 1000000000ull + m.tv_nsec;
  const uint64_t real = static_cast<uint64_t>(r.tv_sec) * 1000000000ull + r.tv_nsec;
  auto* args = new DataCrumbsArgs();
  (*args)["clock.mono_ns"] = mono;
  (*args)["clock.realtime_ns"] = real;
  datacrumbs::timesync::Reader::MonoFit fit;
  if (g_reader.mono_fit(&fit)) {
    // The writer formats no signed integer. The two epoch-sized values are positive (a PHC
    // reads seconds since 1970) and go as unsigned; the two small signed ones as doubles.
    (*args)["clock.valid"] = 1ull;
    (*args)["clock.bridge_mono_to_phc_ns"] =
        static_cast<unsigned long long>(std::max<int64_t>(0, fit.bridge_mono_to_phc_ns));
    (*args)["clock.anchor_phc_ns"] =
        static_cast<unsigned long long>(std::max<int64_t>(0, fit.anchor_phc_ns));
    (*args)["clock.offset_ns"] = static_cast<double>(fit.offset_ns);
    (*args)["clock.skew_ppb"] = static_cast<double>(fit.skew_ppb);
    (*args)["clock.self_id"] = static_cast<unsigned long long>(fit.self_id);
    (*args)["clock.ref_id"] = static_cast<unsigned long long>(fit.ref_id);
  } else {
    (*args)["clock.valid"] = 0ull;
  }
  emit(g_clock_domain_event_id, mono, args);
}
}  // namespace

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  if (!g_reader.map()) {
    DC_LOG_WARN("timesync plugin: no valid snapshot; events stay on CLOCK_MONOTONIC");
  }
  api->register_event_enricher([](datacrumbs::EventWithId* e) { e->ts = g_reader.remap(e->ts); });
  if (api->register_sampler != nullptr && api->register_event_name != nullptr) {
    g_clock_info_event_id = api->register_event_name("timesync", "clock_info", "metadata");
    const unsigned int interval =
        datacrumbs::ConfigurationManager::runtime().timesync_clock_info_interval_ms;
    api->register_sampler(interval, sample_clock_info);
    g_clock_domain_event_id = api->register_event_name("timesync", "clock_domain", "metadata");
    api->register_sampler(1000, sample_clock_domain);
  }
  return true;
}
