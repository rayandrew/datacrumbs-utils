// Plugin: remap each event's CLOCK_MONOTONIC ts onto the cross-node global timeline published by
// the dc_timesync daemon, so traces from different nodes share one epoch. No-op (ts unchanged) when
// no snapshot is mapped or the fit is not yet valid. Loaded via DATACRUMBS_PLUGINS.

#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/utils/timesync/timesync_reader.h>

namespace {
datacrumbs::timesync::Reader g_reader;
}  // namespace

extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api) {
  if (api == nullptr || api->abi_version != datacrumbs::PluginApi::kAbiVersion) return false;
  if (!g_reader.map()) {
    DC_LOG_WARN("timesync plugin: no valid snapshot; events stay on CLOCK_MONOTONIC");
  }
  api->register_event_enricher([](datacrumbs::EventWithId* e) { e->ts = g_reader.remap(e->ts); });
  return true;
}
