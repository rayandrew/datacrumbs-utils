// SPDX-License-Identifier: MIT

// The settings a preloaded client runs on, kept apart from the rest of the configuration manager.
// The manager's other work reads yaml and json and walks the filesystem; a library loaded into
// somebody else's process should not link all of that to answer "is the engine module on".

#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/common/constants.h>
#include <datacrumbs/utils/common/constants.h>
#include <fnmatch.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unordered_map>
#include <datacrumbs/common/probe_file.h>
#include <utility>
#include <vector>
#include <regex>
#include <string>

namespace datacrumbs {

/// Set, non-empty and not "0". Anything else counts as on, so 1, yes and all all mean the same.
bool ConfigurationManager::env_flag(const char* name) {
  const char* v = std::getenv(name);
  return v != nullptr && *v != '\0' && std::strcmp(v, "0") != 0;
}

namespace {

}  // namespace

std::string ConfigurationManager::env_text(const char* name) {
  const char* v = std::getenv(name);
  return v != nullptr ? std::string(v) : std::string();
}

/// The environment, else what the configurator resolved from the probe yaml.
///
/// A member, so it lives exactly as long as the configuration it fills: a file-scope cache is
/// built during this object's own construction and destroyed before it, which leaves anything
/// reading configuration while shutting down holding a destroyed map.
std::string ConfigurationManager::setting(const char* name) const {
  const char* v = std::getenv(name);
  if (v != nullptr) return std::string(v);
  const auto it = client_settings_.find(name);
  return it != client_settings_.end() ? it->second : std::string();
}

bool ConfigurationManager::setting_flag(const char* name) const {
  const std::string v = setting(name);
  return !v.empty() && v[0] != '0';
}

/// Unset means on, unlike setting_flag: these bound the trace, and a run that forgot to set them
/// should still be bounded.
bool ConfigurationManager::setting_flag_default_on(const char* name) const {
  const std::string v = setting(name);
  return v.empty() || v[0] != '0';
}

void ConfigurationManager::load_client_settings() {
  const std::string path = env_text(DATACRUMBS_ENV_CLIENT_CONFIG);
  if (path.empty()) return;
  std::ifstream in(path);
  if (!in.is_open()) {
    // Named but unreadable is a broken run, not one with no client configuration.
    DC_LOG_ERROR("%s names %s, which cannot be read", DATACRUMBS_ENV_CLIENT_CONFIG, path.c_str());
    return;
  }
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    client_settings_.emplace(line.substr(0, eq), line.substr(eq + 1));
  }
}

namespace {




/// True when @p name matches any comma separated pattern in @p patterns.
///
/// An entry is a glob, or a regex written `regex:<pattern>`: the two the probe yaml offers as
/// `glob:` and `regex:`. Anchored at both ends, as the yaml anchors.
bool matches_any(const std::string& patterns, const char* name) {
  if (patterns.empty()) return false;
  std::size_t start = 0;
  while (start <= patterns.size()) {
    const std::size_t end = patterns.find(',', start);
    std::string one = patterns.substr(start, end == std::string::npos ? end : end - start);
    if (!one.empty()) {
      bool is_regex = false;
      if (one.rfind("regex:", 0) == 0) {
        one = one.substr(6);
        is_regex = true;
      } else if (one.rfind("glob:", 0) == 0) {
        one = one.substr(5);
      }
      if (is_regex) {
        try {
          if (std::regex_match(name, std::regex(one, std::regex::extended))) return true;
        } catch (const std::regex_error& e) {
          // Silence here would read as a workload that made no such calls.
          DC_LOG_ERROR("selection regex '%s' does not compile: %s", one.c_str(), e.what());
        }
      } else if (fnmatch(one.c_str(), name, 0) == 0) {
        return true;
      }
    }
    if (end == std::string::npos) break;
    start = end + 1;
  }
  return false;
}

}  // namespace

ConfigurationManager::CaptureMode ConfigurationManager::mode_for(CaptureMode dflt,
                                                                 const Selection& sel,
                                                                 const char* name) {
  // A name in both lists takes the one that captures more, so a broad aggregate pattern cannot
  // quietly swallow a call that was named for recording.
  if (matches_any(sel.record, name)) return CaptureMode::RECORD;
  if (matches_any(sel.aggregate, name)) return CaptureMode::AGGREGATE;
  if (matches_any(sel.off, name)) return CaptureMode::OFF;
  return dflt;
}

const ConfigurationManager& ConfigurationManager::runtime() {
  static const ConfigurationManager cfg = [] {
    ConfigurationManager c;
    c.load_runtime_system_configuration();
    return c;
  }();
  return cfg;
}

void ConfigurationManager::load_runtime_system_configuration() {
  load_client_settings();
  if (std::getenv(DATACRUMBS_ENV_USER) != nullptr) {
    user = std::getenv(DATACRUMBS_ENV_USER);
  }
  if (std::getenv(DATACRUMBS_ENV_LOG_DIR) != nullptr) {
    log_dir = std::getenv(DATACRUMBS_ENV_LOG_DIR);
  }
  if (std::getenv(DATACRUMBS_ENV_INSTALL_DATA_DIR) != nullptr) {
    data_dir = std::getenv(DATACRUMBS_ENV_INSTALL_DATA_DIR);
  }
  if (std::getenv(DATACRUMBS_ENV_CONFIGURED_TRACE_DIR) != nullptr) {
    trace_log_dir = std::getenv(DATACRUMBS_ENV_CONFIGURED_TRACE_DIR);
  }

  posix_enabled = setting_flag(DATACRUMBS_ENV_POSIX);
  posix_calls = setting(DATACRUMBS_ENV_POSIX);
  posix_debug = setting_flag(DATACRUMBS_ENV_POSIX_DEBUG);

  stdio_enabled = setting_flag(DATACRUMBS_ENV_STDIO);
  stdio_out = setting(DATACRUMBS_ENV_STDIO_OUT);

  api_enabled = setting_flag(DATACRUMBS_ENV_API);
  api_out = setting(DATACRUMBS_ENV_API_OUT);
  api_config = setting(DATACRUMBS_ENV_API_CONFIG);
  api_debug = setting_flag(DATACRUMBS_ENV_API_DEBUG);

  engine_enabled = setting_flag(DATACRUMBS_ENV_ENGINE);
  engine_out = setting(DATACRUMBS_ENV_ENGINE_OUT);
  engine_stats = setting_flag(DATACRUMBS_ENV_ENGINE_STATS);
  engine_wraps = setting(DATACRUMBS_ENV_ENGINE_WRAPS);

  hwts_enabled = setting_flag(DATACRUMBS_ENV_HWTS);
  hwts_out = setting(DATACRUMBS_ENV_HWTS_OUT);
  hwts_doca = setting_flag(DATACRUMBS_ENV_HWTS_DOCA);
  hwts_doca_dev = setting(DATACRUMBS_ENV_HWTS_DOCA_DEV);

  hwts_uprobe = setting_flag(DATACRUMBS_ENV_HWTS_UPROBE);
  hwts_posthook = setting_flag(DATACRUMBS_ENV_HWTS_POSTHOOK);
  hwts_doorbell = setting_flag(DATACRUMBS_ENV_HWTS_DOORBELL);

  const std::string sample = setting(DATACRUMBS_ENV_HWTS_SAMPLE);
  if (!sample.empty()) hwts_sample = std::max(1, std::atoi(sample.c_str()));

  // Unset or empty leaves it on; only a leading '0' disables. Not env_flag, which reads empty as
  // off.
  const char* post_op = std::getenv(DATACRUMBS_ENV_HWTS_POST_OP);
  hwts_post_op = post_op == nullptr || post_op[0] != '0';

  program_enabled = setting_flag_default_on(DATACRUMBS_ENV_PROGRAM);
  program_sink = setting_flag_default_on(DATACRUMBS_ENV_PROGRAM_SINK);

  sink_index = setting(DATACRUMBS_ENV_SINK_INDEX);
  hw_counters = setting(DATACRUMBS_ENV_HW_COUNTERS);
  dpa_trace = setting(DATACRUMBS_ENV_DPA);
  dpa_anchor = setting(DATACRUMBS_ENV_DPA_ANCHOR);

  // atoi, not env_flag: "0" means off but an unset or empty value leaves the sink asynchronous.
  const std::string async = setting(DATACRUMBS_ENV_PFW_ASYNC);
  pfw_async = async.empty() || std::atoi(async.c_str()) != 0;

  const std::string level = setting(DATACRUMBS_ENV_PFW_LEVEL);
  if (!level.empty()) {
    const int v = std::atoi(level.c_str());
    if (v >= 0 && v <= 9) pfw_level = v;
  }

  clock_enabled = setting_flag(DATACRUMBS_ENV_CLOCK);
  timesync_snapshot = setting(DATACRUMBS_ENV_TIMESYNC_SNAPSHOT);

  const std::string dpa_samples = setting(DATACRUMBS_ENV_DPA_EVENT_SAMPLES);
  if (!dpa_samples.empty())
    dpa_event_samples = static_cast<uint32_t>(std::atoi(dpa_samples.c_str()));

  dpa_mode_events = setting(DATACRUMBS_ENV_DPA_MODE) == "events";

  doca_diag_groups = setting(DATACRUMBS_ENV_DOCA_DIAG_GROUPS);

  // The same knob the core's sysfs, ethtool and rdma_qp samplers already use: every periodic
  // node-scope sampler ticks together rather than each on its own private interval.
  const std::string telemetry_ms = setting(DATACRUMBS_ENV_TELEMETRY_INTERVAL_MS);
  if (!telemetry_ms.empty())
    telemetry_interval_ms = static_cast<unsigned int>(std::atoi(telemetry_ms.c_str()));
  if (telemetry_interval_ms == 0) telemetry_interval_ms = 100u;

  if (trace_log_dir.empty()) {
    trace_log_dir = DATACRUMBS_CONFIGURED_TRACE_DIR;
  }
  if (log_dir.empty()) {
    log_dir = DATACRUMBS_LOG_DIR;
  }
  if (data_dir.empty()) {
    data_dir = DATACRUMBS_INSTALL_DATA_DIR;
  }

  // Aggregation is global, following dftracer: off leaves every module recording, full folds every
  // module's records into interval buckets, and selective folds only what a module's own selection
  // names. A module that is not enabled stays off whatever the aggregation says.
  const bool aggregating = setting_flag(DATACRUMBS_ENV_ENABLE_AGGREGATION);
  const std::string agg_type = setting(DATACRUMBS_ENV_AGGREGATION_TYPE);
  aggregation_selective = agg_type == "selective";
  if (!agg_type.empty() && agg_type != "selective" && agg_type != "full") {
    // Silence here would look like a workload that did no work rather than a typo.
    DC_LOG_ERROR("%s must be full or selective, got '%s'", DATACRUMBS_ENV_AGGREGATION_TYPE,
                 agg_type.c_str());
  }
  // full aggregates everything and lets a selection name exceptions; selective records by default
  // and aggregates only what the selection names.
  const CaptureMode dflt =
      (aggregating && !aggregation_selective) ? CaptureMode::AGGREGATE : CaptureMode::RECORD;
  auto mode_for_module = [dflt](bool enabled) { return enabled ? dflt : CaptureMode::OFF; };

  posix_mode = mode_for_module(posix_enabled);
  posix_select = {setting(DATACRUMBS_ENV_POSIX_RECORD),
                   setting(DATACRUMBS_ENV_POSIX_AGGREGATE),
                   setting(DATACRUMBS_ENV_POSIX_OFF)};
  stdio_mode = mode_for_module(stdio_enabled);
  stdio_select = {setting(DATACRUMBS_ENV_STDIO_RECORD),
                   setting(DATACRUMBS_ENV_STDIO_AGGREGATE),
                   setting(DATACRUMBS_ENV_STDIO_OFF)};
  api_mode = mode_for_module(api_enabled);
  api_select = {setting(DATACRUMBS_ENV_API_RECORD),
                   setting(DATACRUMBS_ENV_API_AGGREGATE),
                   setting(DATACRUMBS_ENV_API_OFF)};
  engine_mode = mode_for_module(engine_enabled);
  engine_select = {setting(DATACRUMBS_ENV_ENGINE_RECORD),
                   setting(DATACRUMBS_ENV_ENGINE_AGGREGATE),
                   setting(DATACRUMBS_ENV_ENGINE_OFF)};
  hwts_mode = mode_for_module(hwts_enabled);
  hwts_select = {setting(DATACRUMBS_ENV_HWTS_RECORD),
                   setting(DATACRUMBS_ENV_HWTS_AGGREGATE),
                   setting(DATACRUMBS_ENV_HWTS_OFF)};

  // The per-module modes were replaced by the two globals above. Ignoring one silently would run a
  // module in the wrong mode and look like the workload changed.
  for (const char* gone :
       {"DATACRUMBS_POSIX_MODE", "DATACRUMBS_STDIO_MODE", "DATACRUMBS_API_MODE",
        "DATACRUMBS_ENGINE_MODE", "DATACRUMBS_HWTS_MODE", "DATACRUMBS_ENGINE_RECORD",
        "DATACRUMBS_ENGINE_AGGREGATE"}) {
    if (std::getenv(gone) != nullptr)
      DC_LOG_ERROR("%s is no longer read; set %s and %s instead", gone,
                   DATACRUMBS_ENV_ENABLE_AGGREGATION, DATACRUMBS_ENV_AGGREGATION_TYPE);
  }
}

}  // namespace datacrumbs
