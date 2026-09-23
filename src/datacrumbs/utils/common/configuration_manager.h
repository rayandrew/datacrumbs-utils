// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__
#define DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__

#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_utils_config.h>

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace datacrumbs {

/**
 * Loads, validates, and derives datacrumbs configuration from CLI arguments or a runtime probe
 * file.
 */
class ConfigurationManager {
 public:
  std::filesystem::path config_file_path;
  std::filesystem::path data_dir;
  std::filesystem::path trace_log_dir;
  std::vector<std::shared_ptr<CaptureProbe>> capture_probes;

  // Runtime probes loaded from a signed probe file.
  std::vector<std::shared_ptr<Probe>> runtime_probes;

  // Event IDs generated at runtime load, keyed by probe/function pair.
  std::unordered_map<std::string, uint64_t> runtime_event_ids;

  std::string user;

  std::string inclusion_path;
  std::string inclusion_paths;  // colon-separated runtime inclusion paths

  std::string log_dir;

  /// What a module does with a call it wrapped. COUNT keeps the same wrapping and the same cost at
  /// the call site; it only replaces the per-call record with one aggregate record per name, which
  /// is what makes a full-visibility probeset affordable to leave on.
  enum class CaptureMode { OFF, RECORD, AGGREGATE };

  /// A datacrumbs-utils client module named by the probe yaml. Its pattern overrides the
  /// module's default mode: an aggregating module still records what matches, and a recording
  /// module still aggregates what matches. Matched once when the module starts, not per call.
  struct ClientLayer {
    std::string name;
    std::string module;  // posix, stdio, vendor_api, doca_engine, ibverbs_hwts
    std::string pattern;
    bool is_regex{false};  // which of the yaml's two keys it came from
    bool aggregate{false};
    bool off{false};
    /// Calls never to wrap, as globs. Unlike `off`, which drops the record after paying for the
    /// call, these are excluded from the binding table, so a polling loop costs nothing.
    std::vector<std::string> skip;
  };

  struct Selection {
    std::string record;     // comma separated
    std::string aggregate;  // comma separated
    /// Calls to drop. Trims the trace, not the instrument: the call is still wrapped and costs
    /// what it did. An explicit record or aggregate pattern wins over this.
    std::string off;
  };

  /// The mode @p name runs in, given its module's default and that module's exception lists.
  static CaptureMode mode_for(CaptureMode dflt, const Selection& sel, const char* name);

  // Which client modules are on, what each does with a call, and where each writes. All read here
  // in one place, so one name and one spelling controls each setting. A module that starts but
  // records nothing looks the same as a workload that did no work, so a typo here must not be
  // silent.
  bool posix_enabled{false};
  /// True when aggregation applies only to what each module's selection names, false when it
  /// applies to everything. Meaningless unless aggregation is enabled.
  bool aggregation_selective{false};

  CaptureMode posix_mode{CaptureMode::OFF};
  Selection posix_select;
  std::string posix_calls;  // empty means every call the module wraps
  bool posix_debug{false};

  bool stdio_enabled{false};
  CaptureMode stdio_mode{CaptureMode::OFF};
  Selection stdio_select;
  std::string stdio_out;

  bool api_enabled{false};
  CaptureMode api_mode{CaptureMode::OFF};
  Selection api_select;
  std::string api_out;
  std::string api_config;  // yaml naming the subset of the wrap list to bind
  bool api_debug{false};

  bool engine_enabled{false};
  CaptureMode engine_mode{CaptureMode::OFF};
  Selection engine_select;
  std::string engine_out;
  bool engine_stats{false};
  // Which symbols the engine module interposes, comma separated. Empty means all of them. Exists
  // to isolate which interposition a kernel-bypass data path cannot tolerate.
  std::string engine_wraps;
  // Off keeps the ring scan (so byte-count and hardware timestamp records still count device work)
  // but skips the submit/completion join table entirely: a count-only mode with none of the join
  // cost, for a collection instrument that only needs throughput and cannot pay for per-op names.
  bool engine_join_enabled{true};
  // Off re-parses every scanned entry's data segments even when its control-segment bytes have not
  // changed since the last scan. Diagnostic: isolates the rescan cache's contribution to cost from
  // the join table's.
  bool engine_scan_cache_enabled{true};
  // How often the engine module's own drain thread sweeps every bound CQ, in addition to the
  // app's own doca_pe_progress calls. Microseconds. Left a raw uint here rather than a duration
  // type, matching dpa_anchor_interval_s below.
  unsigned int engine_drain_us{100};
  // DATACRUMBS_ENGINE_CAPTURE_MODE, raw; the doca module parses "records" (default) or "aggregate",
  // the same way dpa_anchor_mode below is a string here and an enum in its own client module.
  std::string engine_capture_mode;
  // Every Nth completion becomes a full record; the rest only count. In aggregate mode this is the
  // spot-check, in records mode it thins a stream the writer cannot keep up with. 0 or 1 means
  // every completion. Not an app-thread cost either way: the timer thread does the capture.
  unsigned int engine_sample{1};

  bool hwts_enabled{false};
  CaptureMode hwts_mode{CaptureMode::OFF};
  Selection hwts_select;
  std::string hwts_out;
  bool hwts_doca{false};
  std::string hwts_doca_dev;

  bool clock_enabled{false};

  std::string timesync_snapshot;  // empty means the compiled-in default path

  // Default on when unset, so an untraced run still bounds itself; "" or a leading 0 turns it off.
  bool program_enabled{true};
  bool program_sink{true};

  int pfw_level{
      1};  // gzip level: levels 1 and 2 cost the same CPU time on a BlueField core with
           // libdeflate, and level 1 compresses faster, so it is the better default
  bool pfw_async{true};  // default on when unset or empty
  unsigned ring_mb{64};  // record ring per thread per sink
  unsigned compress_threads{3};
  /// CPU list (taskset syntax) the client's own worker threads are pinned to. Empty inherits
  /// the process mask, which under taskset puts them on the application's cores.
  std::string worker_cpus;
  std::string sink_index;  // empty disables the shared index

  bool hwts_uprobe{false};
  bool hwts_posthook{false};
  bool hwts_doorbell{false};
  int hwts_sample{1};       // completions per captured sample, never below 1
  bool hwts_post_op{true};  // default on; only a leading '0' turns it off
  std::string dpa_trace;    // file holding a DPA kernel's DC_DPA records
  // Format: "<dpa_us>:<global_ns>[:<err_ns>]". Holds one manual pairing of the DPA clock to the
  // global clock. Empty leaves DPA records on their own clock instead of guessing an offset.
  // Overrides the automatic anchor loop below when set.
  std::string dpa_anchor;
  // How often the automatic DPA anchor loop samples the clock, once registered. Reading the clock
  // needs a kernel launch, which is slow, so this interval is in seconds, unlike the millisecond
  // telemetry interval below.
  unsigned int dpa_anchor_interval_s{10};
  // DATACRUMBS_DPA_ANCHOR_MODE, raw; datacrumbs::client::dpa::AnchorMode parses it, "rpc" as the
  // fallback for anything unrecognised. Left a string here, like dpa_dev below, rather than the
  // enum itself: that type lives in the client module, not this shared header.
  std::string dpa_anchor_mode;
  // Window mode only: how long the burst kernel runs, on the DPA's own clock.
  unsigned int dpa_anchor_burst_us{1000};
  std::string dpa_dev;  // DATACRUMBS_DPA_DEV; empty means the first device offering a DPA context
  std::string hw_counters;  // read by the pmu plugin

  uint32_t dpa_event_samples{4096};  // read by the dpa_telemetry plugin
  bool dpa_mode_events{false};       // true when DATACRUMBS_DPA_MODE == "events"
  // DATACRUMBS_DPA_KEEP_ANCHOR: keep the anchor's own DPA events in the trace. Diagnostic only:
  // the anchor's 1 ms bursts are the one DPA event with a host bracket under 1 us.
  bool dpa_keep_anchor{false};
  // When the telemetry plugin re-arms the event tracer, which empties the device's event buffers:
  // "all" on any process or thread change, "process" on a new process only, "off" never.
  std::string dpa_rearm{"all"};

  // Read by the doca_diag plugin. Empty group list means every group the device supports.
  std::vector<ClientLayer> client_layers;

  std::string doca_diag_groups;

  // Shared by every periodic sampler, plugins included, from DATACRUMBS_TELEMETRY_INTERVAL_MS.
  unsigned int telemetry_interval_ms{100};  // 0 falls back to 100

  // Cadence of the timesync plugin's raw clock_info audit record, from
  // DATACRUMBS_TIMESYNC_CLOCK_INFO_INTERVAL_MS. Independent of telemetry_interval_ms: this one
  // tracks the daemon's own clock_info refresh (default 60000 ms), not the general sampler cadence.
  unsigned int timesync_clock_info_interval_ms{60000};

  std::filesystem::path trace_file_path;
  std::filesystem::path probe_file_path;

  // Optional override for the exact probe file output path
  std::filesystem::path explicit_probe_file_path;

  std::filesystem::path probe_exclusion_file_path;
  std::filesystem::path probe_invalid_file_path;
  std::filesystem::path category_map_path;
  std::filesystem::path manual_probe_path;
  std::filesystem::path system_probe_path;
  std::unordered_map<uint64_t, std::pair<std::string, std::string>> category_map;
  std::string hostname;
  std::string run_id;
  bool disable_mpi;
  int mpi_rank{0};
  int mpi_size{1};

  /**
   * @param load_capture_probes Load capture probes immediately, rather than deferring.
   * @throws std::runtime_error or std::invalid_argument on invalid configuration.
   */
  ConfigurationManager(int argc, char** argv, bool load_capture_probes = false, bool print = true);

  /**
   * @param runtime_probe_file Signed probe file path.
   * @throws std::runtime_error when runtime configuration is invalid.
   */
  ConfigurationManager(const std::filesystem::path& runtime_probe_file, bool print = true);

  ConfigurationManager() {}

  /// The settings a preloaded client runs on, read from the environment once. The other
  /// constructors take argv or a probe file, which a library in somebody else's process has
  /// neither of. Built on first use, not at load: a wrapped call can arrive before this unit's
  /// dynamic initializers would have run.
  static const ConfigurationManager& runtime();

  /// Environment lookups for the few callers whose variable name is only known at run time (a sink
  /// given a per-instance override name). Everything with a fixed name gets a field above instead,
  /// so one place decides what a setting is called and what its default means.
  static std::string env_text(const char* name);

 private:
  /// What the configurator resolved from the probe yaml, read once when this is loaded.
  std::unordered_map<std::string, std::string> client_settings_;
  void load_client_settings();
  std::string setting(const char* name) const;
  bool setting_flag(const char* name) const;
  bool setting_flag_default_on(const char* name) const;

 public:
  static bool env_flag(const char* name);

  void print_configurations();

  /// @return Event id if found, otherwise std::nullopt.
  std::optional<uint64_t> get_runtime_event_id(const std::string& probe_name,
                                               const std::string& function_name) const;

 private:
  /// @throws std::runtime_error if required derived values cannot be formed.
  void derive_configurations();

  /**
   * Logs an error and exits the process on an invalid configuration.
   * @throws std::runtime_error when invariants are violated.
   */
  void validate_configurations();

  /// @throws std::runtime_error when the category map file is invalid.
  void load_category_map();

  /// Loads runtime system configuration overrides from sqlite.
  /// @throws std::runtime_error when critical runtime metadata is invalid.
  void load_runtime_system_configuration();

  /// @throws std::runtime_error when the runtime probe payload cannot be parsed or verified.
  void load_runtime_probe_file();
};

class ArgumentParser {
 public:
  std::string config_file_path;  ///< YAML configuration file to load
  std::optional<std::string> trace_log_dir;
  std::optional<std::string> data_dir;
  std::optional<std::string> probe_file_path;
  std::optional<std::string> user;
  std::optional<uint64_t> skip_event_threshold_us;
  std::optional<std::string> inclusion_path;
  std::optional<std::string> log_dir;
  std::optional<std::string> run_id;
  /// @throws std::invalid_argument if a required argument is missing or unknown.
  ArgumentParser(int argc, char** argv);
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__
