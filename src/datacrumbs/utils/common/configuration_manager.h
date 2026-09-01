// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__
#define DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__

/**
 * @file configuration_manager.h
 * @brief Internal header for the ConfigurationManager class.
 *
 * This file defines the ConfigurationManager class, which is responsible for
 * managing, validating, and deriving configuration settings for the DataCrumbs
 * library.
 */
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>

// std headers
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace datacrumbs {

/**
 * @class ConfigurationManager
 * @brief Manages configuration settings for the DataCrumbs library.
 *
 * The ConfigurationManager class handles loading, validating, and deriving
 * configuration settings based on command-line arguments. It ensures that all
 * required configurations are set and valid before the library is used.
 */
class ConfigurationManager {
 public:
  // Exact configuration file path provided by the user
  std::filesystem::path config_file_path;

  // Directory for data storage
  std::filesystem::path data_dir;

  // Directory where trace logs will be stored
  std::filesystem::path trace_log_dir;

  // List of capture probes to be used in the session
  std::vector<std::shared_ptr<CaptureProbe>> capture_probes;

  // Runtime probes loaded from a signed probe file.
  std::vector<std::shared_ptr<Probe>> runtime_probes;

  // Event IDs generated at runtime load, keyed by probe/function pair.
  std::unordered_map<std::string, uint64_t> runtime_event_ids;

  // User associated with the configuration
  std::string user;

  std::string inclusion_path;   // Path to the inclusion file
  std::string inclusion_paths;  // Colon-separated runtime inclusion paths

  std::string log_dir;  // Directory for log files

  /// What a module does with a call it wrapped. COUNT keeps the same wrapping and the same cost at
  /// the call site; it only replaces the per-call record with one aggregate record per name, which
  /// is what makes a full-visibility probeset affordable to leave on.
  enum class CaptureMode { OFF, RECORD, AGGREGATE };

  /// Glob patterns naming the calls that do the opposite of their module's mode: a module set to
  /// aggregate still records what @c record matches, and one set to record still aggregates what
  /// @c aggregate matches. This is dftracer's selective aggregation.
  ///
  /// Matched once when a module starts, never per call: running a pattern match on every wrapped
  /// call would cost more than aggregating saves.
  /// A datacrumbs-utils client module named by the probe yaml, so one file describes what a run
  /// captures in userspace as well as in the kernel.
  struct ClientLayer {
    std::string name;
    std::string module;  // posix, stdio, vendor_api, doca_engine, ibverbs_hwts
    std::string pattern;
    bool is_regex{false};  // which of the yaml's two keys it came from
    bool aggregate{false};
    bool off{false};
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

  // Which client modules are on, what each does with a call, and where each writes. Read in one
  // place: a getenv per use spread the names over the tree in two spellings, and a typo is silent,
  // since a module that starts and records nothing looks like a workload that did no work.
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

  int pfw_level{2};        // zlib level for the sink
  bool pfw_async{true};    // default on when unset or empty
  std::string sink_index;  // empty disables the shared index

  bool hwts_uprobe{false};
  bool hwts_posthook{false};
  bool hwts_doorbell{false};
  int hwts_sample{1};       // completions per captured sample, never below 1
  bool hwts_post_op{true};  // default on; only a leading '0' turns it off
  std::string dpa_trace;    // file holding a DPA kernel's DC_DPA records
  // "<dpa_us>:<global_ns>[:<err_ns>]": one measured pairing of the DPA clock to the global
  // epoch. Empty leaves DPA records on their own clock rather than guessing an offset.
  std::string dpa_anchor;
  std::string hw_counters;  // read by the pmu plugin

  uint32_t dpa_event_samples{4096};             // read by the dpa_telemetry plugin
  bool dpa_mode_events{false};                  // true when DATACRUMBS_DPA_MODE == "events"

  // Read by the doca_diag plugin. Empty group list means every group the device supports.
  std::vector<ClientLayer> client_layers;

  std::string doca_diag_groups;

  // Shared by every periodic sampler, plugins included, from DATACRUMBS_TELEMETRY_INTERVAL_MS.
  unsigned int telemetry_interval_ms{100};  // 0 falls back to 100

  // Derived configuration: path to the trace file
  std::filesystem::path trace_file_path;

  // Derived configuration: path to the probe file
  std::filesystem::path probe_file_path;

  // Optional override for the exact probe file output path
  std::filesystem::path explicit_probe_file_path;

  // Derived configuration: path to the probe exclusion file
  std::filesystem::path probe_exclusion_file_path;

  // Derived configuration: path to the probe invalid file
  std::filesystem::path probe_invalid_file_path;

  // Derived configuration: path to the category map file
  std::filesystem::path category_map_path;

  // Derived configuration: path to the manual probe file
  std::filesystem::path manual_probe_path;

  // Derived configuration: path to the combined system probe file
  std::filesystem::path system_probe_path;

  // Derived configuration: category map for event IDs
  std::unordered_map<uint64_t, std::pair<std::string, std::string>> category_map;

  // Derived configuration: current hostname
  std::string hostname;

  // Unique run identifier
  std::string run_id;

  // Flag to disable MPI usage
  bool disable_mpi;

  // MPI rank of the current process
  int mpi_rank{0};

  // MPI size (total number of processes)
  int mpi_size{1};

  /**
   * @brief Constructor that initializes the ConfigurationManager with
   * command-line arguments.
   *
   * Parses the command-line arguments to set up the configuration, derives
   * necessary configurations, and validates them. If any required configuration
   * is missing or invalid, logs an error and exits the program.
   *
   * @param argc Number of command-line arguments
   * @param argv Array of command-line argument strings.
   *        Example: ["datacrumbs_probe_configurator_exec", "/tmp/config.yaml", ...]
   * @param load_capture_probes Whether capture probes should be loaded immediately.
   *        Example: true for extractor CLI, false for deferred flows.
   * @param print Whether to print resolved configuration to logs.
   *        Example: true for diagnostics-friendly runs.
   * @throws std::runtime_error or std::invalid_argument when configuration is invalid.
   */
  ConfigurationManager(int argc, char** argv, bool load_capture_probes = false, bool print = true);

  /**
   * @brief Constructor for runtime mode from an already generated probe file.
   * @param runtime_probe_file Signed probe file path.
   *        Example: "/tmp/datacrumbs-ci-probes.json.gz".
   * @param print Whether to print resolved configuration to logs.
   * @throws std::runtime_error when runtime configuration is invalid.
   */
  ConfigurationManager(const std::filesystem::path& runtime_probe_file, bool print = true);

  ConfigurationManager() {
    // Default constructor for internal use
  }

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

  /**
   * @brief Print all resolved configuration values to logs.
   */
  void print_configurations();

  /**
   * @brief Lookup event id for a runtime probe/function pair.
   * @return Event id if found, otherwise std::nullopt.
   */
  std::optional<uint64_t> get_runtime_event_id(const std::string& probe_name,
                                               const std::string& function_name) const;

 private:
  /**
   * @brief Derives configurations based on the provided command-line arguments.
   *
   * Sets up paths and other configurations based on the mode of operation.
   * @throws std::runtime_error if required derived values cannot be formed.
   */
  void derive_configurations();

  /**
   * @brief Validates the derived configurations.
   *
   * Checks if all required configurations are set and valid. If any
   * configuration is invalid, logs an error and exits the program. This ensures
   * correct operation of the DataCrumbs library.
   * @throws std::runtime_error when invariants are violated.
   */
  void validate_configurations();

  /**
   * @brief Load category/event map from JSON file.
   * @throws std::runtime_error when category map file is invalid.
   */
  void load_category_map();

  /**
   * @brief Load runtime system configuration overrides from sqlite.
   * @throws std::runtime_error when critical runtime metadata is invalid.
   */
  void load_runtime_system_configuration();

  /**
   * @brief Load and validate runtime probe payload.
   * @throws std::runtime_error when payload cannot be parsed/verified.
   */
  void load_runtime_probe_file();
};

class ArgumentParser {
 public:
  std::string config_file_path;                     ///< YAML configuration file to load
  std::optional<std::string> trace_log_dir;         ///< Optional trace log directory
  std::optional<std::string> data_dir;              ///< Optional data directory
  std::optional<std::string> probe_file_path;       ///< Optional probe file path
  std::optional<std::string> user;                  ///< Optional user argument
  std::optional<uint64_t> skip_event_threshold_us;  ///< Optional skip event threshold
  std::optional<std::string> inclusion_path;        ///< Optional inclusion path
  std::optional<std::string> log_dir;               ///< Optional log directory
  std::optional<std::string> run_id;                ///< Optional run_id
  /**
   * @brief Constructor that parses command-line arguments.
   * @param argc Number of command-line arguments
   * @param argv Array of command-line argument strings
   *        Example: ["datacrumbs", "--config", "config.yaml", "--user", "runner"]
   * @throws std::invalid_argument if required arguments are missing or unknown
   * arguments are found
   */
  ArgumentParser(int argc, char** argv);
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_COMMON_CONFIGURATION_MANAGER_H__
