// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

/**
 * @file configuration_manager.cpp
 * @brief Implements the ConfigurationManager class for managing DataCrumbs
 * configuration.
 *
 * This file contains the implementation of the ConfigurationManager class,
 * which is responsible for parsing command-line arguments, loading YAML
 * configuration files, and setting up configuration parameters for the
 * DataCrumbs application. It also includes the ArgumentParser class for
 * handling command-line arguments and utility functions for deriving and
 * validating configuration values.
 */

/**
 * std headers
 */
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
/**
 * Internal headers
 */
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>  // <-- Added logging header
#include <datacrumbs/common/probe_file.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/utils/common/configuration_manager.h>
/**
 * External headers
 */
#include <yaml-cpp/yaml.h>

namespace datacrumbs {

namespace {

constexpr uint64_t kRuntimeProbeEventIdBase = 1000;

std::string env_or_default(const char* name, const std::string& fallback) {
  const char* value = std::getenv(name);
  return (value && value[0] != '\0') ? value : fallback;
}

std::string runtime_timestamp() {
  std::time_t now = std::time(nullptr);
  std::tm tm_now{};
  localtime_r(&now, &tm_now);
  std::ostringstream oss;
  oss << std::put_time(&tm_now, "%Y%m%d%H%M%S");
  return oss.str();
}

std::string json_string_or_empty(json_object* root, const char* key) {
  json_object* value = nullptr;
  if (!root || !json_object_object_get_ex(root, key, &value) ||
      json_object_get_type(value) != json_type_string) {
    return "";
  }
  return json_object_get_string(value);
}

std::shared_ptr<Probe> probe_from_json(json_object* probe_obj) {
  if (!probe_obj) return nullptr;
  Probe base = Probe::fromJson(probe_obj);
  switch (base.type) {
    case ProbeType::SYSCALLS:
      return std::make_shared<SysCallProbe>(SysCallProbe::fromJson(probe_obj));
    case ProbeType::KPROBE:
      return std::make_shared<KProbe>(KProbe::fromJson(probe_obj));
    case ProbeType::UPROBE:
      return std::make_shared<UProbe>(UProbe::fromJson(probe_obj));
    case ProbeType::USDT:
      return std::make_shared<USDTProbe>(USDTProbe::fromJson(probe_obj));
    case ProbeType::CUSTOM:
      return std::make_shared<CustomProbe>(CustomProbe::fromJson(probe_obj));
    default:
      return nullptr;
  }
}

std::string runtime_event_key(const std::string& probe_name, const std::string& function_name) {
  return probe_name + "\n" + function_name;
}

std::filesystem::path absolute_normalized_path(const std::filesystem::path& input_path) {
  if (input_path.empty()) {
    return input_path;
  }
  std::error_code ec;
  const std::filesystem::path absolute_path = std::filesystem::absolute(input_path, ec);
  if (ec) {
    return input_path.lexically_normal();
  }
  return absolute_path.lexically_normal();
}

}  // namespace

// Singleton template specialization for ConfigurationManager
template <>
std::shared_ptr<datacrumbs::ConfigurationManager>
    datacrumbs::Singleton<datacrumbs::ConfigurationManager>::instance = nullptr;
template <>
bool datacrumbs::Singleton<datacrumbs::ConfigurationManager>::stop_creating_instances = false;

/**
 * YAML keys for configuration
 */
#define DC_YAML_TRACE_LOG_DIR "trace_log_dir"
#define DC_YAML_DATA_DIR "data_dir"
#define DC_YAML_CAPTURE_PROBES "capture_probes"
#define DC_YAML_USER "user"
#define DC_YAML_INCLUSION_PATH "inclusion_path"

ArgumentParser::ArgumentParser(int argc, char** argv) {
  DC_LOG_TRACE("[ArgumentParser] Parsing command line arguments...");
  if (argc >= 2) {
    std::string first_arg = argv[1];
    if (first_arg == "--help" || first_arg == "-h") {
      DC_LOG_PRINT(
          "Usage: %s <config-file> [--run_id <id>] [--trace_log_dir <path>] "
          "[--user <user>] [--data_dir <path>] "
          "[--probe_file_path <path>] "
          "[--inclusion_path <path>] [--log_dir <path>]",
          argv[0]);
      exit(0);
    }
  }
  if (argc < 2) {
    throw std::invalid_argument("Configuration file path is required as the first argument.");
  }
  int start_index = 1;
  config_file_path = argv[start_index++];

  for (int i = start_index; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--run_id" && i + 1 < argc) {
      run_id = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Run ID set to: %s", run_id->c_str());
    } else if (arg == "--trace_log_dir" && i + 1 < argc) {
      trace_log_dir = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Trace log dir set to: %s", trace_log_dir->c_str());
    } else if (arg == "--data_dir" && i + 1 < argc) {
      data_dir = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Data directory set to: %s", data_dir->c_str());
    } else if (arg == "--probe_file_path" && i + 1 < argc) {
      probe_file_path = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Probe file path set to: %s", probe_file_path->c_str());
    } else if (arg == "--user" && i + 1 < argc) {
      user = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] User set to: %s", user->c_str());
    } else if (arg == "--inclusion_path" && i + 1 < argc) {
      inclusion_path = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Inclusion path set to: %s", inclusion_path->c_str());
    } else if (arg == "--log_dir" && i + 1 < argc) {
      log_dir = argv[++i];
      DC_LOG_DEBUG("[ArgumentParser] Log directory set to: %s", log_dir->c_str());
    } else if (arg == "--help" || arg == "-h") {
      DC_LOG_PRINT(
          "Usage: %s <config-file> [--run_id <id>] [--trace_log_dir <path>] "
          "[--user <user>] [--data_dir "
          "<path>] [--probe_file_path <path>] "
          "[--inclusion_path <path>] [--log_dir <path>]",
          argv[0]);
      exit(0);
    } else {
      DC_LOG_ERROR("[ArgumentParser] Unknown argument: %s", arg.c_str());
      throw std::invalid_argument("Unknown argument: " + arg);
    }
  }
}

/**
 * @brief ConfigurationManager constructor.
 *
 * Initializes the ConfigurationManager with command-line arguments, loads the
 * YAML configuration file, parses it, and sets up the necessary configurations.
 * Also derives and validates configurations.
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 */
ConfigurationManager::ConfigurationManager(int argc, char** argv, bool load_capture_probes,
                                           bool print)
    : config_file_path(),
      trace_log_dir(DATACRUMBS_LOG_DIR),
      capture_probes(),
      user("datacrumbs"),
      run_id("0") {
  struct rlimit rl;
  if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;  // Set soft limit to hard limit
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      DC_LOG_WARN("[ConfigurationManager] Failed to set ulimit -n to hard limit.");
    } else {
      DC_LOG_DEBUG("[ConfigurationManager] Set ulimit -n to hard limit: %lu", rl.rlim_max);
    }
  } else {
    DC_LOG_WARN("[ConfigurationManager] Failed to get current ulimit -n.");
  }
  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;  // Set soft limit to hard limit
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
      DC_LOG_WARN("[ConfigurationManager] Failed to set ulimit -l to hard limit.");
    } else {
      DC_LOG_DEBUG("[ConfigurationManager] Set ulimit -l to hard limit: %lu", rl.rlim_max);
    }
  } else {
    DC_LOG_WARN("[ConfigurationManager] Failed to get current ulimit -l.");
  }
  // Set ulimit -c (core file size) to its hard limit
  if (getrlimit(RLIMIT_CORE, &rl) == 0) {
    rl.rlim_cur = rl.rlim_max;  // Set soft limit to hard limit
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
      DC_LOG_WARN("[ConfigurationManager] Failed to set ulimit -c to hard limit.");
    } else {
      DC_LOG_DEBUG("[ConfigurationManager] Set ulimit -c to hard limit: %lu", rl.rlim_max);
    }
  } else {
    DC_LOG_WARN("[ConfigurationManager] Failed to get current ulimit -c.");
  }
  DC_LOG_TRACE("[ConfigurationManager] Initializing with arguments...");
  ArgumentParser parser(argc, argv);
  this->config_file_path = absolute_normalized_path(parser.config_file_path);
  YAML::Node config;
  DC_LOG_DEBUG("[ConfigurationManager] Loading configuration file: %s",
               config_file_path.string().c_str());
  std::ifstream config_stream(config_file_path);
  if (config_stream.is_open()) {
    std::ostringstream buffer;
    buffer << config_stream.rdbuf();
    const std::string config_text = buffer.str();
    if (std::regex_search(config_text, std::regex(R"(@[A-Za-z0-9_]+@)"))) {
      DC_LOG_ERROR(
          "[ConfigurationManager] Configuration file contains "
          "unresolved CMake placeholders: %s",
          config_file_path.string().c_str());
      throw std::runtime_error("Configuration file is an unconfigured template: " +
                               config_file_path.string());
    }
  }
  try {
    config = YAML::LoadFile(config_file_path.string());
    DC_LOG_DEBUG("[ConfigurationManager] Configuration file loaded successfully.");
  } catch (const YAML::ParserException& e) {
    DC_LOG_ERROR("[ConfigurationManager] Failed to parse configuration file: %s",
                 config_file_path.string().c_str());
    throw std::runtime_error("Failed to parse configuration file: " + config_file_path.string());
  } catch (const YAML::BadFile& e) {
    DC_LOG_ERROR("[ConfigurationManager] Failed to load configuration file: %s",
                 config_file_path.string().c_str());
    throw std::runtime_error("Failed to load configuration file: " + config_file_path.string());
  }

  // Parse YAML configuration if loaded successfully
  if (config) {
    DC_LOG_TRACE("[ConfigurationManager] Parsing configuration YAML...");
    // Parse trace log directory from YAML
    if (config[DC_YAML_TRACE_LOG_DIR]) {
      this->trace_log_dir = config[DC_YAML_TRACE_LOG_DIR].as<std::string>();
      DC_LOG_DEBUG("[ConfigurationManager] Trace log dir set from config: %s",
                   this->trace_log_dir.string().c_str());
    }
    // Parse data directory from YAML or use default
    if (config[DC_YAML_DATA_DIR]) {
      this->data_dir = config[DC_YAML_DATA_DIR].as<std::string>();
      DC_LOG_DEBUG("[ConfigurationManager] Data directory set from config: %s",
                   this->data_dir.string().c_str());
    } else {
      this->data_dir = DATACRUMBS_DATA_DIR;
      DC_LOG_DEBUG(
          "[ConfigurationManager] Data directory not specified, using "
          "default: %s",
          this->data_dir.string().c_str());
    }
    if (config[DC_YAML_CAPTURE_PROBES]) {
      if (!load_capture_probes) {
        DC_LOG_DEBUG(
            "[ConfigurationManager] capture_probes present in %s but "
            "ignored for this "
            "executable.",
            config_file_path.string().c_str());
      } else {
        DC_LOG_TRACE("[ConfigurationManager] Parsing capture probes...");
        for (const auto& probe_node : config[DC_YAML_CAPTURE_PROBES]) {
          if (probe_node["type"]) {
            CaptureType type;
            convert(probe_node["type"].as<std::string>(), type);

            std::shared_ptr<CaptureProbe> probe;
            switch (type) {
              case CaptureType::HEADER: {
                auto header_probe = std::make_shared<HeaderCaptureProbe>();
                if (probe_node["file"]) {
                  header_probe->file = probe_node["file"].as<std::string>();
                } else {
                  throw std::invalid_argument("Header name is required for HEADER capture type.");
                }
                probe = header_probe;
                break;
              }
              case CaptureType::BINARY: {
                auto binary_probe = std::make_shared<BinaryCaptureProbe>();
                if (probe_node["file"]) {
                  binary_probe->file = probe_node["file"].as<std::string>();
                } else {
                  throw std::invalid_argument("Binary path is required for BINARY capture type.");
                }
                const bool is_uprobe =
                    probe_node["probe"] && probe_node["probe"].as<std::string>() == "uprobe";
                binary_probe->include_offsets =
                    is_uprobe
                        ? true
                        : (probe_node["include_offsets"] ? probe_node["include_offsets"].as<bool>()
                                                         : false);
                probe = binary_probe;
                break;
              }
              case CaptureType::KSYM: {
                auto kernel_probe = std::make_shared<KernelCaptureProbe>();
                if (probe_node["regex"]) {
                  kernel_probe->regex = probe_node["regex"].as<std::string>();
                } else {
                  throw std::invalid_argument("Regex is required for KSYM capture type.");
                }
                probe = kernel_probe;
                break;
              }
              case CaptureType::USDT: {
                auto usdt_probe = std::make_shared<USDTCaptureProbe>();
                if (!probe_node["binary_path"] || !probe_node["provider"]) {
                  throw std::invalid_argument(
                      "binary_path and provider are "
                      "required for USDT capture type.");
                }
                usdt_probe->binary_path = probe_node["binary_path"].as<std::string>();
                usdt_probe->provider = probe_node["provider"].as<std::string>();
                probe = usdt_probe;
                break;
              }
              case CaptureType::CUSTOM: {
                auto custom_probe = std::make_shared<CustomCaptureProbe>();
                if (!probe_node["file"] || !probe_node["probes"]) {
                  throw std::invalid_argument(
                      "file and probes are required for CUSTOM capture type.");
                }
                custom_probe->bpf_file = probe_node["file"].as<std::string>();
                custom_probe->probe_file = probe_node["probes"].as<std::string>();
                custom_probe->start_event_id =
                    probe_node["start_event_id"] ? probe_node["start_event_id"].as<uint64_t>() : 0;
                custom_probe->process_header = probe_node["process_header"]
                                                   ? probe_node["process_header"].as<std::string>()
                                                   : "";
                custom_probe->event_type =
                    probe_node["event_type"] ? probe_node["event_type"].as<uint64_t>() : 1;
                probe = custom_probe;
                break;
              }
              default:
                throw std::invalid_argument("Unknown CaptureType in configuration: " +
                                            probe_node["type"].as<std::string>());
            }

            probe->enable_explorer =
                probe_node["enable_explorer"] ? probe_node["enable_explorer"].as<bool>() : true;
            if (!probe_node["probe"] || !probe_node["name"]) {
              throw std::invalid_argument("Probe type and name are required for capture probes.");
            }
            convert(probe_node["probe"].as<std::string>(), probe->probe_type);
            probe->name = probe_node["name"].as<std::string>();
            if (probe_node["regex"]) {
              probe->regex = probe_node["regex"].as<std::string>();
            }
            this->capture_probes.push_back(probe);
          }
        }
      }
    }
    // Parse user from YAML or use default
    if (config[DC_YAML_USER]) {
      this->user = config[DC_YAML_USER].as<std::string>();
      DC_LOG_DEBUG("[ConfigurationManager] User set from config: %s", this->user.c_str());
    } else {
      DC_LOG_DEBUG(
          "[ConfigurationManager] No user specified in config, using "
          "default: %s",
          this->user.c_str());
    }
    // Parse inclusion path from YAML
    if (config[DC_YAML_INCLUSION_PATH]) {
      this->inclusion_path = config[DC_YAML_INCLUSION_PATH].as<std::string>();
      this->inclusion_paths = this->inclusion_path;
      DC_LOG_DEBUG("[ConfigurationManager] Inclusion path set from config: %s",
                   this->inclusion_path.c_str());
    }
    // Override run_id if provided as argument
    if (parser.run_id) {
      this->run_id = *parser.run_id;
      DC_LOG_DEBUG("[ConfigurationManager] Run ID overridden by argument: %s",
                   this->run_id.c_str());
    }
    // Override config path if provided as argument
    if (parser.data_dir) {
      this->data_dir = absolute_normalized_path(*parser.data_dir);
      DC_LOG_DEBUG("[ConfigurationManager] Data directory overridden by argument: %s",
                   this->data_dir.string().c_str());
    }
    if (parser.probe_file_path) {
      this->explicit_probe_file_path = absolute_normalized_path(*parser.probe_file_path);
      DC_LOG_DEBUG("[ConfigurationManager] Probe file path overridden by argument: %s",
                   this->explicit_probe_file_path.string().c_str());
    }
    // Override trace log dir if provided as argument
    if (parser.trace_log_dir) {
      this->trace_log_dir = absolute_normalized_path(*parser.trace_log_dir);
      DC_LOG_DEBUG("[ConfigurationManager] Trace log dir overridden by argument: %s",
                   parser.trace_log_dir->c_str());
    }
    // Override user if provided as argument
    if (parser.user) {
      this->user = *parser.user;
      DC_LOG_DEBUG("[ConfigurationManager] User overridden by argument: %s", parser.user->c_str());
    } else {
      DC_LOG_DEBUG("[ConfigurationManager] No user specified, using default: %s",
                   this->user.c_str());
    }
    // Override inclusion path if provided as argument
    if (parser.inclusion_path) {
      this->inclusion_path = *parser.inclusion_path;
      this->inclusion_paths = this->inclusion_path;
      DC_LOG_DEBUG("[ConfigurationManager] Inclusion path overridden by argument: %s",
                   parser.inclusion_path->c_str());
    }
    // Override log dir if provided as argument
    if (parser.log_dir) {
      this->log_dir = *parser.log_dir;
      DC_LOG_DEBUG("[ConfigurationManager] Log directory overridden by argument: %s",
                   parser.log_dir->c_str());
    } else {
      this->log_dir = std::filesystem::current_path();
      DC_LOG_DEBUG(
          "[ConfigurationManager] No log directory specified, using "
          "default: %s",
          this->log_dir.c_str());
    }
    this->disable_mpi = true;
  }
  // Derive additional configuration values and validate
  derive_configurations();
  load_category_map();
  validate_configurations();
  if (print) {
    print_configurations();
    DC_LOG_INFO("[ConfigurationManager] Initialization complete.");
  }
};

ConfigurationManager::ConfigurationManager(const std::filesystem::path& runtime_probe_file,
                                           bool print)
    : config_file_path(),
      data_dir(DATACRUMBS_INSTALL_SHARED_DATA_DIR),
      trace_log_dir(DATACRUMBS_LOG_DIR),
      capture_probes(),
      runtime_probes(),
      user(env_or_default("DATACRUMBS_USER", env_or_default("USER", DATACRUMBS_INSTALL_USER))),
      log_dir(DATACRUMBS_LOG_DIR),
      run_id(env_or_default("DATACRUMBS_SERVER_RUN_ID", runtime_timestamp())),
      disable_mpi(true) {
  probe_file_path = absolute_normalized_path(runtime_probe_file);
  system_probe_path = DATACRUMBS_SYSTEM_PROBE_FILE;
  load_runtime_system_configuration();
  derive_configurations();
  system_probe_path = DATACRUMBS_SYSTEM_PROBE_FILE;
  probe_file_path = absolute_normalized_path(runtime_probe_file);
  load_runtime_probe_file();
  validate_configurations();
  if (print) {
    print_configurations();
    DC_LOG_INFO("[ConfigurationManager] Runtime probe configuration initialized.");
  }
}

void ConfigurationManager::print_configurations() {
  // Log final configuration for debugging
  DC_LOG_INFO("[ConfigurationManager] Final configuration:");
  DC_LOG_INFO("[ConfigurationManager] Capture probes loaded: %zu", this->capture_probes.size());
  DC_LOG_INFO("[ConfigurationManager] Category map loaded with %zu entries.", category_map.size());
  DC_LOG_INFO("  Config file path: %s", this->config_file_path.string().c_str());
  DC_LOG_INFO("  Trace log dir: %s", this->trace_log_dir.string().c_str());
  DC_LOG_INFO("  Trace file path: %s", this->trace_file_path.string().c_str());
  DC_LOG_INFO("  Data dir: %s", this->data_dir.string().c_str());
  DC_LOG_INFO("  Probe file path: %s", this->probe_file_path.string().c_str());
  DC_LOG_INFO("  Probe exclusion file path: %s", this->probe_exclusion_file_path.string().c_str());
  DC_LOG_INFO("  Probe invalid file path: %s", this->probe_invalid_file_path.string().c_str());
  DC_LOG_INFO("  Manual probe path: %s", this->manual_probe_path.string().c_str());
  DC_LOG_INFO("  System probe path: %s", this->system_probe_path.string().c_str());
  DC_LOG_INFO("  Category map path: %s", this->category_map_path.string().c_str());
  DC_LOG_INFO("  Profiling interval: %f", DATACRUMBS_TIME_INTERVAL_NS / 1e9);
  DC_LOG_INFO("  Runtime User: %s", this->user.c_str());
  DC_LOG_INFO("  Install user: %s", DATACRUMBS_INSTALL_USER);
  DC_LOG_INFO("  Hostname: %s", this->hostname.c_str());
  DC_LOG_INFO("  Capture probes: %d", static_cast<int>(this->capture_probes.size()));
  if (DATACRUMBS_MODE == 1) {
    DC_LOG_INFO("  Mode: Tracing");
  } else if (DATACRUMBS_MODE == 2) {
    DC_LOG_INFO("  Mode: Profiling");
  }
  if (this->inclusion_path.empty()) {
    DC_LOG_INFO("  Inclusion path: Not set");
  } else {
    DC_LOG_INFO("  Inclusion path: %s", this->inclusion_path.c_str());
  }
  for (const auto& probe : this->capture_probes) {
    DC_LOG_INFO("    Probe: name=%s, type=%d, probe_type=%d, regex=%s", probe->name.c_str(),
                static_cast<int>(probe->type), static_cast<int>(probe->probe_type),
                probe->regex.c_str());
  }
}

/**
 * @brief Derives additional configuration values based on current settings.
 *
 * This function generates file paths for trace files, probe files, exclusion
 * files, and category maps based on the hostname, process ID, timestamp, and
 * user.
 */
void ConfigurationManager::derive_configurations() {
  DC_LOG_TRACE("[ConfigurationManager] Deriving configurations...");
  DC_LOG_DEBUG("[ConfigurationManager] Process ID: %d", getpid());

  // Use this->hostname (std::string) instead of local char array
  std::string hostname;
  char hostname_buf[256] = {0};
  if (gethostname(hostname_buf, sizeof(hostname_buf) - 1) != 0) {
    DC_LOG_ERROR("[ConfigurationManager] Failed to get hostname.");
    throw std::runtime_error("Failed to get hostname.");
  }
  hostname = hostname_buf;
  this->hostname = hostname;
  DC_LOG_DEBUG("[ConfigurationManager] Hostname: %s", this->hostname.c_str());

  const std::string configuration_stem =
      this->config_file_path.empty() ? hostname : this->config_file_path.stem().string();
  std::string generated_file_suffix =
      this->user + "-" + this->run_id + "-" + hostname + "-" + configuration_stem;

  std::string trace_file_name = "trace-" + generated_file_suffix + ".pfw.gz";
  this->trace_file_path = this->trace_log_dir / trace_file_name;
  this->trace_file_path = absolute_normalized_path(this->trace_file_path);
  DC_LOG_DEBUG("[ConfigurationManager] Trace file path: %s",
               this->trace_file_path.string().c_str());

  std::string lookup_file_suffix = std::string(DATACRUMBS_INSTALL_USER) + "-" + configuration_stem;

  // Construct probe file name: probes-DATACRUMBS_INSTALL_USER-host.json
  std::string probe_file_name = "probes-" + lookup_file_suffix + ".json.gz";
  this->probe_file_path = this->data_dir / probe_file_name;
  if (!this->explicit_probe_file_path.empty()) {
    this->probe_file_path = this->explicit_probe_file_path;
  }
  this->probe_file_path = absolute_normalized_path(this->probe_file_path);
  DC_LOG_DEBUG("[ConfigurationManager] Probe file path: %s",
               this->probe_file_path.string().c_str());

  // Construct probe exclusion file name:
  // probes-exclusion-DATACRUMBS_INSTALL_USER-host.json
  std::string probe_exclusion_file_name = "probes-exclusion-" + lookup_file_suffix + ".json";
  this->probe_exclusion_file_path = this->data_dir / probe_exclusion_file_name;
  this->probe_exclusion_file_path = absolute_normalized_path(this->probe_exclusion_file_path);
  DC_LOG_DEBUG("[ConfigurationManager] Probe exclusion file path: %s",
               this->probe_exclusion_file_path.string().c_str());

  // Construct probe invalid file name:
  // probes-invalid-DATACRUMBS_INSTALL_USER-host.json
  std::string probe_invalid_file_name = "probes-invalid-" + lookup_file_suffix + ".json";
  this->probe_invalid_file_path = this->data_dir / probe_invalid_file_name;
  this->probe_invalid_file_path = absolute_normalized_path(this->probe_invalid_file_path);
  DC_LOG_DEBUG("[ConfigurationManager] Probe invalid path: %s",
               this->probe_invalid_file_path.string().c_str());

  // Construct categories file name:
  // categories-DATACRUMBS_INSTALL_USER-host.json
  std::string categories_file_name = "categories-" + lookup_file_suffix + ".json";
  this->category_map_path = this->data_dir / categories_file_name;
  this->category_map_path = absolute_normalized_path(this->category_map_path);
  DC_LOG_DEBUG("[ConfigurationManager] Category map path: %s",
               this->category_map_path.string().c_str());

  // Construct manual probe file name:
  // manual-probes-DATACRUMBS_INSTALL_USER-host.json
  std::string manual_probe_file_name = "manual-probes-" + lookup_file_suffix + ".json";
  this->manual_probe_path = this->data_dir / manual_probe_file_name;
  this->manual_probe_path = absolute_normalized_path(this->manual_probe_path);
  DC_LOG_DEBUG("[ConfigurationManager] Manual probe path: %s",
               this->manual_probe_path.string().c_str());

  std::string system_probe_file_name = "system-probe-" + lookup_file_suffix + ".sqlite";
  this->system_probe_path = this->data_dir / system_probe_file_name;
  this->system_probe_path = absolute_normalized_path(this->system_probe_path);
  DC_LOG_DEBUG("[ConfigurationManager] System probe path: %s",
               this->system_probe_path.string().c_str());
}

/**
 * @brief Validates the loaded and derived configuration values.
 *
 * Checks for the presence of capture probes and the existence of required
 * directories. Throws exceptions if validation fails.
 */
void ConfigurationManager::load_category_map() {
  std::string category_json_path = category_map_path.string();
  if (category_json_path.empty() || !std::filesystem::exists(category_json_path)) {
    DC_LOG_WARN("[ConfigurationManager] Category map file does not exist: %s",
                category_json_path.c_str());
    return;
  }

  std::ifstream file(category_json_path);
  if (!file) {
    DC_LOG_ERROR("Failed to open category map file: %s", category_json_path.c_str());
    throw std::invalid_argument("Failed to open category map file: " + category_json_path);
  }

  std::string json_str((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  file.close();

  struct json_object* root = json_tokener_parse(json_str.c_str());
  if (!root) {
    DC_LOG_ERROR("Failed to parse JSON from %s", category_json_path.c_str());
    throw std::invalid_argument("Failed to parse JSON from: " + category_json_path);
  }

  json_object_object_foreach(root, key, val) {
    uint64_t event_id = std::stoull(key);
    const char* probe_name = nullptr;
    const char* function_name = nullptr;

    struct json_object* probe_obj = nullptr;
    struct json_object* func_obj = nullptr;

    if (json_object_object_get_ex(val, "probe_name", &probe_obj) &&
        json_object_object_get_ex(val, "function_name", &func_obj)) {
      probe_name = json_object_get_string(probe_obj);
      function_name = json_object_get_string(func_obj);
      category_map[event_id] =
          std::make_pair(probe_name ? probe_name : "", function_name ? function_name : "");
    }
  }
  json_object_put(root);
}

void ConfigurationManager::load_runtime_system_configuration() {
  if (std::getenv("DATACRUMBS_USER") != nullptr) {
    user = std::getenv("DATACRUMBS_USER");
  }
  if (std::getenv("DATACRUMBS_LOG_DIR") != nullptr) {
    log_dir = std::getenv("DATACRUMBS_LOG_DIR");
  }
  if (std::getenv("DATACRUMBS_INSTALL_DATA_DIR") != nullptr) {
    data_dir = std::getenv("DATACRUMBS_INSTALL_DATA_DIR");
  }
  if (std::getenv("DATACRUMBS_CONFIGURED_TRACE_DIR") != nullptr) {
    trace_log_dir = std::getenv("DATACRUMBS_CONFIGURED_TRACE_DIR");
  }

  if (trace_log_dir.empty()) {
    trace_log_dir = DATACRUMBS_CONFIGURED_TRACE_DIR;
  }
  if (log_dir.empty()) {
    log_dir = DATACRUMBS_LOG_DIR;
  }
  if (data_dir.empty()) {
    data_dir = DATACRUMBS_INSTALL_DATA_DIR;
  }
}

void ConfigurationManager::load_runtime_probe_file() {
  std::string probe_error;
  json_object* categories =
      datacrumbs::probe_file::load_verified_categories_from_file(probe_file_path, &probe_error);
  if (!categories || json_object_get_type(categories) != json_type_array) {
    if (categories) json_object_put(categories);
    throw std::runtime_error("Failed to verify runtime probe file: " + probe_file_path.string() +
                             " (" + probe_error + ")");
  }

  runtime_probes.clear();
  category_map.clear();
  this->runtime_event_ids.clear();
  uint64_t event_id = kRuntimeProbeEventIdBase;
  const int arr_len = json_object_array_length(categories);
  for (int i = 0; i < arr_len; ++i) {
    json_object* probe_obj = json_object_array_get_idx(categories, i);
    auto probe = probe_from_json(probe_obj);
    if (!probe) {
      DC_LOG_WARN(
          "[ConfigurationManager] Skipping unsupported runtime probe "
          "at index %d",
          i);
      continue;
    }
    runtime_probes.push_back(probe);
    for (const auto& function_name : probe->functions) {
      const uint64_t assigned_event_id = event_id++;
      category_map[assigned_event_id] = std::make_pair(probe->name, function_name);
      this->runtime_event_ids[runtime_event_key(probe->name, function_name)] = assigned_event_id;
    }
  }
  json_object_put(categories);
}

std::optional<uint64_t> ConfigurationManager::get_runtime_event_id(
    const std::string& probe_name, const std::string& function_name) const {
  const auto it = this->runtime_event_ids.find(runtime_event_key(probe_name, function_name));
  if (it == this->runtime_event_ids.end()) {
    return std::nullopt;
  }
  return it->second;
}

void ConfigurationManager::validate_configurations() {
  if (this->data_dir.empty() || !std::filesystem::exists(this->data_dir)) {
    DC_LOG_ERROR("[ConfigurationManager] Data directory does not exist: %s.",
                 this->data_dir.string().c_str());
    throw std::runtime_error("Data directory does not exist: " + this->data_dir.string());
  }
  if (this->trace_log_dir.empty() ||
      !std::filesystem::exists(std::filesystem::path(this->trace_log_dir))) {
    DC_LOG_ERROR("[ConfigurationManager] Trace log directory does not exist: %s.",
                 this->trace_log_dir.string().c_str());
    throw std::runtime_error("Trace log directory does not exist: " +
                             std::filesystem::path(this->trace_log_dir).string());
  }
}

}  // namespace datacrumbs
