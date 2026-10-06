// SPDX-License-Identifier: MIT

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/probe_file.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/explorer/mechanism/elf_capture.h>
#include <datacrumbs/utils/explorer/mechanism/header_capture.h>
#include <datacrumbs/utils/explorer/mechanism/ksym_capture.h>
#include <datacrumbs/utils/explorer/mechanism/tracepoint_capture.h>
#include <datacrumbs/utils/explorer/mechanism/usdt_functions.h>

// dependency libraries
#include <json-c/json.h>

// std headers
#include <fstream>
#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace datacrumbs {

/**
 * @brief Extracts probe candidates, applies filtering/validation, and writes signed probe payloads.
 */
class ProbeExplorer {
 public:
  /// load_capture_probes loads capture probes from config immediately; false is lightweight mode.
  ProbeExplorer(int argc, char** argv, bool load_capture_probes = false);

  /// @return Map of probe name to the set of function names to exclude.
  std::unordered_map<std::string, std::unordered_set<std::string>> Extract_Exclusions();

  std::vector<std::shared_ptr<Probe>> extractProbes();

  /// Creates an exclusion file template from probes when one does not already exist.
  void create_exclusion_file(std::vector<std::shared_ptr<Probe>> probes);

  /// Writes extracted probes to JSON, requests signature, and persists the final artifact.
  std::vector<std::shared_ptr<Probe>> writeProbesToJson();

  /// Writes the install-time system configuration artifact as gzipped JSON.
  bool writeSystemProbeJson();
  bool writeClientConfig(const std::filesystem::path& probe_path);

  std::unordered_map<std::string, std::shared_ptr<Probe>> loadExistingProbes();

  bool has_invalid_probes_ = false;
  bool signing_failed_ = false;

 private:
  std::shared_ptr<ConfigurationManager> configManager_;
};

}  // namespace datacrumbs
