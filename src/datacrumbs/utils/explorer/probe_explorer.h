// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>  // Use custom logging macros
#include <datacrumbs/common/probe_file.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/utils.h>
#include <datacrumbs/utils/common/configuration_manager.h>
#include <datacrumbs/utils/explorer/mechanism/elf_capture.h>
#include <datacrumbs/utils/explorer/mechanism/header_capture.h>
#include <datacrumbs/utils/explorer/mechanism/ksym_capture.h>
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
  /**
   * @brief Construct a probe explorer from command-line context.
   * @param argc CLI argument count.
   * @param argv CLI argument vector.
   * @param load_capture_probes Whether capture probes should be loaded from config immediately.
   *        Example: `true` for probe generation flows, `false` for lightweight mode.
   */
  ProbeExplorer(int argc, char** argv, bool load_capture_probes = false);

  /**
   * @brief Load exclusion mappings and validate exclusion entries.
   * @return Map of probe name -> set of function names to exclude.
   */
  std::unordered_map<std::string, std::unordered_set<std::string>> Extract_Exclusions();

  /**
   * @brief Extract probes from configured capture sources.
   * @return Vector of probe definitions ready for serialization/signing.
   */
  std::vector<std::shared_ptr<Probe>> extractProbes();

  /**
   * @brief Create an exclusion file template from extracted probes when missing.
   * @param probes Probe set used to build exclusion-file structure.
   */
  void create_exclusion_file(std::vector<std::shared_ptr<Probe>> probes);

  /**
   * @brief Write extracted probes to JSON, request signature, and persist final artifact.
   * @return The probe vector that was written/signed.
   */
  std::vector<std::shared_ptr<Probe>> writeProbesToJson();

  /**
   * @brief Write install-time system configuration artifact as gzipped JSON.
   * @return true on success, false on write/serialization failure.
   */
  bool writeSystemProbeJson();

  /**
   * @brief Load existing probes from a previously generated JSON file.
   * @return Map of probe name -> probe object.
   */
  std::unordered_map<std::string, std::shared_ptr<Probe>> loadExistingProbes();

  /**
   * @brief Indicates whether extraction/validation encountered invalid probe candidates.
   */
  bool has_invalid_probes_ = false;

 private:
  /**
   * @brief Configuration source for probe extraction and output paths.
   */
  std::shared_ptr<ConfigurationManager> configManager_;
};

}  // namespace datacrumbs
