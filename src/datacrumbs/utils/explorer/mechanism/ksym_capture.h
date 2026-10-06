// SPDX-License-Identifier: MIT

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
// std headers
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
namespace datacrumbs {

/**
 * @brief Captures and filters kernel symbol function names from /proc/kallsyms.
 */
class KSymCapture {
 public:
  KSymCapture(const std::string& kallsyms_path = "/proc/kallsyms") {
    DC_LOG_TRACE("KSymCapture: Start loading functions from %s", kallsyms_path.c_str());
    loadFunctions(kallsyms_path);
    DC_LOG_TRACE("KSymCapture: Finished loading functions from %s", kallsyms_path.c_str());
  }

  std::vector<std::string> getFunctionsByRegex(const std::string& pattern) const {
    DC_LOG_TRACE("KSymCapture: Start getFunctionsByRegex with pattern: %s", pattern.c_str());
    std::vector<std::string> result;
    std::regex re(pattern);
    for (const auto& func : functions_) {
      if (std::regex_search(func, re)) {
        result.push_back(func);
      }
    }
    DC_LOG_DEBUG("KSymCapture: Found %zu functions matching pattern '%s'", result.size(),
                 pattern.c_str());
    DC_LOG_TRACE("KSymCapture: End getFunctionsByRegex");
    return result;
  }
  std::unordered_set<std::string> functions_;

 private:
  void loadFunctions(const std::string& path) {
    DC_LOG_TRACE("KSymCapture: Enter loadFunctions with path: %s", path.c_str());
    std::ifstream file(path);
    if (!file.is_open()) {
      DC_LOG_ERROR("KSymCapture: Failed to open kallsyms file: %s", path.c_str());
      return;
    }
    std::string line;
    size_t count = 0;
    while (std::getline(file, line)) {
      std::istringstream iss(line);
      std::string addr, type, name;
      if (!(iss >> addr >> type >> name)) continue;
      if (type == "T" || type == "t") {
        functions_.insert(name);
        ++count;
      }
    }
    DC_LOG_INFO("KSymCapture: Loaded %zu function symbols from %s", count, path.c_str());
    DC_LOG_TRACE("KSymCapture: Exit loadFunctions");
  }
};

}  // namespace datacrumbs
