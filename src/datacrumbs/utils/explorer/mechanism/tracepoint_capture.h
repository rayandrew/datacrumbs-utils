// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
// std headers
#include <filesystem>
#include <regex>
#include <string>
#include <unordered_set>
#include <vector>

namespace datacrumbs {

// Enumerates kernel tracepoints from tracefs (the tracepoint analog of KSymCapture). A tracepoint is
// "category:name" (e.g. "sched:sched_switch") -- one dir per tracepoint under events/<category>/,
// each holding a "format" file. Regex-matched like kernel symbols.
class TracepointCapture {
 public:
  TracepointCapture() {
    namespace fs = std::filesystem;
    for (const char* root : {"/sys/kernel/debug/tracing/events", "/sys/kernel/tracing/events"}) {
      std::error_code ec;
      for (const auto& cat : fs::directory_iterator(root, ec)) {
        if (ec || !cat.is_directory()) continue;
        for (const auto& ev : fs::directory_iterator(cat.path(), ec)) {
          if (ec) break;
          if (fs::exists(ev.path() / "format")) {
            tracepoints_.insert(cat.path().filename().string() + ":" + ev.path().filename().string());
          }
        }
      }
      if (!tracepoints_.empty()) break;
    }
    DC_LOG_DEBUG("TracepointCapture: loaded %zu tracepoints", tracepoints_.size());
  }

  std::vector<std::string> getFunctionsByRegex(const std::string& pattern) const {
    std::vector<std::string> result;
    std::regex re(pattern);
    for (const auto& tp : tracepoints_) {
      if (std::regex_search(tp, re)) result.push_back(tp);
    }
    // tracefs is root-only (debugfs 0700) and the configurator usually signs as a normal user, so
    // enumeration is often empty. Fall back to the literal "category:name" tokens in the pattern so
    // an explicit list still works unprivileged; a broad regex only expands when tracefs is readable.
    if (result.empty() && tracepoints_.empty()) {
      static const std::regex literal(R"([A-Za-z0-9_]+:[A-Za-z0-9_]+)");
      for (auto it = std::sregex_iterator(pattern.begin(), pattern.end(), literal);
           it != std::sregex_iterator(); ++it) {
        result.push_back(it->str());
      }
    }
    DC_LOG_DEBUG("TracepointCapture: %zu tracepoints match '%s'", result.size(), pattern.c_str());
    return result;
  }

  std::unordered_set<std::string> tracepoints_;  // "category:name"
};

}  // namespace datacrumbs
