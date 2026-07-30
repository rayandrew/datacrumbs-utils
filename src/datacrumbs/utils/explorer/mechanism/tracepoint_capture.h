// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/singleton.h>
// std headers
#include <dirent.h>
#include <unistd.h>

#include <regex>
#include <string>
#include <unordered_set>
#include <vector>
namespace datacrumbs {

/**
 * @brief Enumerates kernel tracepoints from tracefs (the analog of KSymCapture for kprobes).
 *
 * A tracepoint is identified as "category:name" (e.g. "mlx5:mlx5_fw") -- one subdir per tracepoint
 * under events/<category>/, each holding a "format" file. Regex-matched the same way as kernel
 * symbols, so a probe regex like "^mlx5:" grabs every mlx5 tracepoint.
 */
class TracepointCapture {
 public:
  TracepointCapture() {
    // debugfs mount first, then the standalone tracefs mount; stop at the first that yields entries.
    for (const char* root : {"/sys/kernel/debug/tracing/events", "/sys/kernel/tracing/events"}) {
      loadFrom(root);
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
    // an explicit list (the common case, e.g. "^(mlx5:mlx5_fw|mlx5:mlx5_cmd)$") still works without
    // tracefs. A broad regex like "^mlx5:" only expands when tracefs is readable (root).
    if (result.empty() && tracepoints_.empty()) {
      const std::regex literal(R"([A-Za-z0-9_]+:[A-Za-z0-9_]+)");
      for (auto it = std::sregex_iterator(pattern.begin(), pattern.end(), literal);
           it != std::sregex_iterator(); ++it) {
        result.push_back(it->str());
      }
    }
    DC_LOG_DEBUG("TracepointCapture: %zu tracepoints match '%s'", result.size(), pattern.c_str());
    return result;
  }

  std::unordered_set<std::string> tracepoints_;  // "category:name"

 private:
  void loadFrom(const std::string& root) {
    DIR* categories = ::opendir(root.c_str());
    if (categories == nullptr) return;
    for (struct dirent* cat; (cat = ::readdir(categories)) != nullptr;) {
      if (cat->d_name[0] == '.') continue;
      const std::string cat_path = root + "/" + cat->d_name;
      DIR* events = ::opendir(cat_path.c_str());
      if (events == nullptr) continue;
      for (struct dirent* ev; (ev = ::readdir(events)) != nullptr;) {
        if (ev->d_name[0] == '.') continue;
        const std::string fmt = cat_path + "/" + ev->d_name + "/format";
        if (::access(fmt.c_str(), F_OK) == 0) {
          tracepoints_.insert(std::string(cat->d_name) + ":" + ev->d_name);
        }
      }
      ::closedir(events);
    }
    ::closedir(categories);
  }
};

}  // namespace datacrumbs
