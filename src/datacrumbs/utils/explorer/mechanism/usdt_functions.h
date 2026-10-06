// SPDX-License-Identifier: MIT

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>
// std headers
#include <string>
#include <vector>

/**
 * @brief Extracts USDT (User-level Statically Defined Tracing) function names for a provider.
 * Only the "python" provider has a built-in function mapping.
 */
class USDTFunctionExtractor {
 public:
  explicit USDTFunctionExtractor(const std::string& provider) : provider_(provider) {
    DC_LOG_TRACE("USDTFunctionExtractor constructed for provider: %s", provider.c_str());
  }

  /// Returns an empty vector for an unsupported provider.
  std::vector<std::string> extractFunctionNames() const {
    DC_LOG_TRACE("extractFunctionNames() called for provider: %s", provider_.c_str());
    if (provider_ == "python") {
      DC_LOG_DEBUG("Extracting USDT function names for Python provider");
      return {"function__entry"};
    } else {
      DC_LOG_WARN("Provider '%s' is not supported. Returning empty function list.",
                  provider_.c_str());
    }
    return {};
  }

 private:
  std::string provider_;
};