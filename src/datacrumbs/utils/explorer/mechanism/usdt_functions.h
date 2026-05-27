// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>  // Logging macros
// std headers
#include <string>
#include <vector>

/**
 * @brief Extract USDT (User-level Statically Defined Tracing) function names
 * for a provider.
 *
 * Currently, only the "python" provider has built-in function mapping.
 */
class USDTFunctionExtractor {
 public:
  /**
   * @brief Constructor: initializes extractor with provider name.
   * @param provider Provider identifier.
   *        Example: "python".
   */
  explicit USDTFunctionExtractor(const std::string& provider) : provider_(provider) {
    DC_LOG_TRACE("USDTFunctionExtractor constructed for provider: %s", provider.c_str());
  }

  /**
   * @brief Extract function names for the configured provider.
   * @return Vector of function names when provider is supported;
   *         empty vector for unsupported providers.
   */
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
  /// Name of the provider (for example "python").
  std::string provider_;
};