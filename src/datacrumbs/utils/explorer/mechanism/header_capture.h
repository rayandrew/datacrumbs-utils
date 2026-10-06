// SPDX-License-Identifier: MIT

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
// dependency headers
#include <clang-c/Index.h>
// std headers
#include <string>
#include <unordered_map>
#include <vector>

namespace datacrumbs {

/**
 * @brief Extracts function names from a given C/C++ header file using libclang.
 */
class HeaderFunctionExtractor {
 public:
  HeaderFunctionExtractor(const std::string& headerPath);

  ~HeaderFunctionExtractor();

  std::vector<std::string> extractFunctionNames();

  /**
   * @brief Extracts per-function argument capture specifications.
   * @return Map of function name to argument specification list.
   */
  std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>> extractFunctionSignatures();

 private:
  std::string headerPath_;
  CXIndex index_;
  CXTranslationUnit tu_;
};

}  // namespace datacrumbs
