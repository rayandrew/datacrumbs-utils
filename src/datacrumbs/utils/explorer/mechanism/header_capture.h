// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/logging.h>
// dependency headers
#include <clang-c/Index.h>  // Use custom logging macros
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
  /**
   * @brief Constructs the extractor with the path to the header file.
   * @param headerPath Path to the header file to analyze.
   *        Example: "/usr/src/linux-headers-6.8.0/include/linux/syscalls.h".
   */
  HeaderFunctionExtractor(const std::string& headerPath);

  /**
   * @brief Destructor to clean up libclang resources.
   */
  ~HeaderFunctionExtractor();

  /**
   * @brief Extracts all function names from the header file.
   * @return Vector of function names as strings.
   * @throws std::runtime_error when translation unit setup fails.
   */
  std::vector<std::string> extractFunctionNames();

  /**
   * @brief Extracts per-function argument capture specifications from the
   * header file.
   * @return Map of function name to argument specification list.
   * @throws std::runtime_error when parsing/AST traversal fails.
   */
  std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>> extractFunctionSignatures();

 private:
  /// Path to the header file being parsed.
  std::string headerPath_;
  /// libclang index object.
  CXIndex index_;
  /// libclang translation unit.
  CXTranslationUnit tu_;
};

}  // namespace datacrumbs

/**
 * Example compilation command:
 * g++ -o extract_functions header_capture_test.cpp `llvm-config --cxxflags
 * --ldflags --system-libs
 * --libs core` -lclang
 */
