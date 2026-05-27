// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// include first
#include <datacrumbs/datacrumbs_utils_config.h>
// other headers
#include <datacrumbs/common/logging.h>
// std headers
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace datacrumbs {

/**
 * @class ElfSymbolExtractor
 * @brief Extracts symbol names from ELF files.
 */
class ElfSymbolExtractor {
 public:
  /**
   * @brief Constructs the extractor for a given ELF file path.
   * @param path Path to the ELF file.
   *        Example: "/usr/lib/x86_64-linux-gnu/libc.so.6".
   * @param include_offsets Whether symbols should include relative offsets.
   *        Example: true can produce symbols like "foo:0x18".
   */
  explicit ElfSymbolExtractor(const std::string& path, bool include_offsets = false);

  /**
   * @brief Destructor to clean up resources.
   */
  ~ElfSymbolExtractor();

  /**
   * @brief Extracts symbol and demangled symbol names from the ELF file.
   * @return Vector of extracted symbol names.
   * @throws std::runtime_error if the ELF cannot be parsed.
   */
  std::vector<std::string> extract_symbols();

 private:
  /**
   * @brief Checks if the mapped file is a valid ELF file.
   * @return True if ELF, false otherwise.
   */
  bool is_elf() const;

  /// File descriptor for the ELF file.
  int fd_;
  /// Pointer to memory-mapped ELF data.
  uint8_t* data_;
  /// Size of mapped ELF file in bytes.
  size_t size_;
  /// Whether to include offsets in emitted symbol names.
  bool include_offsets_;
  /// Base address for relative symbols (0 for ET_DYN, entry point for ET_EXEC).
  uint64_t base_address_;
  std::unordered_set<std::string>
      kExcludedFunctions;  ///< Set of functions to exclude from extraction.
};

}  // namespace datacrumbs
/**
 * g++ -std=c++14 elf_capture_test.cpp -o elf_capture_test -lelf
 */
