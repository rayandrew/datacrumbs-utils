// SPDX-License-Identifier: MIT

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
 * @brief Extracts function symbol names from an ELF file.
 */
class ElfSymbolExtractor {
 public:
  /**
   * @brief Opens and parses the ELF file at path.
   * @param include_offsets If true, emit symbols as "name:0xoffset".
   */
  explicit ElfSymbolExtractor(const std::string& path, bool include_offsets = false);

  ~ElfSymbolExtractor();

  /**
   * @brief Extracts function symbol names from the ELF file.
   * @throws std::runtime_error if the ELF cannot be parsed.
   */
  std::vector<std::string> extract_symbols();

 private:
  bool is_elf() const;

  int fd_;
  uint8_t* data_;
  size_t size_;
  bool include_offsets_;
  /// 0 for ET_DYN, entry point for ET_EXEC.
  uint64_t base_address_;
  std::unordered_set<std::string> kExcludedFunctions;
};

}  // namespace datacrumbs
