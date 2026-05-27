// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/utils/common/probe_signing_service.h>
#include <datacrumbs/utils/explorer/probe_explorer.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iomanip>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace {

std::string probe_signing_payload(json_object* summary, json_object* categories) {
  json_object* root = json_object_new_object();
  json_object_object_add(root, "summary", json_object_get(summary));
  json_object_object_add(root, "categories", json_object_get(categories));
  json_object_object_add(root, "checksum_algorithm", json_object_new_string("hmac-sha256"));
  const char* payload = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
  const std::string result = payload != nullptr ? payload : "";
  json_object_put(root);
  return result;
}

const char* probe_type_to_string(datacrumbs::ProbeType type) {
  switch (type) {
    case datacrumbs::ProbeType::SYSCALLS:
      return "syscalls";
    case datacrumbs::ProbeType::KPROBE:
      return "kprobe";
    case datacrumbs::ProbeType::UPROBE:
      return "uprobe";
    case datacrumbs::ProbeType::USDT:
      return "usdt";
    case datacrumbs::ProbeType::CUSTOM:
      return "custom";
  }
  return "unknown";
}

const char* capture_type_to_string(datacrumbs::CaptureType type) {
  switch (type) {
    case datacrumbs::CaptureType::HEADER:
      return "header";
    case datacrumbs::CaptureType::BINARY:
      return "binary";
    case datacrumbs::CaptureType::KSYM:
      return "ksym";
    case datacrumbs::CaptureType::USDT:
      return "usdt";
    case datacrumbs::CaptureType::CUSTOM:
      return "custom";
  }
  return "unknown";
}

json_object* string_or_empty_json(const char* value) {
  return json_object_new_string(value ? value : "");
}

std::string trim_copy(std::string value) {
  auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

std::string normalize_spaces(std::string value) {
  value = trim_copy(std::regex_replace(value, std::regex(R"(\s+)"), " "));
  value = std::regex_replace(value, std::regex(R"(\s+\*)"), " *");
  value = std::regex_replace(value, std::regex(R"(\*\s+)"), "* ");
  return value;
}

std::string base_function_name(const std::string& function_name) {
  const auto pos = function_name.find(':');
  return pos == std::string::npos ? function_name : function_name.substr(0, pos);
}

std::string syscall_base_name(const std::string& function_name) {
  std::string base = base_function_name(function_name);
  if (base.rfind("__x64_sys_", 0) == 0) {
    base = base.substr(10);
  } else if (base.rfind("sys_", 0) == 0) {
    base = base.substr(4);
  }
  return base;
}

bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}

unsigned int scalar_size_from_type(const std::string& c_type) {
  if (c_type == "_Bool" || c_type == "bool" || c_type == "char" || c_type == "signed char" ||
      c_type == "unsigned char") {
    return 1;
  }
  if (c_type.find("short") != std::string::npos) return 2;
  if (c_type == "float") return 4;
  if (c_type == "double") return 8;
  if (c_type.find("long double") != std::string::npos) return 8;
  if (c_type.find("long long") != std::string::npos) return 8;
  if (c_type.find("long") != std::string::npos) return 8;
  if (c_type.find("int") != std::string::npos) return 4;
  if (c_type.find("size_t") != std::string::npos || c_type.find("ssize_t") != std::string::npos ||
      c_type.find("off_t") != std::string::npos || c_type.find("mode_t") != std::string::npos ||
      c_type.find("pid_t") != std::string::npos || c_type.find("uid_t") != std::string::npos ||
      c_type.find("gid_t") != std::string::npos) {
    return 8;
  }
  return 8;
}

datacrumbs::ProbeArgCaptureSpec build_arg_spec(unsigned int index, const std::string& label,
                                               const std::string& c_type, bool is_pointer) {
  datacrumbs::ProbeArgCaptureSpec spec;
  spec.index = index;
  spec.label = label.empty() ? ("arg" + std::to_string(index + 1)) : label;
  spec.c_type = normalize_spaces(c_type);
  spec.is_pointer = is_pointer;
  spec.num_bytes = is_pointer
                       ? (is_char_pointer_type(spec.c_type) ? DATACRUMBS_MAX_CAPTURE_BYTES : 8U)
                       : scalar_size_from_type(spec.c_type);
  return spec;
}

std::string shell_escape(const std::string& value) {
  std::string escaped = "'";
  for (char ch : value) {
    if (ch == '\'') {
      escaped += "'\\''";
    } else {
      escaped.push_back(ch);
    }
  }
  escaped += "'";
  return escaped;
}

std::string run_command(const std::string& command) {
  std::array<char, 4096> buffer{};
  std::string output;
  FILE* pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    return output;
  }
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    output += buffer.data();
  }
  pclose(pipe);
  return output;
}

std::string extract_quoted_value(const std::string& line) {
  const auto first_quote = line.find('"');
  if (first_quote == std::string::npos) return "";
  const auto second_quote = line.find('"', first_quote + 1);
  if (second_quote == std::string::npos) return "";
  return line.substr(first_quote + 1, second_quote - first_quote - 1);
}

std::string format_progress(size_t completed, size_t total) {
  std::ostringstream stream;
  const double percent = total == 0 ? 100.0 : (100.0 * static_cast<double>(completed) / total);
  stream << completed << "/" << total << " (" << std::fixed << std::setprecision(1) << percent
         << "%)";
  return stream.str();
}

std::string join_pending_probe_names(
    const std::vector<std::shared_ptr<datacrumbs::CaptureProbe>>& pending_probes,
    size_t max_names = 4) {
  if (pending_probes.empty()) return "none";
  std::ostringstream stream;
  for (size_t i = 0; i < pending_probes.size() && i < max_names; ++i) {
    if (i > 0) stream << ", ";
    stream << pending_probes[i]->name;
  }
  if (pending_probes.size() > max_names) {
    stream << " +" << (pending_probes.size() - max_names) << " more";
  }
  return stream.str();
}

bool should_emit_progress_log(std::chrono::steady_clock::time_point now,
                              std::chrono::steady_clock::time_point* last_report,
                              std::chrono::seconds interval, bool force) {
  if (force || (now - *last_report) >= interval) {
    *last_report = now;
    return true;
  }
  return false;
}

bool is_openmpi_library(const std::string& path) {
  return std::filesystem::path(path).filename() == "libmpi.so";
}

bool should_use_default_mpi_api_filter(const datacrumbs::CaptureProbe& capture_probe,
                                       const std::string& binary_path) {
  if (!is_openmpi_library(binary_path)) return false;
  const std::string regex = trim_copy(capture_probe.regex);
  return regex.empty() || regex == ".*";
}

bool is_supported_runtime_probe_type(datacrumbs::ProbeType type) {
  switch (type) {
    case datacrumbs::ProbeType::KPROBE:
    case datacrumbs::ProbeType::UPROBE:
    case datacrumbs::ProbeType::SYSCALLS:
    case datacrumbs::ProbeType::USDT:
      return true;
    default:
      return false;
  }
}

size_t count_supported_runtime_functions(
    const std::vector<std::shared_ptr<datacrumbs::Probe>>& probes) {
  size_t total = 0;
  for (const auto& probe : probes) {
    if (probe && is_supported_runtime_probe_type(probe->type)) {
      total += probe->functions.size();
    }
  }
  return total;
}

bool is_public_mpi_symbol(const std::string& function_name) {
  const std::string base_name = base_function_name(function_name);
  return base_name.rfind("MPI_", 0) == 0 || base_name.rfind("PMPI_", 0) == 0 ||
         base_name.rfind("MPIX_", 0) == 0;
}

std::string find_openmpi_header(const std::string& binary_path) {
  const auto lib_dir = std::filesystem::path(binary_path).parent_path();
  const auto include_dir = lib_dir.parent_path() / "include";
  const auto mpi_header = include_dir / "mpi.h";
  if (std::filesystem::exists(mpi_header)) {
    return mpi_header.string();
  }
  return "";
}

const std::vector<datacrumbs::ProbeArgCaptureSpec>* lookup_function_signature(
    const std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>& signatures,
    datacrumbs::ProbeType probe_type, const std::string& function_name) {
  auto find_exact =
      [&signatures](const std::string& key) -> const std::vector<datacrumbs::ProbeArgCaptureSpec>* {
    const auto it = signatures.find(key);
    return it == signatures.end() ? nullptr : &it->second;
  };

  if (const auto* exact = find_exact(function_name)) return exact;

  const std::string base_name = base_function_name(function_name);
  if (const auto* base = find_exact(base_name)) return base;

  if (probe_type == datacrumbs::ProbeType::SYSCALLS) {
    if (const auto* prefixed = find_exact("sys_" + base_name)) return prefixed;
    if (const auto* x64_prefixed = find_exact("__x64_sys_" + base_name)) return x64_prefixed;
  }
  return nullptr;
}

std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>
extract_dwarf_function_signatures(const std::string& elf_path,
                                  const std::vector<std::string>& function_names = {}) {
  std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>> signatures;
  std::unordered_set<std::string> target_names;
  for (const auto& function_name : function_names) {
    target_names.insert(base_function_name(function_name));
  }
  const bool filter_to_target_names = !target_names.empty();

  const std::string output =
      run_command("readelf --debug-dump=info " + shell_escape(elf_path) + " 2>/dev/null");
  if (output.empty()) {
    return signatures;
  }

  struct ParameterState {
    int level = -1;
    std::string name;
    std::string c_type;
  };
  struct FunctionState {
    int level = -1;
    std::string name;
    bool is_declaration = false;
    std::vector<datacrumbs::ProbeArgCaptureSpec> args;
  };

  auto finalize_parameter = [](ParameterState* param, FunctionState* function) {
    if (param->level < 0 || function->level < 0) return;
    const unsigned int index = function->args.size();
    const std::string c_type = param->c_type.empty() ? "unsigned long long" : param->c_type;
    const bool is_pointer = c_type.find('*') != std::string::npos;
    function->args.push_back(build_arg_spec(index, param->name, c_type, is_pointer));
    *param = ParameterState{};
  };

  auto finalize_function = [&signatures](FunctionState* function) {
    if (function->level < 0 || function->name.empty()) return;
    auto& slot = signatures[function->name];
    if (slot.empty() || (!function->args.empty() && slot.empty())) {
      slot = function->args;
    } else if (!function->args.empty()) {
      slot = function->args;
    }
    *function = FunctionState{};
  };

  std::istringstream stream(output);
  std::string line;
  FunctionState current_function;
  ParameterState current_parameter;
  bool current_function_needed = !filter_to_target_names;
  while (std::getline(stream, line)) {
    const auto abbrev_pos = line.find("Abbrev Number:");
    if (abbrev_pos != std::string::npos) {
      int level = -1;
      const auto first_angle = line.find('<');
      if (first_angle != std::string::npos) {
        const auto second_angle = line.find('>', first_angle + 1);
        if (second_angle != std::string::npos) {
          const std::string level_text =
              line.substr(first_angle + 1, second_angle - first_angle - 1);
          if (!level_text.empty()) {
            level = std::atoi(level_text.c_str());
          }
        }
      }

      std::string tag;
      const auto tag_open = line.rfind('(');
      const auto tag_close = line.rfind(')');
      if (tag_open != std::string::npos && tag_close != std::string::npos && tag_close > tag_open) {
        tag = line.substr(tag_open + 1, tag_close - tag_open - 1);
      }
      if (level < 0 || tag.empty()) {
        continue;
      }

      if (current_parameter.level >= 0 && level <= current_parameter.level) {
        finalize_parameter(&current_parameter, &current_function);
      }
      if (current_function.level >= 0 && level <= current_function.level) {
        finalize_function(&current_function);
      }

      if (tag == "DW_TAG_subprogram") {
        current_function = FunctionState{};
        current_function.level = level;
        current_function_needed = !filter_to_target_names;
      } else if (tag == "DW_TAG_formal_parameter" && current_function.level >= 0) {
        if (!current_function_needed) {
          continue;
        }
        current_parameter = ParameterState{};
        current_parameter.level = level;
      }
      continue;
    }

    if (current_parameter.level >= 0) {
      if (line.find("DW_AT_name") != std::string::npos) {
        current_parameter.name = extract_quoted_value(line);
      } else if (line.find("DW_AT_type") != std::string::npos) {
        current_parameter.c_type = normalize_spaces(extract_quoted_value(line));
      }
      continue;
    }

    if (current_function.level >= 0) {
      if (line.find("DW_AT_name") != std::string::npos) {
        current_function.name = extract_quoted_value(line);
        current_function_needed = !filter_to_target_names ||
                                  target_names.find(current_function.name) != target_names.end();
      } else if (line.find("DW_AT_declaration") != std::string::npos &&
                 line.find("(true)") != std::string::npos) {
        current_function.is_declaration = true;
      }
    }
  }

  finalize_parameter(&current_parameter, &current_function);
  finalize_function(&current_function);
  return signatures;
}

std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>
extract_source_backed_dwarf_function_signatures(const std::string& elf_path,
                                                const std::vector<std::string>& function_names) {
  std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>> signatures;
  std::unordered_set<std::string> source_paths;
  std::unordered_set<std::string> base_names;
  for (const auto& function_name : function_names) {
    base_names.insert(base_function_name(function_name));
  }

  if (base_names.empty()) {
    return signatures;
  }

  DC_LOG_INFO("[ProbeExplorer] Single-pass DWARF source scan for %s (%zu symbols)",
              elf_path.c_str(), base_names.size());
  const std::string output =
      run_command("llvm-dwarfdump --debug-info " + shell_escape(elf_path) + " 2>/dev/null");
  if (output.empty()) {
    return signatures;
  }

  std::istringstream stream(output);
  std::string line;
  std::string current_function_name;
  bool current_function_needed = false;
  while (std::getline(stream, line)) {
    if (line.find("DW_TAG_subprogram") != std::string::npos) {
      current_function_name.clear();
      current_function_needed = false;
      continue;
    }

    if (line.find("DW_AT_name") != std::string::npos) {
      current_function_name = extract_quoted_value(line);
      current_function_needed = base_names.find(current_function_name) != base_names.end();
      continue;
    }

    if (!current_function_needed) {
      continue;
    }

    if (line.find("DW_AT_decl_file") != std::string::npos) {
      const std::string path = extract_quoted_value(line);
      if (std::filesystem::exists(path)) {
        source_paths.insert(path);
      }
    }
  }

  DC_LOG_INFO("[ProbeExplorer] DWARF source scan found %zu source files for %s",
              source_paths.size(), elf_path.c_str());
  for (const auto& source_path : source_paths) {
    datacrumbs::HeaderFunctionExtractor extractor(source_path);
    auto file_signatures = extractor.extractFunctionSignatures();
    signatures.insert(file_signatures.begin(), file_signatures.end());
  }
  return signatures;
}

std::vector<std::string> split_arguments(const std::string& arg_list) {
  std::vector<std::string> arguments;
  std::string current;
  int depth = 0;
  for (char ch : arg_list) {
    if (ch == '(') ++depth;
    if (ch == ')') --depth;
    if (ch == ',' && depth == 0) {
      arguments.push_back(trim_copy(current));
      current.clear();
      continue;
    }
    current.push_back(ch);
  }
  if (!trim_copy(current).empty()) {
    arguments.push_back(trim_copy(current));
  }
  return arguments;
}

std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>
extract_header_prototype_signatures(const std::string& header_path) {
  std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>> signatures;
  std::ifstream input(header_path);
  if (!input.is_open()) {
    return signatures;
  }

  std::string line;
  std::string statement;
  const std::regex prototype_re(R"(\b([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*;)");
  while (std::getline(input, line)) {
    const auto comment_pos = line.find("//");
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }
    statement += " " + trim_copy(line);
    if (line.find(';') == std::string::npos) {
      continue;
    }

    const std::string normalized = normalize_spaces(statement);
    statement.clear();
    if (normalized.find("sys_") == std::string::npos) {
      continue;
    }

    std::smatch match;
    if (!std::regex_search(normalized, match, prototype_re)) {
      continue;
    }

    const std::string function_name = match[1].str();
    const auto arguments = split_arguments(match[2].str());
    std::vector<datacrumbs::ProbeArgCaptureSpec> arg_specs;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
      std::string argument = normalize_spaces(arguments[index]);
      if (argument.empty() || argument == "void") {
        continue;
      }

      argument = std::regex_replace(argument, std::regex(R"(\b__user\b)"), "");
      argument = std::regex_replace(argument, std::regex(R"(\b__force\b)"), "");
      argument = std::regex_replace(argument, std::regex(R"(\b__iomem\b)"), "");
      argument = normalize_spaces(argument);

      std::smatch arg_match;
      std::string label = "arg" + std::to_string(index + 1);
      std::string c_type = argument;
      if (std::regex_match(argument, arg_match, std::regex(R"((.+?)([A-Za-z_][A-Za-z0-9_]*)$)"))) {
        label = arg_match[2].str();
        c_type = normalize_spaces(arg_match[1].str());
      }

      const bool is_pointer = c_type.find('*') != std::string::npos;
      arg_specs.push_back(
          build_arg_spec(static_cast<unsigned int>(index), label, c_type, is_pointer));
    }
    signatures[function_name] = std::move(arg_specs);
  }
  return signatures;
}

struct BtfTypeDef {
  std::string kind;
  std::string name;
  int target_type_id = 0;
  unsigned int size = 0;
  std::vector<std::pair<std::string, int>> params;
};

std::string resolve_btf_type_name(const std::unordered_map<int, BtfTypeDef>& types, int type_id,
                                  std::set<int>* seen) {
  if (type_id == 0 || !seen->insert(type_id).second) return "void";
  const auto it = types.find(type_id);
  if (it == types.end()) return "unsigned long long";
  const auto& type = it->second;

  if (type.kind == "INT" || type.kind == "ENUM") return type.name.empty() ? "int" : type.name;
  if (type.kind == "STRUCT") return type.name.empty() ? "struct" : "struct " + type.name;
  if (type.kind == "UNION") return type.name.empty() ? "union" : "union " + type.name;
  if (type.kind == "TYPEDEF")
    return type.name.empty() ? resolve_btf_type_name(types, type.target_type_id, seen) : type.name;
  if (type.kind == "CONST")
    return "const " + resolve_btf_type_name(types, type.target_type_id, seen);
  if (type.kind == "VOLATILE" || type.kind == "RESTRICT") {
    return resolve_btf_type_name(types, type.target_type_id, seen);
  }
  if (type.kind == "PTR")
    return normalize_spaces(resolve_btf_type_name(types, type.target_type_id, seen) + " *");
  if (type.kind == "ARRAY") {
    return normalize_spaces(resolve_btf_type_name(types, type.target_type_id, seen) + " *");
  }
  if (type.kind == "FWD") return type.name.empty() ? "struct" : "struct " + type.name;
  return type.name.empty() ? "unsigned long long" : type.name;
}

unsigned int resolve_btf_type_size(const std::unordered_map<int, BtfTypeDef>& types, int type_id,
                                   std::set<int>* seen) {
  if (type_id == 0 || !seen->insert(type_id).second) return 0;
  const auto it = types.find(type_id);
  if (it == types.end()) return 8;
  const auto& type = it->second;
  if (type.kind == "PTR" || type.kind == "ARRAY") return 8;
  if (type.kind == "INT" || type.kind == "ENUM" || type.kind == "STRUCT" || type.kind == "UNION") {
    return type.size;
  }
  if (type.kind == "TYPEDEF" || type.kind == "CONST" || type.kind == "VOLATILE" ||
      type.kind == "RESTRICT") {
    return resolve_btf_type_size(types, type.target_type_id, seen);
  }
  return type.size > 0 ? type.size : 8;
}

std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>
extract_btf_function_signatures(const std::string& btf_path) {
  static std::mutex cache_mutex;
  static std::condition_variable cache_cv;
  static std::unordered_map<
      std::string, std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>>
      cache;
  static std::unordered_set<std::string> in_progress_paths;

  {
    std::unique_lock<std::mutex> lock(cache_mutex);
    while (true) {
      const auto cached = cache.find(btf_path);
      if (cached != cache.end()) {
        DC_LOG_INFO("[ProbeExplorer] Reusing cached BTF signatures from %s", btf_path.c_str());
        return cached->second;
      }
      if (in_progress_paths.insert(btf_path).second) {
        break;
      }
      cache_cv.wait(lock);
    }
  }

  DC_LOG_INFO("[ProbeExplorer] Loading BTF signatures from %s", btf_path.c_str());
  std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>> signatures;
  const std::string output =
      run_command("bpftool btf dump file " + shell_escape(btf_path) + " format raw 2>/dev/null");
  if (output.empty()) {
    return signatures;
  }

  const std::regex type_re(
      R"(^\[(\d+)\]\s+([A-Z_]+)\s+'([^']*)'(?:\s+type_id=(\d+))?(?:\s+ret_type_id=(\d+))?(?:\s+vlen=(\d+))?(?:\s+size=(\d+))?.*)");
  const std::regex param_re(R"(^\s*'([^']*)'\s+type_id=(\d+).*)");

  std::unordered_map<int, BtfTypeDef> types;
  std::unordered_map<std::string, int> function_proto_ids;
  int current_type_id = -1;
  std::istringstream stream(output);
  std::string line;
  while (std::getline(stream, line)) {
    std::smatch match;
    if (std::regex_match(line, match, type_re)) {
      current_type_id = std::stoi(match[1].str());
      BtfTypeDef type;
      type.kind = match[2].str();
      type.name = match[3].str();
      if (match[4].matched) type.target_type_id = std::stoi(match[4].str());
      if (match[7].matched) type.size = static_cast<unsigned int>(std::stoul(match[7].str()));
      types[current_type_id] = type;
      if (type.kind == "FUNC" && !type.name.empty() && type.target_type_id > 0) {
        function_proto_ids[type.name] = type.target_type_id;
      }
      continue;
    }
    if (current_type_id < 0) continue;
    auto type_it = types.find(current_type_id);
    if (type_it == types.end()) continue;

    if (type_it->second.kind == "FUNC_PROTO") {
      std::smatch param_match;
      if (std::regex_match(line, param_match, param_re)) {
        type_it->second.params.emplace_back(param_match[1].str(), std::stoi(param_match[2].str()));
      }
    }
  }

  for (const auto& [function_name, proto_id] : function_proto_ids) {
    const auto proto_it = types.find(proto_id);
    if (proto_it == types.end()) continue;
    std::vector<datacrumbs::ProbeArgCaptureSpec> arg_specs;
    for (std::size_t index = 0; index < proto_it->second.params.size(); ++index) {
      const auto& [label, type_id] = proto_it->second.params[index];
      std::set<int> seen_name;
      const std::string c_type =
          normalize_spaces(resolve_btf_type_name(types, type_id, &seen_name));
      std::set<int> seen_size;
      unsigned int num_bytes = resolve_btf_type_size(types, type_id, &seen_size);
      const bool is_pointer = c_type.find('*') != std::string::npos;
      auto spec = build_arg_spec(static_cast<unsigned int>(index), label, c_type, is_pointer);
      if (!is_pointer) {
        spec.num_bytes = std::min<unsigned int>(num_bytes > 0 ? num_bytes : spec.num_bytes, 8U);
      }
      arg_specs.push_back(std::move(spec));
    }
    signatures[function_name] = std::move(arg_specs);
  }

  {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache[btf_path] = signatures;
    in_progress_paths.erase(btf_path);
  }
  cache_cv.notify_all();
  DC_LOG_INFO("[ProbeExplorer] Loaded %zu BTF function signatures from %s", signatures.size(),
              btf_path.c_str());
  return signatures;
}

void attach_discovered_function_signatures(
    datacrumbs::Probe* probe, datacrumbs::ProbeType probe_type,
    const std::vector<std::string>& function_names,
    const std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>&
        discovered) {
  for (const auto& function_name : function_names) {
    const auto* arg_specs = lookup_function_signature(discovered, probe_type, function_name);
    if (arg_specs != nullptr) {
      probe->function_arguments[function_name] = *arg_specs;
    }
  }
}

json_object* capture_probe_to_json(const std::shared_ptr<datacrumbs::CaptureProbe>& capture_probe) {
  json_object* config = json_object_new_object();
  json_object_object_add(config, "name", json_object_new_string(capture_probe->name.c_str()));
  json_object_object_add(config, "capture_type",
                         json_object_new_string(capture_type_to_string(capture_probe->type)));
  json_object_object_add(config, "probe_type",
                         json_object_new_string(probe_type_to_string(capture_probe->probe_type)));
  json_object_object_add(config, "regex", json_object_new_string(capture_probe->regex.c_str()));
  json_object_object_add(config, "enable_explorer",
                         json_object_new_boolean(capture_probe->enable_explorer));
  if (!capture_probe->function_arguments.empty()) {
    json_object* function_arguments = json_object_new_object();
    for (const auto& [function_name, arg_specs] : capture_probe->function_arguments) {
      json_object* arg_list = json_object_new_array();
      for (const auto& arg_spec : arg_specs) {
        json_object_array_add(arg_list, arg_spec.toJson());
      }
      json_object_object_add(function_arguments, function_name.c_str(), arg_list);
    }
    json_object_object_add(config, "function_arguments", function_arguments);
  }

  switch (capture_probe->type) {
    case datacrumbs::CaptureType::HEADER: {
      auto header_probe = std::static_pointer_cast<datacrumbs::HeaderCaptureProbe>(capture_probe);
      json_object_object_add(config, "file", json_object_new_string(header_probe->file.c_str()));
      break;
    }
    case datacrumbs::CaptureType::BINARY: {
      auto binary_probe = std::static_pointer_cast<datacrumbs::BinaryCaptureProbe>(capture_probe);
      json_object_object_add(config, "file", json_object_new_string(binary_probe->file.c_str()));
      json_object_object_add(config, "include_offsets",
                             json_object_new_boolean(binary_probe->include_offsets));
      break;
    }
    case datacrumbs::CaptureType::USDT: {
      auto usdt_probe = std::static_pointer_cast<datacrumbs::USDTCaptureProbe>(capture_probe);
      json_object_object_add(config, "binary_path",
                             json_object_new_string(usdt_probe->binary_path.c_str()));
      json_object_object_add(config, "provider",
                             json_object_new_string(usdt_probe->provider.c_str()));
      break;
    }
    case datacrumbs::CaptureType::CUSTOM: {
      auto custom_probe = std::static_pointer_cast<datacrumbs::CustomCaptureProbe>(capture_probe);
      json_object_object_add(config, "file",
                             json_object_new_string(custom_probe->bpf_file.c_str()));
      json_object_object_add(config, "probes",
                             json_object_new_string(custom_probe->probe_file.c_str()));
      json_object_object_add(config, "start_event_id",
                             json_object_new_int64(custom_probe->start_event_id));
      json_object_object_add(config, "process_header",
                             json_object_new_string(custom_probe->process_header.c_str()));
      json_object_object_add(config, "event_type", json_object_new_int64(custom_probe->event_type));
      break;
    }
    case datacrumbs::CaptureType::KSYM:
      break;
  }

  return config;
}

json_object* configured_environment_to_json() {
  static const char* kEnvVars[] = {
      "DATACRUMBS_VERSION",
      "DATACRUMBS_LIB_VERSION",
      "DATACRUMBS_INSTALL_HOST",
      "DATACRUMBS_INSTALL_USER",
      "DATACRUMBS_INSTALL_PREFIX",
      "DATACRUMBS_INSTALL_BIN_DIR",
      "DATACRUMBS_INSTALL_SBIN_DIR",
      "DATACRUMBS_INSTALL_LIB_DIR",
      "DATACRUMBS_INSTALL_LIBEXEC_DIR",
      "DATACRUMBS_INSTALL_ETC_DIR",
      "DATACRUMBS_INSTALL_CONFIGS_DIR",
      "DATACRUMBS_INSTALL_DATA_DIR",
      "DATACRUMBS_INSTALL_MODULES_DIR",
      "DATACRUMBS_INSTALL_PROBE_OBJECTS_DIR",
      "DATACRUMBS_INSTALL_COMPOSABLE_DIR",
      "DATACRUMBS_INSTALL_COMPOSE_BIN",
      "DATACRUMBS_INSTALL_RUNSTATEDIR",
      "DATACRUMBS_CLIENT_LIB",
      "DATACRUMBS_CLIENT_BIN",
      "DATACRUMBS_TRACE_DIR_PATTERN",
      "DATACRUMBS_JOB_SCHEDULER",
      "DATACRUMBS_JOB_ID_VAR",
      "DATACRUMBS_SERVER_LOAD_TIMEOUT",
      "DATACRUMBS_SERVER_RUN_DIR",
      "DATACRUMBS_SERVER_RUN_ID_FILE",
      "DATACRUMBS_SERVER_RUN_ID",
      "DATACRUMBS_SERVER_PID_FILE",
      "DATACRUMBS_SERVER_SYSTEMD_PID_FILE",
      "DATACRUMBS_SERVER_READY_FILE",
      "DATACRUMBS_SERVER_STATUS_FILE",
      "DATACRUMBS_SERVER_ENV_FILE",
      "DATACRUMBS_SERVER_MODULE",
      "DATACRUMBS_SERVER_PREAMBLE",
      "DATACRUMBS_LOG_DIR",
      "DATACRUMBS_LOG_FILE",
      "DATACRUMBS_USER",
      "DATACRUMBS_TRACE_DIR",
  };

  json_object* env_json = json_object_new_object();
  for (const char* env_var : kEnvVars) {
    json_object_object_add(env_json, env_var, string_or_empty_json(std::getenv(env_var)));
  }
  return env_json;
}

}  // namespace

namespace datacrumbs {

// Constructor for ProbeExplorer, initializes the configuration manager
// singleton
ProbeExplorer::ProbeExplorer(int argc, char** argv, bool load_capture_probes) {
  DC_LOG_TRACE("ProbeExplorer::ProbeExplorer - start");
  configManager_ =
      datacrumbs::Singleton<ConfigurationManager>::get_instance(argc, argv, load_capture_probes);
  has_invalid_probes_ = false;
  DC_LOG_TRACE("ProbeExplorer::ProbeExplorer - end");
}
std::unordered_map<std::string, std::unordered_set<std::string>>
ProbeExplorer::Extract_Exclusions() {
  DC_LOG_TRACE("ProbeExplorer::validate_exclusion_file - start");
  std::unordered_map<std::string, std::unordered_set<std::string>> exclusionMap;
  if (!configManager_->probe_exclusion_file_path.empty() &&
      std::filesystem::exists(configManager_->probe_exclusion_file_path)) {
    std::ifstream ifs(configManager_->probe_exclusion_file_path);
    if (ifs.is_open()) {
      std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
      json_object* jobj = json_tokener_parse(content.c_str());
      if (jobj && json_object_get_type(jobj) == json_type_array) {
        int arr_len = json_object_array_length(jobj);
        for (int i = 0; i < arr_len; ++i) {
          json_object* probe_obj = json_object_array_get_idx(jobj, i);
          if (!probe_obj) {
            DC_LOG_WARN(
                "the %dth element of exclusion file is missing (null "
                "pointer returned).",
                i);
            continue;
          }
          if (json_object_get_type(probe_obj) == json_type_null) {
            DC_LOG_WARN("exclusion file contains explicit JSON null at %dth element.", i);
            continue;
          }
          json_object* name_obj = nullptr;
          json_object* funcs_obj = nullptr;
          if (json_object_object_get_ex(probe_obj, "name", &name_obj) &&
              json_object_object_get_ex(probe_obj, "functions", &funcs_obj) &&
              json_object_get_type(name_obj) == json_type_string &&
              json_object_get_type(funcs_obj) == json_type_array) {
            std::string probe_name = json_object_get_string(name_obj);
            std::unordered_set<std::string> func_set;
            int func_len = json_object_array_length(funcs_obj);
            for (int j = 0; j < func_len; ++j) {
              json_object* func_obj = json_object_array_get_idx(funcs_obj, j);

              if (func_obj && json_object_get_type(func_obj) == json_type_string) {
                // check the function name
                std::string func_name = json_object_get_string(func_obj);
                if (func_name.find('/') != std::string::npos ||
                    func_name.find('\\') != std::string::npos ||
                    func_name.find(' ') != std::string::npos) {
                  DC_LOG_WARN(
                      "Exclusion file contains invalid function name "
                      "'%s' for probe '%s'. Skipping "
                      "this function.",
                      func_name.c_str(), probe_name.c_str());
                  continue;
                }
                func_set.insert(json_object_get_string(func_obj));
              }
            }
            exclusionMap[probe_name] = std::move(func_set);
          } else {
            DC_LOG_WARN(
                "Exclusion file entry at index %d is missing 'name' or "
                "'functions' field, or they "
                "are of incorrect type.",
                i);
          }
        }
      } else {
        DC_LOG_WARN("Exclusion file is not a valid JSON array.");
      }
      if (jobj) json_object_put(jobj);
    } else {
      DC_LOG_ERROR("Failed to open exclusion probes file: %s",
                   configManager_->probe_exclusion_file_path.string().c_str());
    }
  }
  return exclusionMap;

  DC_LOG_TRACE("ProbeExplorer::validate_exclusion_file - end");
}
// Extracts probes based on configuration and exclusion file
std::vector<std::shared_ptr<Probe>> ProbeExplorer::extractProbes() {
  DC_LOG_TRACE("ProbeExplorer::extractProbes - start");
  auto exclusionMap = Extract_Exclusions();

  // Log the contents of the exclusion map for debugging
  DC_LOG_DEBUG("Exclusion Map Contents:");
  for (const auto& [probe_name, func_set] : exclusionMap) {
    DC_LOG_DEBUG("Probe: %s", probe_name.c_str());
    for (const auto& func : func_set) {
      DC_LOG_DEBUG("  Excluded Function: %s", func.c_str());
    }
  }

  // Load additional invalid probes from file if specified
  if (!configManager_->probe_invalid_file_path.empty() &&
      std::filesystem::exists(configManager_->probe_invalid_file_path)) {
    std::ifstream ifs(configManager_->probe_invalid_file_path);
    if (ifs.is_open()) {
      std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
      json_object* jobj = json_tokener_parse(content.c_str());
      if (jobj && json_object_get_type(jobj) == json_type_array) {
        int arr_len = json_object_array_length(jobj);
        for (int i = 0; i < arr_len; ++i) {
          json_object* probe_obj = json_object_array_get_idx(jobj, i);
          if (!probe_obj) continue;
          json_object* name_obj = nullptr;
          json_object* funcs_obj = nullptr;
          if (json_object_object_get_ex(probe_obj, "name", &name_obj) &&
              json_object_object_get_ex(probe_obj, "functions", &funcs_obj) &&
              json_object_get_type(name_obj) == json_type_string &&
              json_object_get_type(funcs_obj) == json_type_array) {
            std::string probe_name = json_object_get_string(name_obj);
            std::unordered_set<std::string> func_set;
            int func_len = json_object_array_length(funcs_obj);
            for (int j = 0; j < func_len; ++j) {
              json_object* func_obj = json_object_array_get_idx(funcs_obj, j);
              if (func_obj && json_object_get_type(func_obj) == json_type_string) {
                func_set.insert(json_object_get_string(func_obj));
              }
            }
            // Merge with existing exclusion map if present
            auto& existing_set = exclusionMap[probe_name];
            existing_set.insert(func_set.begin(), func_set.end());
          }
        }
      }
      if (jobj) json_object_put(jobj);
    } else {
      DC_LOG_ERROR("Failed to open invalid probes file: %s",
                   configManager_->probe_invalid_file_path.string().c_str());
    }
  }

  auto existingProbesMap = loadExistingProbes();

  static std::unordered_set<std::string> global_function_names;
  std::vector<std::shared_ptr<Probe>> probes;
  struct ExtractionResult {
    std::vector<std::string> function_names;
    std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>
        discovered_function_signatures;
    bool invalid = false;
  };
  struct PendingExtraction {
    std::shared_ptr<CaptureProbe> capture_probe;
    std::shared_ptr<Probe> probe;
    std::future<ExtractionResult> future;
  };

  std::vector<PendingExtraction> pending_extractions;
  pending_extractions.reserve(configManager_->capture_probes.size());

  bool needs_vmlinux_btf = false;
  for (const auto& capture_probe : configManager_->capture_probes) {
    if (capture_probe->type == CaptureType::KSYM) {
      needs_vmlinux_btf = true;
      break;
    }
  }

  std::shared_future<std::unordered_map<std::string, std::vector<datacrumbs::ProbeArgCaptureSpec>>>
      vmlinux_btf_future;
  if (needs_vmlinux_btf) {
    DC_LOG_INFO("[ProbeExplorer] Prewarming vmlinux BTF signatures in parallel");
    vmlinux_btf_future = std::async(std::launch::async, []() {
                           return extract_btf_function_signatures("/sys/kernel/btf/vmlinux");
                         }).share();
  }

  auto launch_extraction =
      [vmlinux_btf_future](const std::shared_ptr<CaptureProbe>& capture_probe,
                           const std::shared_ptr<Probe>& probe) -> std::future<ExtractionResult> {
    return std::async(std::launch::async, [capture_probe, probe, vmlinux_btf_future]() mutable {
      ExtractionResult result;

      switch (capture_probe->type) {
        case CaptureType::HEADER:
          DC_LOG_INFO("Extracting header probes...");
          if (auto headerProbe = std::static_pointer_cast<HeaderCaptureProbe>(capture_probe)) {
            DC_LOG_DEBUG("Header Name: %s", headerProbe->file.c_str());
            HeaderFunctionExtractor extractor(headerProbe->file);
            result.function_names = extractor.extractFunctionNames();
            result.discovered_function_signatures = extractor.extractFunctionSignatures();
            auto prototype_signatures = extract_header_prototype_signatures(headerProbe->file);
            for (auto& [function_name, arg_specs] : prototype_signatures) {
              result.discovered_function_signatures[function_name] = std::move(arg_specs);
            }
          }
          if (capture_probe->probe_type == ProbeType::KPROBE ||
              capture_probe->probe_type == ProbeType::SYSCALLS) {
            DC_LOG_DEBUG("Filtering header symbols against /proc/kallsyms...");
            const auto& ksym_functions =
                datacrumbs::Singleton<KSymCapture>::get_instance()->functions_;
            std::vector<std::string> valid_function_names;
            for (const auto& name : result.function_names) {
              const std::string base = capture_probe->probe_type == ProbeType::SYSCALLS
                                           ? syscall_base_name(name)
                                           : base_function_name(name);
              const bool found =
                  ksym_functions.count(base) || (capture_probe->probe_type == ProbeType::SYSCALLS &&
                                                 (ksym_functions.count("sys_" + base) ||
                                                  ksym_functions.count("__x64_sys_" + base)));
              if (found) {
                valid_function_names.push_back(name);
              } else {
                DC_LOG_WARN("Function '%s' not found in KSymCapture functions, skipping.",
                            name.c_str());
              }
            }
            result.function_names = std::move(valid_function_names);
          }
          break;
        case CaptureType::BINARY:
          DC_LOG_INFO("Extracting binary probes...");
          if (auto binaryProbe = std::static_pointer_cast<BinaryCaptureProbe>(capture_probe)) {
            DC_LOG_DEBUG("Binary Path: %s", binaryProbe->file.c_str());
            result.function_names =
                ElfSymbolExtractor(binaryProbe->file, binaryProbe->include_offsets)
                    .extract_symbols();
            if (capture_probe->probe_type == ProbeType::UPROBE) {
              if (should_use_default_mpi_api_filter(*capture_probe, binaryProbe->file)) {
                std::vector<std::string> filtered_function_names;
                filtered_function_names.reserve(result.function_names.size());
                for (const auto& name : result.function_names) {
                  if (is_public_mpi_symbol(name)) {
                    filtered_function_names.push_back(name);
                  }
                }
                DC_LOG_INFO(
                    "[ProbeExplorer] Applied default MPI public API "
                    "filter to %s: %zu -> %zu symbols",
                    binaryProbe->file.c_str(), result.function_names.size(),
                    filtered_function_names.size());
                result.function_names = std::move(filtered_function_names);
              }

              result.discovered_function_signatures =
                  extract_source_backed_dwarf_function_signatures(binaryProbe->file,
                                                                  result.function_names);
              bool merged_mpi_header_signatures = false;
              if (result.discovered_function_signatures.empty()) {
                const std::string mpi_header = find_openmpi_header(binaryProbe->file);
                if (!mpi_header.empty()) {
                  DC_LOG_INFO("[ProbeExplorer] Loading MPI signatures from %s", mpi_header.c_str());
                  auto mpi_header_signatures = extract_header_prototype_signatures(mpi_header);
                  if (!mpi_header_signatures.empty()) {
                    result.discovered_function_signatures.insert(mpi_header_signatures.begin(),
                                                                 mpi_header_signatures.end());
                    merged_mpi_header_signatures = true;
                  }
                }
              }
              DC_LOG_INFO("[ProbeExplorer] Loading DWARF signatures from %s",
                          binaryProbe->file.c_str());
              auto dwarf_signatures =
                  extract_dwarf_function_signatures(binaryProbe->file, result.function_names);
              if (result.discovered_function_signatures.empty()) {
                result.discovered_function_signatures = std::move(dwarf_signatures);
              } else {
                for (auto& [function_name, arg_specs] : dwarf_signatures) {
                  if (result.discovered_function_signatures.find(function_name) ==
                      result.discovered_function_signatures.end()) {
                    result.discovered_function_signatures.emplace(function_name,
                                                                  std::move(arg_specs));
                  }
                }
              }
              if (merged_mpi_header_signatures) {
                DC_LOG_INFO(
                    "[ProbeExplorer] Merged MPI header signatures with "
                    "DWARF signatures for %s",
                    binaryProbe->file.c_str());
              }
              DC_LOG_DEBUG("UPROBE: Extracting symbols from binary...");
              if (auto uprobe = std::dynamic_pointer_cast<UProbe>(probe)) {
                uprobe->binary_path = binaryProbe->file;
                uprobe->include_offsets = binaryProbe->include_offsets;
              }
            } else if (capture_probe->probe_type == ProbeType::KPROBE) {
              result.discovered_function_signatures =
                  extract_dwarf_function_signatures(binaryProbe->file);
              std::filesystem::path binary_path(binaryProbe->file);
              const std::filesystem::path module_btf =
                  std::filesystem::path("/sys/kernel/btf") / binary_path.stem();
              if (std::filesystem::exists(module_btf)) {
                result.discovered_function_signatures =
                    extract_btf_function_signatures(module_btf.string());
              }
            }
          }
          break;
        case CaptureType::USDT:
          DC_LOG_INFO("Extracting USDT probes...");
          if (auto usdtProbe = std::static_pointer_cast<USDTCaptureProbe>(capture_probe)) {
            if (capture_probe->probe_type == ProbeType::USDT) {
              DC_LOG_DEBUG("USDT: Extracting symbols from binary...");
              if (auto usdt_probe = std::dynamic_pointer_cast<USDTProbe>(probe)) {
                usdt_probe->binary_path = usdtProbe->binary_path;
                usdt_probe->provider = usdtProbe->provider;
                result.function_names =
                    USDTFunctionExtractor(usdtProbe->provider).extractFunctionNames();
              }
            }
          }
          break;
        case CaptureType::KSYM:
          DC_LOG_INFO("Extracting kernel symbol probes...");
          if (auto ksymProbe = std::static_pointer_cast<KernelCaptureProbe>(capture_probe)) {
            result.function_names =
                datacrumbs::Singleton<KSymCapture>::get_instance()->getFunctionsByRegex(
                    ksymProbe->regex);
            if (vmlinux_btf_future.valid()) {
              result.discovered_function_signatures = vmlinux_btf_future.get();
            } else {
              result.discovered_function_signatures =
                  extract_btf_function_signatures("/sys/kernel/btf/vmlinux");
            }
          }
          break;
        case CaptureType::CUSTOM:
          DC_LOG_INFO("Extracting custom probes...");
          if (auto customProbe = std::static_pointer_cast<CustomCaptureProbe>(capture_probe)) {
            if (!std::filesystem::exists(customProbe->bpf_file)) {
              DC_LOG_ERROR("Custom BPF file does not exist: %s", customProbe->bpf_file.c_str());
              result.invalid = true;
              return result;
            }
            if (!std::filesystem::exists(customProbe->probe_file)) {
              DC_LOG_ERROR("Custom probe file does not exist: %s", customProbe->probe_file.c_str());
              result.invalid = true;
              return result;
            }
            if (!std::filesystem::exists(customProbe->process_header)) {
              DC_LOG_ERROR("Custom process header file does not exist: %s",
                           customProbe->process_header.c_str());
              result.invalid = true;
              return result;
            }
            std::ifstream probe_ifs(customProbe->probe_file);
            if (!probe_ifs.is_open()) {
              DC_LOG_ERROR("Failed to open custom probe file: %s", customProbe->probe_file.c_str());
              result.invalid = true;
              return result;
            }
            std::string probe_content((std::istreambuf_iterator<char>(probe_ifs)),
                                      std::istreambuf_iterator<char>());
            json_object* probe_jobj = json_tokener_parse(probe_content.c_str());
            if (probe_jobj && json_object_get_type(probe_jobj) == json_type_array) {
              int arr_len = json_object_array_length(probe_jobj);
              for (int i = 0; i < arr_len; ++i) {
                json_object* entry = json_object_array_get_idx(probe_jobj, i);
                if (!entry) continue;
                json_object* funcs_obj = nullptr;
                if (json_object_object_get_ex(entry, "functions", &funcs_obj) &&
                    json_object_get_type(funcs_obj) == json_type_array) {
                  int func_len = json_object_array_length(funcs_obj);
                  for (int j = 0; j < func_len; ++j) {
                    json_object* func_obj = json_object_array_get_idx(funcs_obj, j);
                    if (func_obj && json_object_get_type(func_obj) == json_type_string) {
                      result.function_names.push_back(json_object_get_string(func_obj));
                    }
                  }
                }
              }
            }
            if (probe_jobj) json_object_put(probe_jobj);
            if (auto custom_probe = std::dynamic_pointer_cast<CustomProbe>(probe)) {
              custom_probe->bpf_path = customProbe->bpf_file;
              custom_probe->start_event_id = customProbe->start_event_id;
              custom_probe->process_header = customProbe->process_header;
              custom_probe->event_type = customProbe->event_type;
            }
          }
          break;
        default:
          DC_LOG_WARN("Unknown capture type encountered!");
          break;
      }
      return result;
    });
  };

  // Iterate over all capture probes from configuration
  const size_t total_capture_probes = configManager_->capture_probes.size();
  size_t reused_probe_count = 0;
  for (const auto& capture_probe : configManager_->capture_probes) {
    std::shared_ptr<Probe> probe;

    switch (capture_probe->probe_type) {
      case ProbeType::UPROBE:
        probe = std::make_shared<UProbe>();
        break;
      case ProbeType::SYSCALLS:
        probe = std::make_shared<SysCallProbe>();
        break;
      case ProbeType::USDT:
        probe = std::make_shared<USDTProbe>();
        break;
      case ProbeType::KPROBE:
        probe = std::make_shared<KProbe>();
        break;
      case ProbeType::CUSTOM:
        probe = std::make_shared<CustomProbe>();
        break;
      default:
        DC_LOG_ERROR("Unknown probe type encountered in extractProbes()");
        throw std::runtime_error("Unknown probe type encountered in extractProbes()");
    }

    if (!capture_probe->enable_explorer) {
      // Check if probe already exists and can be reused
      auto existingProbeIt = existingProbesMap.find(capture_probe->name);
      if (existingProbeIt != existingProbesMap.end()) {
        DC_LOG_INFO("Found existing probe '%s', reusing it", capture_probe->name.c_str());
        auto existingProbe = existingProbeIt->second;

        // Copy fields from existing probe to new probe
        probe->name = existingProbe->name;
        probe->functions = existingProbe->functions;
        probe->function_arguments = existingProbe->function_arguments;

        // Copy type-specific fields based on probe type
        switch (capture_probe->probe_type) {
          case ProbeType::UPROBE:
            if (auto existingUprobe = std::dynamic_pointer_cast<UProbe>(existingProbe)) {
              if (auto uprobe = std::dynamic_pointer_cast<UProbe>(probe)) {
                uprobe->binary_path = existingUprobe->binary_path;
                uprobe->include_offsets = existingUprobe->include_offsets;
              }
            }
            break;
          case ProbeType::USDT:
            if (auto existingUsdtProbe = std::dynamic_pointer_cast<USDTProbe>(existingProbe)) {
              if (auto usdtProbe = std::dynamic_pointer_cast<USDTProbe>(probe)) {
                usdtProbe->binary_path = existingUsdtProbe->binary_path;
                usdtProbe->provider = existingUsdtProbe->provider;
              }
            }
            break;
          case ProbeType::CUSTOM:
            if (auto existingCustomProbe = std::dynamic_pointer_cast<CustomProbe>(existingProbe)) {
              if (auto customProbe = std::dynamic_pointer_cast<CustomProbe>(probe)) {
                customProbe->bpf_path = existingCustomProbe->bpf_path;
                customProbe->start_event_id = existingCustomProbe->start_event_id;
                customProbe->process_header = existingCustomProbe->process_header;
                customProbe->event_type = existingCustomProbe->event_type;
              }
            }
            break;
          default:
            // For SYSCALLS and KPROBE, no additional fields to copy
            break;
        }
        DC_LOG_INFO("Reused existing probe: %s", probe->name.c_str());

        // Validate the existing probe and add it to the list
        if (probe->validate()) {
          DC_LOG_INFO("Valid probe reused: %s", probe->name.c_str());
          probes.push_back(probe);
          ++reused_probe_count;
          DC_LOG_INFO("[ProbeExplorer] Progress reused %s after '%s'",
                      format_progress(probes.size(), total_capture_probes).c_str(),
                      capture_probe->name.c_str());
          continue;  // Skip the rest of the processing for this probe
        } else {
          DC_LOG_WARN("Existing probe '%s' failed validation, will extract fresh",
                      probe->name.c_str());
        }
      } else {
        DC_LOG_INFO("No existing probe found for '%s', will extract fresh",
                    capture_probe->name.c_str());
      }
    }
    DC_LOG_DEBUG("[ProbeExplorer] Launching extraction for '%s' (%s/%s)",
                 capture_probe->name.c_str(), capture_type_to_string(capture_probe->type),
                 probe_type_to_string(capture_probe->probe_type));
    pending_extractions.push_back(
        PendingExtraction{capture_probe, probe, launch_extraction(capture_probe, probe)});
  }

  const size_t total_pending_extractions = pending_extractions.size();
  if (total_pending_extractions > 0) {
    DC_LOG_INFO("[ProbeExplorer] Waiting for %zu extraction tasks to finish",
                total_pending_extractions);
  }

  size_t completed_extractions = 0;
  size_t extracted_probe_count = 0;
  std::vector<bool> completed_slots(total_pending_extractions, false);
  const auto progress_interval = std::chrono::seconds(10);
  const auto extraction_start = std::chrono::steady_clock::now();
  auto last_progress_log = extraction_start;

  auto process_completed_extraction = [&](PendingExtraction& pending, ExtractionResult result) {
    auto capture_probe = pending.capture_probe;
    auto probe = pending.probe;
    if (result.invalid) {
      has_invalid_probes_ = true;
      return;
    }

    auto functionNames = std::move(result.function_names);
    auto discovered_function_signatures = std::move(result.discovered_function_signatures);

    // Filter function names by regex if specified
    if (!capture_probe->regex.empty()) {
      std::regex re(capture_probe->regex, std::regex_constants::icase);
      std::vector<std::string> filteredNames;
      for (const auto& name : functionNames) {
        if (std::regex_match(name, re)) {
          filteredNames.push_back(name);
        }
      }
      functionNames = std::move(filteredNames);
    }

    probe->name = capture_probe->name;

    // For syscall probes, normalize to base syscall names expected by attach_ksyscall.
    if (capture_probe->probe_type == ProbeType::SYSCALLS) {
      for (auto& name : functionNames) {
        if (name.rfind("__x64_sys_", 0) == 0) {
          name = name.substr(10);
        } else if (name.rfind("sys_", 0) == 0) {
          name = name.substr(4);
        }
      }
    }

    // Exclude functions as per exclusion map
    if (!exclusionMap.empty()) {
      auto it = exclusionMap.find(capture_probe->name);
      if (it != exclusionMap.end()) {
        const auto& excludedFuncs = it->second;
        std::vector<std::string> filteredNames;
        for (const auto& name : functionNames) {
          auto pos = name.find(':');
          std::string base_name = (pos != std::string::npos) ? name.substr(0, pos) : name;
          if (excludedFuncs.find(name) == excludedFuncs.end() &&
              excludedFuncs.find(base_name) == excludedFuncs.end()) {
            filteredNames.push_back(name);
          } else {
            DC_LOG_INFO(
                "Excluding function '%s' from probe '%s' as per "
                "exclusion list.",
                name.c_str(), capture_probe->name.c_str());
          }
        }
        functionNames = std::move(filteredNames);
      }
    }
    if (capture_probe->probe_type != ProbeType::CUSTOM) {
      std::sort(functionNames.begin(), functionNames.end());
    }

    switch (capture_probe->type) {
      case CaptureType::HEADER: {
        DC_LOG_INFO("Deduplicating header probes...");
        std::vector<std::string> validFunctionNames;
        for (const auto& name : functionNames) {
          DC_LOG_INFO("[ProbeExplorer] Function name '%s' from %s.", name.c_str(),
                      capture_probe->name.c_str());
          auto combined_name = name;
          // Check and insert into global set to avoid duplicates
          if (!global_function_names.insert(combined_name).second) {
            DC_LOG_WARN(
                "[ProbeExplorer] Function name '%s' already processed. "
                "Skipping duplicate "
                "from %s.",
                name.c_str(), capture_probe->name.c_str());
            continue;
          }
          validFunctionNames.push_back(name);
        }
        functionNames = std::move(validFunctionNames);

        break;
      }
      case CaptureType::BINARY: {
        DC_LOG_INFO("Deduplicating binary probes...");
        if (auto binaryProbe = std::static_pointer_cast<BinaryCaptureProbe>(capture_probe)) {
          if (capture_probe->probe_type == ProbeType::UPROBE) {
            std::vector<std::string> validFunctionNames;
            for (const auto& name : functionNames) {
              auto combined_name = binaryProbe->file + "_" + name;
              // Check and insert into global set to avoid duplicates
              if (!global_function_names.insert(combined_name).second) {
                DC_LOG_WARN(
                    "[ProbeExplorer] Function name '%s' already "
                    "processed. Skipping duplicate "
                    "from %s.",
                    name.c_str(), capture_probe->name.c_str());
                continue;
              }
              validFunctionNames.push_back(name);
            }
            functionNames = std::move(validFunctionNames);
          }
        }
        break;
      }
      case CaptureType::USDT: {
        DC_LOG_INFO("Deduplicating USDT probes...");
        if (auto usdtProbe = std::static_pointer_cast<USDTCaptureProbe>(capture_probe)) {
          if (capture_probe->probe_type == ProbeType::USDT) {
            std::vector<std::string> validFunctionNames;
            for (const auto& name : functionNames) {
              auto combined_name = usdtProbe->binary_path + "_" + usdtProbe->provider + "_" + name;
              // Check and insert into global set to avoid duplicates
              if (!global_function_names.insert(combined_name).second) {
                DC_LOG_WARN(
                    "[ProbeExplorer] Function name '%s' already "
                    "processed. Skipping duplicate "
                    "from %s.",
                    name.c_str(), capture_probe->name.c_str());
                continue;
              }
              validFunctionNames.push_back(name);
            }
            functionNames = std::move(validFunctionNames);
          }
        }
        break;
      }
      case CaptureType::KSYM: {
        DC_LOG_INFO("Deduplicating kernel symbol probes...");
        if (auto ksymProbe = std::static_pointer_cast<KernelCaptureProbe>(capture_probe)) {
          std::vector<std::string> validFunctionNames;
          for (const auto& name : functionNames) {
            auto combined_name = name;
            // Check and insert into global set to avoid duplicates
            if (!global_function_names.insert(combined_name).second) {
              DC_LOG_WARN(
                  "[ProbeExplorer] Function name '%s' already processed. "
                  "Skipping duplicate "
                  "from %s.",
                  name.c_str(), capture_probe->name.c_str());
              continue;
            }
            validFunctionNames.push_back(name);
          }
          functionNames = std::move(validFunctionNames);
        }
        break;
      }
      case CaptureType::CUSTOM: {
        DC_LOG_INFO("Deduplicating custom probes...");
        std::vector<std::string> validFunctionNames;
        for (const auto& name : functionNames) {
          DC_LOG_DEBUG("[ProbeExplorer] Function name '%s' from %s.", name.c_str(),
                       capture_probe->name.c_str());
          auto combined_name = name;
          // Check and insert into global set to avoid duplicates
          if (!global_function_names.insert(combined_name).second) {
            DC_LOG_WARN(
                "[ProbeExplorer] Function name '%s' already processed. "
                "Skipping duplicate "
                "from %s.",
                name.c_str(), capture_probe->name.c_str());
            continue;
          }
          validFunctionNames.push_back(name);
        }
        functionNames = std::move(validFunctionNames);
        break;
      }
      default:
        DC_LOG_WARN("Unknown capture type encountered!");
    }

    probe->functions = functionNames;
    attach_discovered_function_signatures(probe.get(), capture_probe->probe_type, functionNames,
                                          discovered_function_signatures);

    // Validate the probe before adding
    if (!probe->validate()) {
      DC_LOG_ERROR("Probe validation failed for: %s", probe->name.c_str());
      has_invalid_probes_ = true;
      return;  // Skip invalid probes
    }
    DC_LOG_INFO("Valid probe extracted: %s", probe->name.c_str());
    probes.push_back(probe);
    ++extracted_probe_count;
    DC_LOG_INFO("[ProbeExplorer] Category '%s' resolved to %zu probes/functions",
                probe->name.c_str(), probe->functions.size());
  };

  while (completed_extractions < total_pending_extractions) {
    bool made_progress = false;
    for (size_t i = 0; i < pending_extractions.size(); ++i) {
      if (completed_slots[i]) continue;
      auto& pending = pending_extractions[i];
      if (pending.future.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready) {
        continue;
      }

      auto result = pending.future.get();
      completed_slots[i] = true;
      ++completed_extractions;
      made_progress = true;
      process_completed_extraction(pending, std::move(result));
    }

    const auto now = std::chrono::steady_clock::now();
    const bool force_log = completed_extractions == total_pending_extractions;
    if (should_emit_progress_log(now, &last_progress_log, progress_interval, force_log)) {
      std::vector<std::shared_ptr<CaptureProbe>> still_pending;
      still_pending.reserve(total_pending_extractions - completed_extractions);
      for (size_t i = 0; i < pending_extractions.size(); ++i) {
        if (!completed_slots[i]) still_pending.push_back(pending_extractions[i].capture_probe);
      }
      const auto elapsed_seconds =
          std::chrono::duration_cast<std::chrono::seconds>(now - extraction_start).count();
      DC_LOG_INFO(
          "[ProbeExplorer] Progress extractions=%s probes=%s elapsed=%llds "
          "pending=%s",
          format_progress(completed_extractions, total_pending_extractions).c_str(),
          format_progress(probes.size(), total_capture_probes).c_str(),
          static_cast<long long>(elapsed_seconds), join_pending_probe_names(still_pending).c_str());
    }

    if (!made_progress && completed_extractions < total_pending_extractions) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  if (has_invalid_probes_) {
    DC_LOG_ERROR("One or more probes failed validation. Please check the logs above.");
  }

  size_t total_discovered_functions = 0;
  for (const auto& probe : probes) {
    total_discovered_functions += probe->functions.size();
  }
  DC_LOG_INFO(
      "[ProbeExplorer] Overall discovery summary: categories=%zu (reused=%zu, extracted=%zu), "
      "total probes/functions=%zu",
      probes.size(), reused_probe_count, extracted_probe_count, total_discovered_functions);

  const size_t supported_runtime_function_count = count_supported_runtime_functions(probes);
  if (supported_runtime_function_count > DATACRUMBS_MAX_RUNTIME_FUNCTIONS) {
    DC_LOG_ERROR(
        "[ProbeExplorer] Selected too many runtime functions: %zu. "
        "The current maximum "
        "supported is %d. Please limit the selected probes/functions "
        "and regenerate.",
        supported_runtime_function_count, DATACRUMBS_MAX_RUNTIME_FUNCTIONS);
    throw std::runtime_error("Selected too many runtime functions for datacrumbs runtime.");
  }
  if (supported_runtime_function_count >
      static_cast<size_t>(DATACRUMBS_MAX_RUNTIME_FUNCTIONS * 9 / 10)) {
    DC_LOG_WARN(
        "[ProbeExplorer] Selected %zu runtime functions. This is close "
        "to the supported "
        "maximum of %d.",
        supported_runtime_function_count, DATACRUMBS_MAX_RUNTIME_FUNCTIONS);
  }
  DC_LOG_INFO(
      "[ProbeExplorer] Extraction summary: total=%zu reused=%zu "
      "extracted=%zu invalid=%s",
      total_capture_probes, reused_probe_count, extracted_probe_count,
      has_invalid_probes_ ? "yes" : "no");
  DC_LOG_TRACE("ProbeExplorer::extractProbes - end");
  return probes;
}
void ProbeExplorer::create_exclusion_file(std::vector<std::shared_ptr<Probe>> probes) {
  DC_LOG_TRACE("ProbeExplorer::create_exclusion_file - start");
  json_object* jexarray = json_object_new_array();
  // Serialize each probe to JSON without functions
  for (const auto& probe : probes) {
    json_object* jexclude = nullptr;
    switch (probe->type) {
      case ProbeType::SYSCALLS:
        jexclude = std::dynamic_pointer_cast<SysCallProbe>(probe)->toJson(false);
        break;
      case ProbeType::KPROBE:
        jexclude = std::dynamic_pointer_cast<KProbe>(probe)->toJson(false);
        break;
      case ProbeType::UPROBE:
        jexclude = std::dynamic_pointer_cast<UProbe>(probe)->toJson(false);
        break;
      case ProbeType::USDT:
        jexclude = std::dynamic_pointer_cast<USDTProbe>(probe)->toJson(false);
        break;
      case ProbeType::CUSTOM:
        jexclude = std::dynamic_pointer_cast<CustomProbe>(probe)->toJson(false);
        break;
      default:
        DC_LOG_ERROR("Unknown probe type encountered.");
        continue;  // Skip unknown types
    }
    if (!jexclude) {
      DC_LOG_ERROR("Failed to serialize probe for exclusion: %s", probe->name.c_str());
      continue;  // Skip serialization failure
    }
    json_object_array_add(jexarray, jexclude);
  }
  if (!configManager_->probe_exclusion_file_path.empty() &&
      !std::filesystem::exists(configManager_->probe_exclusion_file_path)) {
    const char* exclude_json_str =
        json_object_to_json_string_ext(jexarray, JSON_C_TO_STRING_PRETTY);
    std::ofstream ofs(configManager_->probe_exclusion_file_path);
    if (ofs.is_open()) {
      ofs << exclude_json_str;
      ofs.close();
    } else {
      DC_LOG_ERROR("Failed to open file: %s", configManager_->probe_exclusion_file_path.c_str());
    }
  }

  DC_LOG_TRACE("ProbeExplorer::create_exclusion_file - end");
}

// Loads existing probes from JSON file and builds a map for querying
std::unordered_map<std::string, std::shared_ptr<Probe>> ProbeExplorer::loadExistingProbes() {
  DC_LOG_TRACE("ProbeExplorer::loadExistingProbes - start");
  std::unordered_map<std::string, std::shared_ptr<Probe>> existingProbesMap;

  if (!configManager_->probe_file_path.empty() &&
      std::filesystem::exists(configManager_->probe_file_path)) {
    std::ifstream ifs(configManager_->probe_file_path);
    if (ifs.is_open()) {
      std::string error;
      json_object* jobj = datacrumbs::probe_file::load_verified_categories_from_file(
          configManager_->probe_file_path, &error);

      if (jobj && json_object_get_type(jobj) == json_type_array) {
        int arr_len = json_object_array_length(jobj);
        for (int i = 0; i < arr_len; ++i) {
          json_object* probe_obj = json_object_array_get_idx(jobj, i);
          if (!probe_obj) {
            DC_LOG_WARN("Probe object at index %d is null", i);
            continue;
          }

          json_object* name_obj = nullptr;
          json_object* type_obj = nullptr;

          if (json_object_object_get_ex(probe_obj, "name", &name_obj) &&
              json_object_object_get_ex(probe_obj, "type", &type_obj) &&
              json_object_get_type(name_obj) == json_type_string &&
              json_object_get_type(type_obj) == json_type_int) {
            std::string probe_name = json_object_get_string(name_obj);
            ProbeType probe_type = static_cast<ProbeType>(json_object_get_int(type_obj));

            std::shared_ptr<Probe> probe;

            // Create appropriate probe type based on the type field
            switch (probe_type) {
              case ProbeType::UPROBE:
                probe = std::make_shared<UProbe>();
                probe->type = ProbeType::UPROBE;
                break;
              case ProbeType::SYSCALLS:
                probe = std::make_shared<SysCallProbe>();
                probe->type = ProbeType::SYSCALLS;
                break;
              case ProbeType::USDT:
                probe = std::make_shared<USDTProbe>();
                probe->type = ProbeType::USDT;
                break;
              case ProbeType::KPROBE:
                probe = std::make_shared<KProbe>();
                probe->type = ProbeType::KPROBE;
                break;
              case ProbeType::CUSTOM:
                probe = std::make_shared<CustomProbe>();
                probe->type = ProbeType::CUSTOM;
                break;
              default:
                DC_LOG_WARN("Unknown probe type '%d' for probe '%s'", static_cast<int>(probe_type),
                            probe_name.c_str());
                continue;
            }

            probe->name = probe_name;

            // Load functions array if present
            json_object* funcs_obj = nullptr;
            if (json_object_object_get_ex(probe_obj, "functions", &funcs_obj) &&
                json_object_get_type(funcs_obj) == json_type_array) {
              int func_len = json_object_array_length(funcs_obj);
              for (int j = 0; j < func_len; ++j) {
                json_object* func_obj = json_object_array_get_idx(funcs_obj, j);
                if (func_obj && json_object_get_type(func_obj) == json_type_string) {
                  probe->functions.push_back(json_object_get_string(func_obj));
                }
              }
            }

            // Load type-specific fields
            switch (probe_type) {
              case ProbeType::UPROBE:
                if (auto uprobe = std::dynamic_pointer_cast<UProbe>(probe)) {
                  json_object* binary_path_obj = nullptr;
                  json_object* include_offsets_obj = nullptr;
                  if (json_object_object_get_ex(probe_obj, "binary_path", &binary_path_obj) &&
                      json_object_get_type(binary_path_obj) == json_type_string) {
                    uprobe->binary_path = json_object_get_string(binary_path_obj);
                  }
                  if (json_object_object_get_ex(probe_obj, "include_offsets",
                                                &include_offsets_obj) &&
                      json_object_get_type(include_offsets_obj) == json_type_boolean) {
                    uprobe->include_offsets = json_object_get_boolean(include_offsets_obj);
                  }
                }
                break;
              case ProbeType::USDT:
                if (auto usdtProbe = std::dynamic_pointer_cast<USDTProbe>(probe)) {
                  json_object* binary_path_obj = nullptr;
                  json_object* provider_obj = nullptr;
                  if (json_object_object_get_ex(probe_obj, "binary_path", &binary_path_obj) &&
                      json_object_get_type(binary_path_obj) == json_type_string) {
                    usdtProbe->binary_path = json_object_get_string(binary_path_obj);
                  }
                  if (json_object_object_get_ex(probe_obj, "provider", &provider_obj) &&
                      json_object_get_type(provider_obj) == json_type_string) {
                    usdtProbe->provider = json_object_get_string(provider_obj);
                  }
                }
                break;
              case ProbeType::CUSTOM:
                if (auto customProbe = std::dynamic_pointer_cast<CustomProbe>(probe)) {
                  json_object* bpf_path_obj = nullptr;
                  json_object* start_event_id_obj = nullptr;
                  json_object* process_header_obj = nullptr;
                  json_object* event_type_obj = nullptr;

                  if (json_object_object_get_ex(probe_obj, "bpf_path", &bpf_path_obj) &&
                      json_object_get_type(bpf_path_obj) == json_type_string) {
                    customProbe->bpf_path = json_object_get_string(bpf_path_obj);
                  }
                  if (json_object_object_get_ex(probe_obj, "start_event_id", &start_event_id_obj) &&
                      json_object_get_type(start_event_id_obj) == json_type_int) {
                    customProbe->start_event_id = json_object_get_int(start_event_id_obj);
                  }
                  if (json_object_object_get_ex(probe_obj, "process_header", &process_header_obj) &&
                      json_object_get_type(process_header_obj) == json_type_string) {
                    customProbe->process_header = json_object_get_string(process_header_obj);
                  }
                  if (json_object_object_get_ex(probe_obj, "event_type", &event_type_obj) &&
                      json_object_get_type(event_type_obj) == json_type_int) {
                    customProbe->event_type = json_object_get_int(event_type_obj);
                  }
                }
                break;
              case ProbeType::SYSCALLS:
              case ProbeType::KPROBE:
                // No additional fields to load for these types
                break;
              default:
                // Already handled above, should not reach here
                break;
            }

            existingProbesMap[probe_name] = probe;
            DC_LOG_DEBUG("Loaded existing probe: %s with %zu functions", probe_name.c_str(),
                         probe->functions.size());
          } else {
            DC_LOG_WARN("Probe at index %d missing required 'name' or 'type' field", i);
          }
        }
      } else {
        DC_LOG_ERROR("Existing probe file verification failed: %s", error.c_str());
      }

      if (jobj) json_object_put(jobj);
    } else {
      DC_LOG_ERROR("Failed to open existing probe file: %s",
                   configManager_->probe_file_path.string().c_str());
    }
  } else {
    DC_LOG_INFO("No existing probe file found at: %s",
                configManager_->probe_file_path.string().c_str());
  }

  DC_LOG_INFO("Loaded %zu existing probes", existingProbesMap.size());
  DC_LOG_TRACE("ProbeExplorer::loadExistingProbes - end");
  return existingProbesMap;
}

// Writes extracted probes to a JSON file and returns the probe list
std::vector<std::shared_ptr<Probe>> ProbeExplorer::writeProbesToJson() {
  DC_LOG_TRACE("ProbeExplorer::writeProbesToJson - start");
  auto probes = extractProbes();
  if (probes.empty()) {
    DC_LOG_WARN("No valid probes extracted. Skipping JSON write.");
    return probes;
  }
  if (!configManager_->probe_exclusion_file_path.empty() &&
      !std::filesystem::exists(configManager_->probe_exclusion_file_path)) {
    create_exclusion_file(probes);
  }
  json_object* jarray = json_object_new_array();

  // Serialize each probe to JSON
  for (const auto& probe : probes) {
    json_object* jprobe = nullptr;
    switch (probe->type) {
      case ProbeType::SYSCALLS:
        jprobe = std::dynamic_pointer_cast<SysCallProbe>(probe)->toJson();
        break;
      case ProbeType::KPROBE:
        jprobe = std::dynamic_pointer_cast<KProbe>(probe)->toJson();
        break;
      case ProbeType::UPROBE:
        jprobe = std::dynamic_pointer_cast<UProbe>(probe)->toJson();
        break;
      case ProbeType::USDT:
        jprobe = std::dynamic_pointer_cast<USDTProbe>(probe)->toJson();
        break;
      case ProbeType::CUSTOM:
        jprobe = std::dynamic_pointer_cast<CustomProbe>(probe)->toJson();
        break;
      default:
        DC_LOG_ERROR("Unknown probe type encountered.");
        continue;  // Skip unknown types
    }
    if (!jprobe) {
      DC_LOG_ERROR("Failed to serialize probe: %s", probe->name.c_str());
      continue;  // Skip serialization failure
    }
    json_object_array_add(jarray, jprobe);
  }

  json_object* root = json_object_new_object();
  json_object* summary = json_object_new_object();
  json_object_object_add(summary, "config_file_path",
                         json_object_new_string(configManager_->config_file_path.string().c_str()));
  json_object_object_add(summary, "probe_file_path",
                         json_object_new_string(configManager_->probe_file_path.string().c_str()));
  json_object_object_add(summary, "hostname",
                         json_object_new_string(configManager_->hostname.c_str()));
  json_object_object_add(summary, "user", json_object_new_string(configManager_->user.c_str()));
  json_object_object_add(summary, "install_user", json_object_new_string(DATACRUMBS_INSTALL_USER));
  json_object_object_add(root, "summary", summary);
  json_object_object_add(root, "categories", json_object_get(jarray));

  const std::string signing_payload = probe_signing_payload(summary, jarray);
  std::string checksum;
  std::string signing_error;
  DC_LOG_INFO("Requesting probe signature for %s",
              configManager_->probe_file_path.string().c_str());
  const bool signed_ok = datacrumbs::probe_signing_service::request_probe_signature(
      signing_payload, &checksum, &signing_error);
  if (!signed_ok) {
    DC_LOG_ERROR("Failed to sign probes through datacrumbs_probe_manager service: %s",
                 signing_error.c_str());
    json_object_put(root);
    json_object_put(jarray);
    return probes;
  }

  json_object_object_add(root, "checksum_algorithm", json_object_new_string("hmac-sha256"));
  json_object_object_add(root, "checksum", json_object_new_string(checksum.c_str()));
  DC_LOG_INFO("Probe file signed successfully: %s",
              configManager_->probe_file_path.string().c_str());

  const char* signed_json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
  const std::string signed_payload = signed_json != nullptr ? signed_json : "";

  if (!datacrumbs::probe_file::write_gzip_file(configManager_->probe_file_path, signed_payload)) {
    DC_LOG_ERROR("Failed to open file: %s", configManager_->probe_file_path.c_str());
  } else {
    DC_LOG_INFO("Signed probe file written: %s", configManager_->probe_file_path.c_str());
  }

  json_object_put(root);
  json_object_put(jarray);
  DC_LOG_TRACE("ProbeExplorer::writeProbesToJson - end");
  return probes;
}

bool ProbeExplorer::writeSystemProbeJson() {
  DC_LOG_TRACE("ProbeExplorer::writeSystemProbeJson - start");

  json_object* root = json_object_new_object();
  json_object* summary = json_object_new_object();

  json_object_object_add(root, "system_configuration", configured_environment_to_json());
  json_object_object_add(summary, "trace_log_dir",
                         json_object_new_string(configManager_->trace_log_dir.string().c_str()));
  json_object_object_add(summary, "data_dir",
                         json_object_new_string(configManager_->data_dir.string().c_str()));
  json_object_object_add(
      summary, "system_probe_path",
      json_object_new_string(configManager_->system_probe_path.string().c_str()));
  json_object_object_add(summary, "hostname",
                         json_object_new_string(configManager_->hostname.c_str()));
  json_object_object_add(summary, "user", json_object_new_string(configManager_->user.c_str()));
  json_object_object_add(summary, "install_user", json_object_new_string(DATACRUMBS_INSTALL_USER));
  json_object_object_add(root, "summary", summary);

  const char* json_payload = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
  bool ok =
      datacrumbs::probe_file::write_gzip_file(configManager_->system_probe_path, json_payload);
  json_object_put(root);

  if (!ok) {
    DC_LOG_ERROR("Failed to write compressed system probe file: %s",
                 configManager_->system_probe_path.string().c_str());
    return false;
  }

  DC_LOG_INFO("Compressed system probe written to: %s",
              configManager_->system_probe_path.string().c_str());
  DC_LOG_TRACE("ProbeExplorer::writeSystemProbeJson - end");
  return true;
}

}  // namespace datacrumbs
