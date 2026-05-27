
// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <datacrumbs/utils/explorer/mechanism/header_capture.h>

#include <algorithm>
#include <cctype>

namespace datacrumbs {

namespace {

std::string trim_copy(std::string value) {
  value.erase(value.begin(), std::find_if(value.begin(), value.end(),
                                          [](unsigned char ch) { return !std::isspace(ch); }));
  value.erase(
      std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) { return !std::isspace(ch); })
          .base(),
      value.end());
  return value;
}

bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}

unsigned int scalar_type_size(const std::string& c_type) {
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
      c_type.find("off_t") != std::string::npos || c_type.find("pid_t") != std::string::npos) {
    return 8;
  }
  return 8;
}

ProbeArgCaptureSpec build_arg_spec(CXCursor function_cursor, int index) {
  ProbeArgCaptureSpec spec;
  spec.index = static_cast<unsigned int>(index);

  CXCursor arg_cursor = clang_Cursor_getArgument(function_cursor, index);
  CXType arg_type = clang_getCursorType(arg_cursor);
  CXType canonical_arg_type = clang_getCanonicalType(arg_type);

  CXString arg_name = clang_getCursorSpelling(arg_cursor);
  CXString type_name = clang_getTypeSpelling(arg_type);
  spec.label = clang_getCString(arg_name) ? clang_getCString(arg_name) : "";
  spec.c_type = trim_copy(clang_getCString(type_name) ? clang_getCString(type_name) : "");
  clang_disposeString(arg_name);
  clang_disposeString(type_name);

  if (spec.c_type.empty()) {
    CXString canonical_type_name = clang_getTypeSpelling(canonical_arg_type);
    spec.c_type = trim_copy(
        clang_getCString(canonical_type_name) ? clang_getCString(canonical_type_name) : "");
    clang_disposeString(canonical_type_name);
  }

  if (spec.label.empty()) {
    spec.label = "arg" + std::to_string(index + 1);
  }

  spec.is_pointer =
      arg_type.kind == CXType_Pointer || arg_type.kind == CXType_BlockPointer ||
      arg_type.kind == CXType_LValueReference || arg_type.kind == CXType_RValueReference ||
      canonical_arg_type.kind == CXType_Pointer || canonical_arg_type.kind == CXType_BlockPointer ||
      canonical_arg_type.kind == CXType_LValueReference ||
      canonical_arg_type.kind == CXType_RValueReference ||
      spec.c_type.find('*') != std::string::npos;
  if (spec.is_pointer) {
    spec.num_bytes = is_char_pointer_type(spec.c_type) ? DATACRUMBS_MAX_CAPTURE_BYTES : 8U;
  } else {
    long long type_size = clang_Type_getSizeOf(arg_type);
    if (type_size <= 0) {
      type_size = clang_Type_getSizeOf(canonical_arg_type);
    }
    spec.num_bytes = type_size > 0 ? static_cast<unsigned int>(std::min<long long>(type_size, 8))
                                   : scalar_type_size(spec.c_type);
  }
  return spec;
}

}  // namespace

// Constructor: Initializes the extractor with the given header file path.
HeaderFunctionExtractor::HeaderFunctionExtractor(const std::string& headerPath)
    : headerPath_(headerPath), index_(nullptr), tu_(nullptr) {}

// Destructor: Cleans up Clang resources.
HeaderFunctionExtractor::~HeaderFunctionExtractor() {
  if (tu_) clang_disposeTranslationUnit(tu_);
  if (index_) clang_disposeIndex(index_);
}

// Extracts all function and method names from the header file.
std::vector<std::string> HeaderFunctionExtractor::extractFunctionNames() {
  DC_LOG_TRACE("HeaderFunctionExtractor::extractFunctionNames - start");

  std::vector<std::string> functionNames;

  if (tu_) {
    clang_disposeTranslationUnit(tu_);
    tu_ = nullptr;
  }
  if (index_) {
    clang_disposeIndex(index_);
    index_ = nullptr;
  }

  // Create a Clang index for parsing.
  index_ = clang_createIndex(0, 0);
  if (!index_) {
    DC_LOG_ERROR("Failed to create Clang index.");
    return functionNames;
  }

  // Parse the translation unit (header file).
  tu_ = clang_parseTranslationUnit(index_, headerPath_.c_str(), nullptr, 0, nullptr, 0,
                                   CXTranslationUnit_None);

  if (!tu_) {
    DC_LOG_ERROR("Failed to parse translation unit for: %s", headerPath_.c_str());
    return functionNames;
  }

  // Visitor data structure to collect function names.
  struct VisitorData {
    std::vector<std::string>* names;
  } data{&functionNames};

  // Visit all children in the translation unit to find function and method
  // declarations.
  clang_visitChildren(
      clang_getTranslationUnitCursor(tu_),
      [](CXCursor cursor, CXCursor /*parent*/, CXClientData client_data) {
        auto* data = static_cast<VisitorData*>(client_data);
        // Check if the cursor is a function or C++ method declaration.
        if (cursor.kind == CXCursor_FunctionDecl || cursor.kind == CXCursor_CXXMethod) {
          CXString functionName = clang_getCursorSpelling(cursor);
          data->names->emplace_back(clang_getCString(functionName));
          clang_disposeString(functionName);
        }
        return CXChildVisit_Recurse;
      },
      &data);

  DC_LOG_TRACE("HeaderFunctionExtractor::extractFunctionNames - end");
  return functionNames;
}

std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>>
HeaderFunctionExtractor::extractFunctionSignatures() {
  DC_LOG_TRACE("HeaderFunctionExtractor::extractFunctionSignatures - start");

  std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>> function_signatures;

  if (tu_) {
    clang_disposeTranslationUnit(tu_);
    tu_ = nullptr;
  }
  if (index_) {
    clang_disposeIndex(index_);
    index_ = nullptr;
  }

  index_ = clang_createIndex(0, 0);
  if (!index_) {
    DC_LOG_ERROR("Failed to create Clang index.");
    return function_signatures;
  }

  tu_ = clang_parseTranslationUnit(index_, headerPath_.c_str(), nullptr, 0, nullptr, 0,
                                   CXTranslationUnit_None);
  if (!tu_) {
    DC_LOG_ERROR("Failed to parse translation unit for: %s", headerPath_.c_str());
    return function_signatures;
  }

  struct VisitorData {
    std::unordered_map<std::string, std::vector<ProbeArgCaptureSpec>>* signatures;
  } data{&function_signatures};

  clang_visitChildren(
      clang_getTranslationUnitCursor(tu_),
      [](CXCursor cursor, CXCursor /*parent*/, CXClientData client_data) {
        auto* data = static_cast<VisitorData*>(client_data);
        if (cursor.kind != CXCursor_FunctionDecl && cursor.kind != CXCursor_CXXMethod) {
          return CXChildVisit_Recurse;
        }

        CXString function_name = clang_getCursorSpelling(cursor);
        const char* function_name_cstr = clang_getCString(function_name);
        if (function_name_cstr != nullptr && function_name_cstr[0] != '\0') {
          const int num_args = clang_Cursor_getNumArguments(cursor);
          std::vector<ProbeArgCaptureSpec> arg_specs;
          if (num_args > 0) {
            arg_specs.reserve(static_cast<std::size_t>(num_args));
            for (int index = 0; index < num_args; ++index) {
              arg_specs.push_back(build_arg_spec(cursor, index));
            }
          }
          (*data->signatures)[function_name_cstr] = std::move(arg_specs);
        }
        clang_disposeString(function_name);
        return CXChildVisit_Recurse;
      },
      &data);

  DC_LOG_TRACE("HeaderFunctionExtractor::extractFunctionSignatures - end");
  return function_signatures;
}

}  // namespace datacrumbs
