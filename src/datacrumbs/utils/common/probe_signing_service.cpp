// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#include <arpa/inet.h>
#include <datacrumbs/datacrumbs_utils_config.h>
#include <datacrumbs/utils/common/probe_signing_service.h>
#include <json-c/json.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace datacrumbs::probe_signing_service {

namespace {

constexpr const char* kRpcVersion = "2.0";
constexpr const char* kSignMethod = "sign_probe_payload";

std::string json_string_or_empty(json_object* root, const char* key) {
  json_object* value = nullptr;
  if (root == nullptr || !json_object_object_get_ex(root, key, &value) ||
      json_object_get_type(value) != json_type_string) {
    return "";
  }
  return json_object_get_string(value);
}

bool read_all_from_fd(int fd, std::string* payload) {
  char buffer[4096];
  payload->clear();
  ssize_t read_bytes = 0;
  for (;;) {
    read_bytes = read(fd, buffer, sizeof(buffer));
    if (read_bytes > 0) {
      payload->append(buffer, static_cast<std::size_t>(read_bytes));
      continue;
    }
    if (read_bytes < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
  return read_bytes == 0;
}

bool write_all_to_fd(int fd, const std::string& payload) {
  std::size_t total_written = 0;
  while (total_written < payload.size()) {
    const ssize_t written =
        write(fd, payload.data() + total_written, payload.size() - total_written);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return false;
    }
    total_written += static_cast<std::size_t>(written);
  }
  return true;
}

bool read_response_payload(const std::string& response_payload, std::string* signed_payload,
                           std::string* error) {
  json_object* root = json_tokener_parse(response_payload.c_str());
  if (root == nullptr || json_object_get_type(root) != json_type_object) {
    if (error != nullptr) {
      *error = "failed to parse manager response";
    }
    if (root != nullptr) {
      json_object_put(root);
    }
    return false;
  }

  const std::string version = json_string_or_empty(root, "jsonrpc");
  if (version != kRpcVersion) {
    if (error != nullptr) {
      *error = "manager response missing jsonrpc version";
    }
    json_object_put(root);
    return false;
  }

  json_object* error_obj = nullptr;
  if (json_object_object_get_ex(root, "error", &error_obj) && error_obj != nullptr &&
      json_object_get_type(error_obj) == json_type_object) {
    if (error != nullptr) {
      *error = json_string_or_empty(error_obj, "message");
      if (error->empty()) {
        *error = "manager rejected request";
      }
    }
    json_object_put(root);
    return false;
  }

  json_object* result_obj = nullptr;
  if (!json_object_object_get_ex(root, "result", &result_obj) || result_obj == nullptr ||
      json_object_get_type(result_obj) != json_type_object) {
    if (error != nullptr) {
      *error = "manager response missing result";
    }
    json_object_put(root);
    return false;
  }

  if (signed_payload != nullptr) {
    *signed_payload = json_string_or_empty(result_obj, "checksum");
  }
  json_object_put(root);
  return signed_payload != nullptr && !signed_payload->empty();
}

}  // namespace

std::string tcp_host() {
  return DATACRUMBS_PROBE_MANAGER_TCP_HOST;
}

int tcp_port() {
  return DATACRUMBS_PROBE_MANAGER_TCP_PORT;
}

bool request_probe_signature(const std::string& signing_payload, std::string* checksum,
                             std::string* error) {
  // Resolve manager endpoint from runtime configuration.
  const std::string host = tcp_host();
  const int port = tcp_port();
  const int client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_fd < 0) {
    if (error != nullptr) {
      *error = "failed to create client socket";
    }
    return false;
  }

  // Resolve host to socket address before connect.
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* resolved = nullptr;
  const std::string port_str = std::to_string(port);
  const int gai_rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &resolved);
  if (gai_rc != 0) {
    if (error != nullptr) {
      *error = std::string("failed to resolve manager TCP host: ") + gai_strerror(gai_rc);
    }
    close(client_fd);
    return false;
  }

  sockaddr_in address{};
  std::memcpy(&address, resolved->ai_addr, sizeof(address));
  freeaddrinfo(resolved);

  if (connect(client_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    if (error != nullptr) {
      *error = "failed to connect to datacrumbs_probe_manager service";
    }
    close(client_fd);
    return false;
  }

  // Send JSON-RPC signing request document.
  json_object* request_root = json_object_new_object();
  json_object* params = json_object_new_object();
  json_object_object_add(params, "signing_payload",
                         json_object_new_string(signing_payload.c_str()));
  json_object_object_add(request_root, "jsonrpc", json_object_new_string(kRpcVersion));
  json_object_object_add(request_root, "id", json_object_new_string("1"));
  json_object_object_add(request_root, "method", json_object_new_string(kSignMethod));
  json_object_object_add(request_root, "params", params);
  const char* request_json = json_object_to_json_string_ext(request_root, JSON_C_TO_STRING_PLAIN);
  const std::string request_payload = request_json != nullptr ? request_json : "";
  json_object_put(request_root);

  if (!write_all_to_fd(client_fd, request_payload)) {
    if (error != nullptr) {
      *error = "failed to write signing request";
    }
    close(client_fd);
    return false;
  }
  shutdown(client_fd, SHUT_WR);

  // Read full response payload after half-close write side.
  std::string response_payload;
  const bool ok = read_all_from_fd(client_fd, &response_payload);
  close(client_fd);
  if (!ok) {
    if (error != nullptr) {
      *error = "failed to read manager response";
    }
    return false;
  }
  if (response_payload.empty()) {
    if (error != nullptr) {
      *error = "manager service closed connection without a response";
    }
    return false;
  }
  return read_response_payload(response_payload, checksum, error);
}

}  // namespace datacrumbs::probe_signing_service
