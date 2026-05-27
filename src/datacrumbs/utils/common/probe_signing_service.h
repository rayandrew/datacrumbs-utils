// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
#define DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__

#include <string>

namespace datacrumbs::probe_signing_service {

/**
 * @brief Return probe-manager TCP host used for signing RPC.
 * @return Hostname or IP string.
 */
std::string tcp_host();

/**
 * @brief Return probe-manager TCP port used for signing RPC.
 * @return TCP port number.
 */
int tcp_port();

/**
 * @brief Request a checksum signature for a serialized signing payload.
 * @param signing_payload Serialized JSON payload sent to manager.
 *        Example: "{\"payload\":\"...\"}".
 * @param checksum Output checksum string on success.
 * @param error Optional output error message on failure.
 * @return True when signature request succeeds and checksum is set.
 */
bool request_probe_signature(const std::string& signing_payload, std::string* checksum,
                             std::string* error = nullptr);

}  // namespace datacrumbs::probe_signing_service

#endif  // DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
