// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
#define DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__

#include <string>

namespace datacrumbs::probe_signing_service {

std::string tcp_host();

int tcp_port();

/**
 * @param checksum Set to the signed checksum on success.
 * @param error Set on failure, if non-null.
 */
bool request_probe_signature(const std::string& signing_payload, std::string* checksum,
                             std::string* error = nullptr);

}  // namespace datacrumbs::probe_signing_service

#endif  // DATACRUMBS_COMMON_PROBE_SIGNING_SERVICE_H__
