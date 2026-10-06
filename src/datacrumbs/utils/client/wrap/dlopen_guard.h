// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_WRAP_DLOPEN_GUARD_H
#define DATACRUMBS_UTILS_CLIENT_WRAP_DLOPEN_GUARD_H

namespace datacrumbs::client::wrap {

/**
 * @brief Puts a dlopen wrapper in front of GOTCHA's own, once per process.
 *
 * GOTCHA retries every not-yet-found binding of every tool and rewalks the GOTs on each dlopen,
 * including RTLD_NOLOAD and reopens of a loaded library. The guard lets a dlopen that adds no
 * object to the link map skip that, and sends every other dlopen through GOTCHA as before. Call
 * after this process's own gotcha_wrap. False when the real dlopen cannot be resolved, in which
 * case every dlopen still goes through GOTCHA.
 */
bool install_dlopen_guard();

}  // namespace datacrumbs::client::wrap

#endif  // DATACRUMBS_UTILS_CLIENT_WRAP_DLOPEN_GUARD_H
