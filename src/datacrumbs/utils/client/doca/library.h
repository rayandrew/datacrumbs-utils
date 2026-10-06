// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_DOCA_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_DOCA_LIBRARY_H

namespace datacrumbs::client::doca {

/// Wrap the queue calls the fixed-function engines are driven through, so a completion can be named
/// from the request that asked for it. Reads DATACRUMBS_ENV_ENGINE and returns when it is off.
void init();

/// Stop reading and close the sink. Safe when init did nothing.
void fini();

/// fini's last sweep without closing anything, for a process about to be killed while its own
/// threads still run. Background must be stopped first. Safe when init did nothing.
void drain_for_exit();

}  // namespace datacrumbs::client::doca

#endif  // DATACRUMBS_UTILS_CLIENT_DOCA_LIBRARY_H
