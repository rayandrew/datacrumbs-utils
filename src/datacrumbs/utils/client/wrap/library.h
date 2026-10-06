// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_WRAP_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_WRAP_LIBRARY_H

namespace datacrumbs::client::wrap {

/// Wrap the classified API surface with GOTCHA. Reads DATACRUMBS_ENV_API and returns immediately
/// when it is off.
void init();

/// Flush and close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::wrap

#endif  // DATACRUMBS_UTILS_CLIENT_WRAP_LIBRARY_H
