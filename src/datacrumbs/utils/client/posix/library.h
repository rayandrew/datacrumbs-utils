// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_POSIX_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_POSIX_LIBRARY_H

namespace datacrumbs::client::posix {

/// Wrap the libc I/O calls and open this module's sink. Reads DATACRUMBS_ENV_POSIX and returns
/// immediately when it is off, so linking the module in does not turn it on.
void init();

/// Flush and close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::posix

#endif  // DATACRUMBS_UTILS_CLIENT_POSIX_LIBRARY_H
