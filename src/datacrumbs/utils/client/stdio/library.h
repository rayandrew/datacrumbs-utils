// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H

namespace datacrumbs::client::stdio {

/// Wrap the buffered I/O calls. Reads DATACRUMBS_ENV_STDIO and returns immediately when it is off.
///
/// Separate from the posix module: fwrite reaches the kernel through a libc-internal call that
/// bypasses write's symbol interposition, so the posix module alone misses all fwrite traffic.
void init();

/// Flush and close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::stdio

#endif  // DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H
