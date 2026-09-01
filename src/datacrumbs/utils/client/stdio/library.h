// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H

namespace datacrumbs::client::stdio {

/// Wrap the buffered I/O calls. Reads DATACRUMBS_ENV_STDIO and returns immediately when it is off.
///
/// Separate from the posix module because wrapping write does not see this traffic: stdio reaches
/// the kernel through a call inside libc that never goes through the table symbol interposition
/// rewrites. Measured: a program doing ten write and ten fwrite calls under the posix module alone
/// reported ten, and the file it wrote with fwrite did not appear at all.
void init();

/// Flush and close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::stdio

#endif  // DATACRUMBS_UTILS_CLIENT_STDIO_LIBRARY_H
