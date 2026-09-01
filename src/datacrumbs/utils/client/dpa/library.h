// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H

namespace datacrumbs::client::dpa {

/// Open this module's sink. Off unless DATACRUMBS_DPA names the file the DPA log was written to.
void init();

/// Parse that file's DC_DPA records into the trace, then close. Safe when init did nothing.
void fini();

}  // namespace datacrumbs::client::dpa

#endif  // DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H
