// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H

namespace datacrumbs::client::dpa {

/// Open this module's sink. Off unless DATACRUMBS_DPA names the file the DPA log was written to.
/// Also starts the automated clock anchor where supported, pairing the DPA clock with the
/// global epoch on a background thread every DATACRUMBS_DPA_ANCHOR_INTERVAL_S seconds.
/// DATACRUMBS_DPA_ANCHOR overrides it with a manually computed pairing.
void init();

/// Parse that file's DC_DPA records into the trace, then close. Safe when init did nothing. Also
/// stops the anchor thread and takes one last reading first.
void fini();

}  // namespace datacrumbs::client::dpa

#endif  // DATACRUMBS_UTILS_CLIENT_DPA_LIBRARY_H
