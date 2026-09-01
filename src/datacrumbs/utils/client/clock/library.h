// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_UTILS_CLIENT_CLOCK_LIBRARY_H
#define DATACRUMBS_UTILS_CLIENT_CLOCK_LIBRARY_H

namespace datacrumbs::client::clock {

/// Interpose gettimeofday so another tool's timestamps land on the global cross-node epoch. Reads
/// DATACRUMBS_ENV_CLOCK and returns immediately when it is off.
void init();

/// Nothing to release; present so every module answers the same interface.
void fini();

}  // namespace datacrumbs::client::clock

#endif  // DATACRUMBS_UTILS_CLIENT_CLOCK_LIBRARY_H
