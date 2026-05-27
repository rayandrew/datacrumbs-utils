// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_UTILS_CONFIG_HPP
#define DATACRUMBS_UTILS_CONFIG_HPP

/*
 * Fallback wrapper used before CMake generates datacrumbs_utils_config.h
 * into the build include tree.
 */
#include <datacrumbs/datacrumbs_config.h>

#ifndef DATACRUMBS_UTILS_PACKAGE_VERSION
#define DATACRUMBS_UTILS_PACKAGE_VERSION "unknown"
#endif
#ifndef DATACRUMBS_UTILS_RELEASE_VERSION_STRING
#define DATACRUMBS_UTILS_RELEASE_VERSION_STRING "unknown"
#endif

#endif  // DATACRUMBS_UTILS_CONFIG_HPP
