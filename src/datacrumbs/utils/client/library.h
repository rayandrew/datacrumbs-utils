// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#ifndef DATACRUMBS_LIBRARY_H
#define DATACRUMBS_LIBRARY_H

/**
 * @brief Start datacrumbs client lifecycle from shared library context.
 */
extern "C" __attribute__((visibility("default"))) void datacrumbs_start();

/**
 * @brief Stop datacrumbs client lifecycle from shared library context.
 */
extern "C" __attribute__((visibility("default"))) void datacrumbs_stop();

/**
 * @brief Constructor hook called when shared library is loaded.
 */
extern void __attribute__((constructor)) datacrumbs_init(void);

/**
 * @brief Destructor hook called when shared library is unloaded.
 */
extern void __attribute__((destructor)) datacrumbs_fini(void);

#endif  // DATACRUMBS_LIBRARY_H