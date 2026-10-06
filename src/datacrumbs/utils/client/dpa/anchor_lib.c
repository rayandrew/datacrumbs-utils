/* SPDX-License-Identifier: MIT */

/* libdatacrumbs_dpa_anchor.so carries the dpacc-built kernel archive (anchor_kernel_dev.c) and
 * nothing else; CMakeLists.txt links the archive in whole. This file exists so the target has a
 * source. The client dlopens the library from the anchor thread. */
