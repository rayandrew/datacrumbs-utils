cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0075 NEW)
project(datacrumbs-utils LANGUAGES C CXX)

# Warnings on. A stray vararg left after removing a field from a record made snprintf read an
# integer as a char* and corrupt the traced process; -Wformat would have caught it at compile time.
add_compile_options(-Wall -Wextra -Wformat=2)

include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DATACRUMBS_UTILS_MODULE_NAME "datacrumbs")
set(DATACRUMBS_UTILS_PACKAGE_VERSION "1.0.0")
set(DATACRUMBS_UTILS_VERSION_TUPLE "(0, 0, 4)")
set(DATACRUMBS_UTILS_RELEASE_VERSION_STRING "0.0.4")

string(TOUPPER "${PROJECT_NAME}" UPPER_PROJECT_NAME)
set(DATACRUMBS_UTILS_LIBDIR "lib" CACHE STRING "Library output directory name")
set(
  DATACRUMBS_INSTALL_DIR
  ""
  CACHE PATH "Optional datacrumbs install prefix used to locate datacrumbsConfig.cmake"
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
include(datacrumbs-utils)
if(DATACRUMBS_INSTALL_DIR AND NOT DATACRUMBS_INSTALL_DIR STREQUAL "")
  list(PREPEND CMAKE_PREFIX_PATH "${DATACRUMBS_INSTALL_DIR}")
  list(PREPEND CMAKE_PREFIX_PATH "${DATACRUMBS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/cmake/datacrumbs")
  list(PREPEND CMAKE_PREFIX_PATH "${DATACRUMBS_INSTALL_DIR}/lib/cmake/datacrumbs")
  list(PREPEND CMAKE_PREFIX_PATH "${DATACRUMBS_INSTALL_DIR}/lib64/cmake/datacrumbs")
endif()
find_package(datacrumbs CONFIG REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)

# GOTCHA rewrites the GOT rather than relying on symbol resolution order, which is what lets it
# reach calls made by a dlopened plugin into its own dependency. LD_PRELOAD with dlsym(RTLD_NEXT)
# cannot: measured against doca_bench, which dlopens its engine libraries, interposition saw zero
# typed task allocations where GOTCHA saw them all.
#
# Optional so a build without it still produces the eBPF and writer side. Install it into the same
# prefix as the other out-of-tree dependencies and it is found automatically.
option(DATACRUMBS_UTILS_ENABLE_GOTCHA "Wrap library calls with GOTCHA" ON)
if(DATACRUMBS_UTILS_ENABLE_GOTCHA)
  find_package(gotcha CONFIG QUIET)
  if(gotcha_FOUND)
    message(STATUS "GOTCHA found, library-call wrapping enabled")
  else()
    message(STATUS "GOTCHA not found, falling back to dlsym interposition; "
                   "calls from dlopened plugins will not be traced")
    set(DATACRUMBS_UTILS_ENABLE_GOTCHA OFF)
  endif()
endif()

set(DATACRUMBS_UTILS_PYTHON_EXECUTABLE "${Python3_EXECUTABLE}")

set(_DATACRUMBS_EXPORTED_KEYS
    HOST
    USER
    INSTALL_USER
    LOG_LEVEL_STR
    MODE_STR
    ENABLE_OPT
    TRACE_ALL_PROCESSES_OPT
    BPF_PRINT_ENABLE
    BPFTIME_COMPATIBLE
    INCLUSION_PATH
    CONFIGURED_TRACE_DIR
    CONFIGURED_LOG_DIR
    CONFIGURED_RUN_DIR
    SCHEDULER_TYPE
    SCHEDULER_JOBID_ENV_VAR
    TRACE_RINGBUF_SIZE_MB
    MAX_RUNTIME_FUNCTIONS
    SKIP_SMALL_EVENTS_THRESHOLD_NS
    TIME_INTERVAL_NS
    TIME_UNIT
    TIME_DIVISOR_NS
    KERNEL_UNAME_R
    KERNEL_HEADERS_PATH
    LIBC_SO
    INSTALL_HOST
    INSTALL_CONFIGS_DIR
    INSTALL_DATA_DIR
    INSTALL_MODULES_DIR
    INSTALL_PROBE_OBJECTS_DIR
    INSTALL_RUNSTATEDIR
    CLIENT_LIB
    TRACE_DIR_PATTERN
    JOB_SCHEDULER
    JOB_ID_VAR
    SERVER_RUN_DIR
    SERVER_RUN_ID_FILE
    SYSTEM_PROBE_FILE
    PROBE_SECRET_FILE
    PROBE_MANAGER_TCP_HOST
    PROBE_MANAGER_TCP_PORT
)

foreach(_dc_key IN LISTS _DATACRUMBS_EXPORTED_KEYS)
  if(DEFINED datacrumbs_${_dc_key} AND NOT "${datacrumbs_${_dc_key}}" STREQUAL "")
    set(DATACRUMBS_${_dc_key} "${datacrumbs_${_dc_key}}")
  endif()
endforeach()

# Pass-through safeguard: if package export is empty, read the value from
# datacrumbs public config header instead of re-detecting locally.
if((NOT DEFINED DATACRUMBS_KERNEL_HEADERS_PATH OR "${DATACRUMBS_KERNEL_HEADERS_PATH}" STREQUAL "")
   AND DEFINED datacrumbs_INSTALL_INCLUDE_DIR
)
  set(_datacrumbs_public_config_header
      "${datacrumbs_INSTALL_INCLUDE_DIR}/datacrumbs/datacrumbs_config.h")
  if(EXISTS "${_datacrumbs_public_config_header}")
    file(READ "${_datacrumbs_public_config_header}" _datacrumbs_public_config_contents)
    string(REGEX MATCH
           "#define[ \t]+DATACRUMBS_KERNEL_HEADERS_PATH[ \t]+\"([^\"]*)\""
           _datacrumbs_kernel_headers_define
           "${_datacrumbs_public_config_contents}")
    if(_datacrumbs_kernel_headers_define)
      set(DATACRUMBS_KERNEL_HEADERS_PATH "${CMAKE_MATCH_1}")
    endif()
  endif()
endif()
message(STATUS "[${UPPER_PROJECT_NAME}] Loaded datacrumbs configuration from package header exports")

macro(datacrumbs_set_default variable_name default_value)
  if(NOT DEFINED ${variable_name} OR "${${variable_name}}" STREQUAL "")
    set(${variable_name} "${default_value}")
  endif()
endmacro()

macro(initialize_datacrumbs_utils_build_variables)
  # These are local build toggles for the extracted utils tree rather than
  # install/runtime settings that belong in the datacrumbs system configuration.
  if(NOT DEFINED DATACRUMBS_BUILD_ONLY)
    set(DATACRUMBS_BUILD_ONLY OFF)
  endif()
  if(NOT DEFINED DATACRUMBS_BPFTIME_COMPATIBLE)
    set(DATACRUMBS_BPFTIME_COMPATIBLE OFF)
  endif()
  if(NOT DEFINED BPFTOOL_EXECUTABLE)
    set(BPFTOOL_EXECUTABLE "NONE")
  endif()
  if(NOT DEFINED DATACRUMBS_KERNEL_VERSION)
    set(DATACRUMBS_KERNEL_VERSION "")
  endif()
  if(NOT DEFINED DATACRUMBS_KERNEL_HEADERS_PATH)
    set(DATACRUMBS_KERNEL_HEADERS_PATH "")
  endif()
  if(NOT DEFINED DATACRUMBS_KERNEL_PATH)
    set(DATACRUMBS_KERNEL_PATH "")
  endif()
endmacro()

set(DATACRUMBS_INSTALL_DIR "${datacrumbs_INSTALL_PREFIX}")
set(DATACRUMBS_PUBLIC_INCLUDE_DIR "${datacrumbs_INSTALL_INCLUDE_DIR}")
set(DATACRUMBS_PUBLIC_COMMON_LIBRARY datacrumbs::datacrumbs_common)

initialize_datacrumbs_utils_build_variables()
load_build_variables()
datacrumbs_set_default(DATACRUMBS_ENABLE_OPT ON)
datacrumbs_set_default(DATACRUMBS_TRACE_ALL_PROCESSES_OPT OFF)
datacrumbs_set_default(DATACRUMBS_BPF_PRINT_ENABLE OFF)
datacrumbs_set_default(DATACRUMBS_INCLUSION_PATH "NONE")
datacrumbs_set_default(DATACRUMBS_CONFIGURED_TRACE_DIR "/tmp")
datacrumbs_set_default(DATACRUMBS_CONFIGURED_LOG_DIR "/tmp")
datacrumbs_set_default(DATACRUMBS_CONFIGURED_RUN_DIR "NONE")
datacrumbs_set_default(DATACRUMBS_MODE_STR "TRACE")
datacrumbs_set_default(DATACRUMBS_HOST "NONE")
datacrumbs_set_default(DATACRUMBS_INSTALL_USER "$ENV{USER}")
datacrumbs_set_default(DATACRUMBS_USER "${DATACRUMBS_INSTALL_USER}")
datacrumbs_set_default(DATACRUMBS_TRACE_RINGBUF_SIZE_MB "16")
datacrumbs_set_default(DATACRUMBS_MAX_RUNTIME_FUNCTIONS "16384")
datacrumbs_set_default(DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS "1000")
datacrumbs_set_default(DATACRUMBS_TIME_INTERVAL_NS "1000000")
# Mirrors the core build: the unit of ts and dur, declared in every trace's time_metric record.
datacrumbs_set_default(DATACRUMBS_TIME_UNIT "NS")
if(DATACRUMBS_TIME_UNIT STREQUAL "NS")
  datacrumbs_set_default(DATACRUMBS_TIME_DIVISOR_NS "1")
elseif(DATACRUMBS_TIME_UNIT STREQUAL "US")
  datacrumbs_set_default(DATACRUMBS_TIME_DIVISOR_NS "1000")
else()
  message(FATAL_ERROR "DATACRUMBS_TIME_UNIT must be NS or US, got '${DATACRUMBS_TIME_UNIT}'")
endif()
datacrumbs_set_default(DATACRUMBS_SCHEDULER_TYPE "FLUX")
datacrumbs_set_default(DATACRUMBS_SCHEDULER_JOBID_ENV_VAR "NONE")
datacrumbs_set_default(DATACRUMBS_LOG_LEVEL_STR "INFO")
derive_configurations()
find_system_details()
include_dependencies()

datacrumbs_set_default(DATACRUMBS_INSTALL_HOST "${DATACRUMBS_HOST}")
datacrumbs_set_default(DATACRUMBS_INSTALL_CONFIGS_DIR "${DATACRUMBS_INSTALL_ETC_CONFIGSDIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_SHARED_DATA_DIR "${DATACRUMBS_INSTALL_DIR}/share/datacrumbs/data")
datacrumbs_set_default(DATACRUMBS_INSTALL_DATA_DIR "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}")
datacrumbs_set_default(
  DATACRUMBS_SYSTEM_PROBE_FILE
  "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/system-probe-${DATACRUMBS_INSTALL_USER}-${DATACRUMBS_HOST}.sqlite"
)
datacrumbs_set_default(
  DATACRUMBS_PROBE_SECRET_FILE
  "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/.datacrumbs-probe-secret"
)
datacrumbs_set_default(
  DATACRUMBS_PROBE_MANAGER_SOCKET_PATH
  "${DATACRUMBS_INSTALL_SHARED_DATA_DIR}/datacrumbs-probe-manager.sock"
)
datacrumbs_set_default(DATACRUMBS_PROBE_MANAGER_TCP_HOST "127.0.0.1")
datacrumbs_set_default(DATACRUMBS_PROBE_MANAGER_TCP_PORT "43123")
datacrumbs_set_default(DATACRUMBS_TRACE_DIR_PATTERN "${DATACRUMBS_CONFIGURED_TRACE_DIR}/%YY%/%MM%/%DD%")
datacrumbs_set_default(DATACRUMBS_CLIENT_LIB "${DATACRUMBS_INSTALL_LIB_DIR}/libdatacrumbs_client.so")
datacrumbs_set_default(DATACRUMBS_JOB_SCHEDULER "${DATACRUMBS_SCHEDULER_TYPE}")
datacrumbs_set_default(DATACRUMBS_JOB_ID_VAR "${DATACRUMBS_SCHEDULER_JOBID_ENV_VAR}")
if(DATACRUMBS_ENABLE_INCLUSION_PATH)
  datacrumbs_set_default(DATACRUMBS_INCLUSION_PATHS "${DATACRUMBS_INCLUSION_PATH}")
else()
  datacrumbs_set_default(DATACRUMBS_INCLUSION_PATHS "")
endif()
datacrumbs_set_default(DATACRUMBS_SERVER_RUN_DIR "${DATACRUMBS_INSTALL_RUNSTATEDIR}/datacrumbs")
datacrumbs_set_default(DATACRUMBS_SERVER_RUN_ID_FILE "${DATACRUMBS_SERVER_RUN_DIR}/datacrumbs.runid")
datacrumbs_set_default(DATACRUMBS_INSTALL_PREFIX "${DATACRUMBS_INSTALL_DIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_BIN_DIR "${DATACRUMBS_INSTALL_BINARYDIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_SBIN_DIR "${DATACRUMBS_INSTALL_SBINARYDIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_LIBEXEC_DIR "${DATACRUMBS_INSTALL_LIBEXEC}")
datacrumbs_set_default(DATACRUMBS_INSTALL_ETC_DIR "${DATACRUMBS_INSTALL_SYSCONFDIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_MODULES_DIR "${DATACRUMBS_INSTALL_ETC_MODULESDIR}")
datacrumbs_set_default(DATACRUMBS_INSTALL_PROBE_OBJECTS_DIR "${DATACRUMBS_INSTALL_LIBEXEC}/objects")

set(DATACRUMBS_UTILS_STAGED_INCLUDE_ROOT "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs")
set(DATACRUMBS_UTILS_GENERATED_CONFIG_HEADER
  "${CMAKE_INCLUDE_OUTPUT_DIRECTORY}/datacrumbs/datacrumbs_utils_config.h"
)
set(DATACRUMBS_UTILS_BUILD_SHARE_DIR "${CMAKE_BINARY_DIR}/share/datacrumbs")
set(DATACRUMBS_UTILS_BUILD_DATA_DIR "${DATACRUMBS_UTILS_BUILD_SHARE_DIR}/data")
datacrumbs_set_default(DATACRUMBS_INSTALL_SHARE_DIR "${DATACRUMBS_INSTALL_DIR}/share/datacrumbs")
datacrumbs_set_default(DATACRUMBS_INSTALL_DATA_SHARE_DIR "${DATACRUMBS_INSTALL_SHARE_DIR}/data")
datacrumbs_set_default(DATACRUMBS_INSTALL_CONFIGS_DIR "${DATACRUMBS_INSTALL_DIR}/etc/datacrumbs/configs")
datacrumbs_set_default(
  DATACRUMBS_INSTALL_ETC_MODULESDIR
  "${DATACRUMBS_INSTALL_DIR}/${CMAKE_INSTALL_SYSCONFDIR}/${DATACRUMBS_UTILS_MODULE_NAME}/${CMAKE_INSTALL_MODULES_DIR}"
)
set(DATACRUMBS_UTILS_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(DATACRUMBS_UTILS_INSTALL_BIN_DIR "${DATACRUMBS_INSTALL_BINARYDIR}")
set(DATACRUMBS_UTILS_INSTALL_SBIN_DIR "${DATACRUMBS_INSTALL_SBINARYDIR}")
set(DATACRUMBS_UTILS_INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(DATACRUMBS_UTILS_INSTALL_LIBEXEC_DIR "${DATACRUMBS_INSTALL_LIBEXEC}")
set(DATACRUMBS_UTILS_INSTALL_ETC_DIR "${DATACRUMBS_INSTALL_SYSCONFDIR}")
set(DATACRUMBS_UTILS_INSTALL_SHARE_DIR "${CMAKE_INSTALL_PREFIX}/share/datacrumbs")
set(DATACRUMBS_UTILS_INSTALL_DATA_DIR "${DATACRUMBS_UTILS_INSTALL_SHARE_DIR}/data")
set(DATACRUMBS_UTILS_INSTALL_MODULES_DIR "${DATACRUMBS_INSTALL_ETC_MODULESDIR}")
set(DATACRUMBS_UTILS_BUILD_MODULEFILE
    "${CMAKE_MODULES_OUTPUT_DIRECTORY}/${DATACRUMBS_UTILS_MODULE_NAME}/${DATACRUMBS_UTILS_RELEASE_VERSION_STRING}.lua"
)
set(DATACRUMBS_UTILS_BUILD_TRACK_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_track")
set(DATACRUMBS_UTILS_BUILD_UNTRACK_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_untrack")
set(DATACRUMBS_UTILS_BUILD_WRAP_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_wrap")
set(DATACRUMBS_UTILS_BUILD_SALLOC_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_salloc")
set(DATACRUMBS_UTILS_BUILD_SBATCH_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_sbatch")
set(DATACRUMBS_UTILS_BUILD_SETUP_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_setup")
set(DATACRUMBS_UTILS_BUILD_UTILITY_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_utility")
set(DATACRUMBS_UTILS_BUILD_RUN_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_run")
set(DATACRUMBS_UTILS_BUILD_STOP_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_stop")
set(DATACRUMBS_UTILS_BUILD_SERVICE_WRAPPER_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_service_wrapper")
set(DATACRUMBS_UTILS_BUILD_DEPLOY_SERVICES_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_deploy_services")
set(DATACRUMBS_UTILS_BUILD_DEPLOY_HOOKS_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_deploy_scheduler_hooks")
set(DATACRUMBS_UTILS_BUILD_INSTALL_FLUX_PLUGIN_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_install_flux_plugin")
set(DATACRUMBS_UTILS_BUILD_CLUSTER_SETUP_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_cluster_setup")
set(DATACRUMBS_UTILS_BUILD_SQLITE_EXTRACT_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_sqlite_extract")
set(DATACRUMBS_UTILS_BUILD_CONFIGURE_TEMPLATE_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_configure_template")
set(DATACRUMBS_UTILS_INSTALL_PROBE_WRAPPER "${CMAKE_BINARY_DIR}/datacrumbs_probe_configurator.install")
set(DATACRUMBS_UTILS_BUILD_ARGS_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_args")
set(DATACRUMBS_UTILS_BUILD_LOGGING_SCRIPT "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_logging")
set(DATACRUMBS_UTILS_INSTALL_ARGS_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_args.install")
set(DATACRUMBS_UTILS_INSTALL_LOGGING_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_logging.install")
set(DATACRUMBS_UTILS_INSTALL_TRACK_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_track.install")
set(DATACRUMBS_UTILS_INSTALL_UNTRACK_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_untrack.install")
set(DATACRUMBS_UTILS_INSTALL_WRAP_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_wrap.install")
set(DATACRUMBS_UTILS_INSTALL_SALLOC_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_salloc.install")
set(DATACRUMBS_UTILS_INSTALL_SBATCH_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_sbatch.install")
set(DATACRUMBS_UTILS_INSTALL_SETUP_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_setup.install")
set(DATACRUMBS_UTILS_INSTALL_UTILITY_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_utility.install")
set(DATACRUMBS_UTILS_INSTALL_RUN_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_run.install")
set(DATACRUMBS_UTILS_INSTALL_STOP_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_stop.install")
set(DATACRUMBS_UTILS_INSTALL_SERVICE_WRAPPER_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_service_wrapper.install")
set(DATACRUMBS_UTILS_INSTALL_DEPLOY_SERVICES_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_deploy_services.install")
set(DATACRUMBS_UTILS_INSTALL_DEPLOY_HOOKS_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_deploy_scheduler_hooks.install")
set(DATACRUMBS_UTILS_INSTALL_INSTALL_FLUX_PLUGIN_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_install_flux_plugin.install")
set(DATACRUMBS_UTILS_INSTALL_CLUSTER_SETUP_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_cluster_setup.install")
set(DATACRUMBS_UTILS_INSTALL_SQLITE_EXTRACT_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_sqlite_extract.install")
set(DATACRUMBS_UTILS_INSTALL_CONFIGURE_TEMPLATE_SCRIPT "${CMAKE_BINARY_DIR}/datacrumbs_configure_template.install")
set(DATACRUMBS_UTILS_BUILD_PYTHON_DIR "${CMAKE_LIBEXEC_OUTPUT_DIRECTORY}/python")
set(DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR "${CMAKE_BINARY_DIR}/python-install")
set(DATACRUMBS_UTILS_DD_PRELOAD_TEST_SCRIPT "${CMAKE_BINARY_DIR}/dd_preload_test.sh")
set(DATACRUMBS_UTILS_BUILD_CLIENT_SO "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libdatacrumbs_client.so")

file(MAKE_DIRECTORY "${DATACRUMBS_UTILS_BUILD_DATA_DIR}")

function(stage_datacrumbs_header source_path relative_dest)
  get_filename_component(dest_dir "${DATACRUMBS_UTILS_STAGED_INCLUDE_ROOT}/${relative_dest}" DIRECTORY)
  file(MAKE_DIRECTORY "${dest_dir}")
  configure_file("${source_path}" "${DATACRUMBS_UTILS_STAGED_INCLUDE_ROOT}/${relative_dest}" COPYONLY)
endfunction()

set(DATACRUMBS_UTILS_MOVED_HEADERS
    datacrumbs/utils/common/configuration_manager.h
    datacrumbs/utils/explorer/probe_explorer.h
    datacrumbs/utils/explorer/mechanism/elf_capture.h
    datacrumbs/utils/explorer/mechanism/header_capture.h
    datacrumbs/utils/explorer/mechanism/ksym_capture.h
    datacrumbs/utils/explorer/mechanism/usdt_functions.h
  datacrumbs/utils/client/library.h
)

foreach(header IN LISTS DATACRUMBS_UTILS_MOVED_HEADERS)
  stage_datacrumbs_header("${CMAKE_CURRENT_SOURCE_DIR}/src/${header}" "${header}")
endforeach()
# Client modules this build contains. Decided before the generated config header is written, since
# the one client constructor compiles its calls against these.
datacrumbs_set_default(DATACRUMBS_LIBCLANG "/usr/lib/x86_64-linux-gnu/libclang-14.so.1")
option(DATACRUMBS_UTILS_HAVE_IBVERBS "Build the ibverbs client module into the client" ON)
option(DATACRUMBS_UTILS_HAVE_DOCA "Build the DOCA client module into the client" ON)
# Needs libclang to generate the wrap list. Still an option: a build that has libclang may not want
# 2094 symbols wrapped.
if(EXISTS "${DATACRUMBS_LIBCLANG}" AND EXISTS "${DATACRUMBS_PYLIB}/clang/cindex.py")
  set(_dc_api_wrap_default ON)
else()
  set(_dc_api_wrap_default OFF)
endif()
option(DATACRUMBS_UTILS_HAVE_API_WRAP "Build the wrapped API surface into the client"
       ${_dc_api_wrap_default})
if(DATACRUMBS_UTILS_HAVE_API_WRAP AND NOT _dc_api_wrap_default)
  message(FATAL_ERROR "DATACRUMBS_UTILS_HAVE_API_WRAP needs libclang and its python bindings; "
                      "looked for ${DATACRUMBS_LIBCLANG} and ${DATACRUMBS_PYLIB}/clang/cindex.py")
endif()
message(STATUS "             - client modules: ibverbs=${DATACRUMBS_UTILS_HAVE_IBVERBS} "
               "doca=${DATACRUMBS_UTILS_HAVE_DOCA} api=${DATACRUMBS_UTILS_HAVE_API_WRAP}")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/configure_files/datacrumbs_utils_config.h.in"
  "${DATACRUMBS_UTILS_GENERATED_CONFIG_HEADER}"
  @ONLY
)
include_directories("${DATACRUMBS_PUBLIC_INCLUDE_DIR}")
include_directories("${CMAKE_INCLUDE_OUTPUT_DIRECTORY}")
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/etc/datacrumbs/modulefiles/module.lua.in"
  "${DATACRUMBS_UTILS_BUILD_MODULEFILE}"
  @ONLY
)

message(STATUS "[${UPPER_PROJECT_NAME}] Configured datacrumbs-utils")
message(STATUS "             - DATACRUMBS_HOST: ${DATACRUMBS_HOST}")
message(STATUS "             - DATACRUMBS_USER: ${DATACRUMBS_USER}")
message(STATUS "             - DATACRUMBS_INSTALL_USER: ${DATACRUMBS_INSTALL_USER}")
message(STATUS "             - DATACRUMBS_LOG_LEVEL: ${DATACRUMBS_LOG_LEVEL}")
message(STATUS "             - DATACRUMBS_MODE: ${DATACRUMBS_MODE}")
message(STATUS "             - DATACRUMBS_ENABLE: ${DATACRUMBS_ENABLE}")
message(STATUS "             - DATACRUMBS_TRACE_ALL_PROCESSES: ${DATACRUMBS_TRACE_ALL_PROCESSES}")
message(STATUS "             - DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS: ${DATACRUMBS_SKIP_SMALL_EVENTS_THRESHOLD_NS}")
message(STATUS "             - DATACRUMBS_MAX_RUNTIME_FUNCTIONS: ${DATACRUMBS_MAX_RUNTIME_FUNCTIONS}")
message(STATUS "             - DATACRUMBS_TRACE_RINGBUF_SIZE_MB: ${DATACRUMBS_TRACE_RINGBUF_SIZE_MB}")
message(STATUS "             - DATACRUMBS_TIME_INTERVAL_NS: ${DATACRUMBS_TIME_INTERVAL_NS}")
message(STATUS "             - DATACRUMBS_BPF_PRINT_ENABLE_FLAG: ${DATACRUMBS_BPF_PRINT_ENABLE_FLAG}")
message(STATUS "             - DATACRUMBS_BPFTIME_COMPATIBLE_FLAG: ${DATACRUMBS_BPFTIME_COMPATIBLE_FLAG}")
message(STATUS "             - DATACRUMBS_ENABLE_INCLUSION_PATH: ${DATACRUMBS_ENABLE_INCLUSION_PATH}")
message(STATUS "             - DATACRUMBS_INCLUSION_PATH: ${DATACRUMBS_INCLUSION_PATH}")
message(STATUS "             - DATACRUMBS_KERNEL_UNAME_R: ${DATACRUMBS_KERNEL_UNAME_R}")
message(STATUS "             - DATACRUMBS_KERNEL_HEADERS_PATH: ${DATACRUMBS_KERNEL_HEADERS_PATH}")
message(STATUS "             - DATACRUMBS_LIBC_SO: ${DATACRUMBS_LIBC_SO}")
message(STATUS "             - DATACRUMBS_CONFIGURED_TRACE_DIR: ${DATACRUMBS_CONFIGURED_TRACE_DIR}")
message(STATUS "             - DATACRUMBS_CONFIGURED_LOG_DIR: ${DATACRUMBS_CONFIGURED_LOG_DIR}")
message(STATUS "             - DATACRUMBS_SCHEDULER_TYPE: ${DATACRUMBS_SCHEDULER_TYPE}")
message(STATUS "             - DATACRUMBS_SCHEDULER_JOBID_ENV_VAR: ${DATACRUMBS_SCHEDULER_JOBID_ENV_VAR}")
message(STATUS "             - DATACRUMBS_PROBE_MANAGER_TCP_HOST: ${DATACRUMBS_PROBE_MANAGER_TCP_HOST}")
message(STATUS "             - DATACRUMBS_PROBE_MANAGER_TCP_PORT: ${DATACRUMBS_PROBE_MANAGER_TCP_PORT}")
message(STATUS "             - Build data dir: ${DATACRUMBS_UTILS_BUILD_DATA_DIR}")
message(STATUS "             - Install configs dir: ${DATACRUMBS_INSTALL_CONFIGS_DIR}")
message(STATUS "             - Install data dir: ${DATACRUMBS_INSTALL_DATA_SHARE_DIR}")
message(STATUS "             - DATACRUMBS_INSTALL_DIR: ${DATACRUMBS_INSTALL_DIR}")
message(STATUS "             - DATACRUMBS_PUBLIC_INCLUDE_DIR: ${DATACRUMBS_PUBLIC_INCLUDE_DIR}")
message(STATUS "             - Client library path: ${DATACRUMBS_UTILS_BUILD_CLIENT_SO}")
install(
  FILES "${DATACRUMBS_UTILS_BUILD_MODULEFILE}"
  DESTINATION "${DATACRUMBS_INSTALL_ETC_MODULESDIR}/${DATACRUMBS_UTILS_MODULE_NAME}"
)
# Shipped for DPA kernels to include: the device side of the join capture is compiled into the
# application by dpacc, not into any library here.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/include/datacrumbs/utils/dpa/dc_dpa_trace.h"
        DESTINATION "${DATACRUMBS_INSTALL_INCLUDE_DIR}/datacrumbs/utils/dpa")
install(FILES "${DATACRUMBS_UTILS_GENERATED_CONFIG_HEADER}"
        DESTINATION "${DATACRUMBS_INSTALL_INCLUDE_DIR}/datacrumbs")

# Split out so the preloaded client links environment reading without the yaml, json and filesystem
# work the rest of the manager does.
set(DATACRUMBS_UTILS_RUNTIME_CONFIG_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/runtime_configuration.cpp")

# Anything that writes a trace needs this: the sink maps the timesync snapshot, and the path comes
# from the configuration rather than from getenv at the point of use.
add_library(datacrumbs_runtime_config OBJECT ${DATACRUMBS_UTILS_RUNTIME_CONFIG_SRC})
set_property(TARGET datacrumbs_runtime_config PROPERTY POSITION_INDEPENDENT_CODE ON)

set(DATACRUMBS_UTILS_COMMON_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/configuration_manager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/configuration_manager.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/probe_signing_service.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/probe_signing_service.h"
)

# One client library, not one per module: with seven preloadable objects the init order came from
# how a user spelled LD_PRELOAD, and that order is load bearing. Two of them wrapping one symbol by
# different mechanisms segfaulted, and each opened its own sink.
set(DATACRUMBS_UTILS_CLIENT_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/library.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/library.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/clock.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/common/pfw_sink.h"
)
add_library(datacrumbs_client SHARED ${DATACRUMBS_UTILS_CLIENT_SRC})
set_target_properties(
  datacrumbs_client
  PROPERTIES
    OUTPUT_NAME datacrumbs_client
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
)
target_link_libraries(datacrumbs_client PRIVATE datacrumbs_runtime_config
                      ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} OpenSSL::Crypto
                      ZLIB::ZLIB ${CMAKE_DL_LIBS})
install(TARGETS datacrumbs_client LIBRARY DESTINATION "${DATACRUMBS_INSTALL_LIB_DIR}")

add_custom_target(
  clean_all
  COMMAND "${CMAKE_COMMAND}" -E echo "Dummy clean_all target for datacrumbs-utils"
  COMMENT "No generated BPF artifacts to clean in datacrumbs-utils"
)

set(DATACRUMBS_UTILS_PROBE_CONFIGURATOR_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/probe_configurator_main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/probe_explorer.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/probe_explorer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/elf_capture.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/elf_capture.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/header_capture.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/header_capture.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/ksym_capture.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/explorer/mechanism/usdt_functions.h"
)
add_executable(datacrumbs_probe_configurator ${DATACRUMBS_UTILS_PROBE_CONFIGURATOR_SRC} ${DATACRUMBS_UTILS_COMMON_SRC})
set_target_properties(datacrumbs_probe_configurator PROPERTIES OUTPUT_NAME datacrumbs_probe_configurator_exec)
target_link_libraries(datacrumbs_probe_configurator datacrumbs_runtime_config ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} ${DEPENDENCY_LIB} yaml-cpp OpenSSL::Crypto)
add_dependencies(datacrumbs_probe_configurator datacrumbs_client clean_all)
install(TARGETS datacrumbs_probe_configurator RUNTIME DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}")

# dc_timesync daemon: HW-timestamped UDP exchange per DPU; publishes the seqlock snapshot the server
# reads to remap events onto a shared cross-node axis. Standalone (libm for the line fit).
add_executable(dc_timesync "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/timesync/dc_timesync.c")
target_link_libraries(dc_timesync ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} m ibverbs)
install(TARGETS dc_timesync RUNTIME DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}")

# timesync remap plugin: dlopen'd by the server (DATACRUMBS_PLUGINS) to remap events onto the shared
# axis the dc_timesync daemon publishes. A MODULE (load-only, no link-time consumers).
add_library(datacrumbs_plugin_timesync MODULE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/plugins/timesync/timesync_remap.cpp")
# Every plugin reading ConfigurationManager::runtime() must link datacrumbs_runtime_config. The
# server dlopens plugins and does not export that symbol, so omitting it fails the load with one
# ERROR line while the server carries on and writes a trace that looks complete.
target_link_libraries(datacrumbs_plugin_timesync datacrumbs_runtime_config
                      ${DATACRUMBS_PUBLIC_COMMON_LIBRARY})
install(TARGETS datacrumbs_plugin_timesync
        LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}/datacrumbs/plugins")

# pmu plugin: opens the hw counters (DATACRUMBS_HW_COUNTERS) and names the per-event deltas the core
# BPF captures. Core does the capture-time read; this plugin owns the counter policy.
add_library(datacrumbs_plugin_pmu MODULE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/plugins/pmu/pmu_plugin.cpp")
target_link_libraries(datacrumbs_plugin_pmu datacrumbs_runtime_config
                      ${DATACRUMBS_PUBLIC_COMMON_LIBRARY})
install(TARGETS datacrumbs_plugin_pmu
        LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}/datacrumbs/plugins")



# interposition client: LD_PRELOAD lib that traces libc I/O in userspace (no uprobe/server) and
# writes its own global-epoch .pfw, merged with the server trace at collect.
add_library(datacrumbs_mod_stdio OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/stdio/library.cpp")
target_link_libraries(datacrumbs_mod_stdio PRIVATE ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} gotcha)
set_property(TARGET datacrumbs_mod_stdio PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(datacrumbs_client PRIVATE datacrumbs_mod_stdio)

add_library(datacrumbs_mod_posix OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/dpa/library.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/posix/library.cpp")
target_link_libraries(datacrumbs_mod_posix PRIVATE ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} gotcha)
set_property(TARGET datacrumbs_mod_posix PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(datacrumbs_client PRIVATE datacrumbs_mod_posix)

# Window boundaries written through the same sink as every other client record, so a harness never
# has to reproduce the timesync mapping to say when a configuration ran.
add_executable(datacrumbs_window_mark
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/window_mark.cpp")
target_link_libraries(datacrumbs_window_mark datacrumbs_runtime_config ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} OpenSSL::Crypto
                      ZLIB::ZLIB ${CMAKE_DL_LIBS})
install(TARGETS datacrumbs_window_mark RUNTIME DESTINATION "${DATACRUMBS_UTILS_INSTALL_BIN_DIR}")

# dftracer clock shim: LD_PRELOAD with dftracer (unmodified) so its gettimeofday timestamps become
# the dc_timesync global epoch. Reuses the shared timesync reader.
add_library(datacrumbs_mod_clock OBJECT
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/clock/library.cpp")
target_link_libraries(datacrumbs_mod_clock PRIVATE ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} gotcha)
set_property(TARGET datacrumbs_mod_clock PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(datacrumbs_client PRIVATE datacrumbs_mod_clock)

# RDMA hw-timestamp capture: LD_PRELOAD upgrades ibv_create_cq CQs to timestamped extended CQs and
# emits per-completion NIC hw timestamps on the global epoch. Uses dlvsym for verbs symbols (no
# -libverbs link); needs infiniband/verbs.h in the sysroot. Enable at runtime with DC_HWTS=1.
if(DATACRUMBS_UTILS_HAVE_IBVERBS)
  add_library(datacrumbs_mod_ibverbs OBJECT
      "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/ibverbs/library.cpp")
  target_link_libraries(datacrumbs_mod_ibverbs PRIVATE ${DATACRUMBS_PUBLIC_COMMON_LIBRARY})
  set_property(TARGET datacrumbs_mod_ibverbs PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(datacrumbs_client PRIVATE datacrumbs_mod_ibverbs)
endif()

# DOCA-native variant: same source with the DATACRUMBS_DOCA_HWTS block (frida-gum inline hook on the
# DOCA CQ poll to capture the kernel-bypass fabric wire). Built only when the frida-gum devkit is
# present (DOCA/DevX is DPU-only), so ordinary builds are unaffected.
datacrumbs_set_default(FRIDA_GUM_DIR
    "/home/sinurat1/projects/dpu-explainability/deps/src/bpftime/build-arm64/FridaGum-prefix/src/FridaGum")
if(EXISTS "${FRIDA_GUM_DIR}/libfrida-gum.a")
  add_library(datacrumbs_rdma_hwts_doca SHARED
      "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/ibverbs/library.cpp")
  target_compile_definitions(datacrumbs_rdma_hwts_doca PRIVATE DATACRUMBS_DOCA_HWTS)
  target_include_directories(datacrumbs_rdma_hwts_doca PRIVATE "${FRIDA_GUM_DIR}")
  target_link_libraries(datacrumbs_rdma_hwts_doca ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} OpenSSL::Crypto
                        ZLIB::ZLIB "${FRIDA_GUM_DIR}/libfrida-gum.a" ${CMAKE_DL_LIBS} pthread resolv m)
  install(TARGETS datacrumbs_rdma_hwts_doca LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}")
else()
  message(STATUS "frida-gum devkit not at ${FRIDA_GUM_DIR}; skipping datacrumbs_rdma_hwts_doca")
endif()


# Fixed-engine hw timestamps: LD_PRELOAD reads the mlx5 CQEs the DOCA engines complete on. Those CQs
# are built through mlx5dv_devx_obj_create, not ibv_create_cq, so the ibverbs shim above cannot see
# them. Enable at runtime with DC_ENGINE_HWTS=1.
if(DATACRUMBS_UTILS_HAVE_DOCA)
  add_library(datacrumbs_mod_doca OBJECT
      "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/doca/library.cpp")
  target_link_libraries(datacrumbs_mod_doca PRIVATE ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} gotcha)
  set_property(TARGET datacrumbs_mod_doca PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(datacrumbs_client PRIVATE datacrumbs_mod_doca)
endif()

# Classified API surface, wrapped with GOTCHA. The wrap list is generated from the headers by
# reverse-eng/inventory/gen_gotcha.py and filtered through the symbol classification, so what gets
# wrapped follows the inventory rather than what was convenient to hand-write. GOTCHA rather than
# uprobes because a uprobe traps inside the function and on BlueField that breaks libmlx5's
# write-combining doorbell burst. Enable at runtime with DC_API_TRACE=1.
if(DATACRUMBS_UTILS_ENABLE_GOTCHA)
  # The wrap list is generated at build time from the headers this build actually compiles against.
  # A checked-in list drifts: the same libclang run over a different machine's rdma-core produced a
  # different set, so a stale list would emit prototypes that do not match the target.
  #
  # Needs libclang plus its python bindings. DATACRUMBS_LIBCLANG and DATACRUMBS_PYLIB point at them;
  # both come from the out-of-tree deps prefix, since the build node has no network to install them.
  datacrumbs_set_default(DATACRUMBS_LIBCLANG "/usr/lib/x86_64-linux-gnu/libclang-14.so.1")
  datacrumbs_set_default(DATACRUMBS_PYLIB
      "/home/sinurat1/projects/dpu-explainability/deps/pylib")
  # The rdma-core headers this build compiles against. Not in the cross sysroot - they are
  # arch-independent, so the cross build uses the build machine's copy, and the wrap list must be
  # generated from that same copy or the prototypes will not match.
  datacrumbs_set_default(DATACRUMBS_IBVERBS_INCLUDE "/usr/include")
  # The device op tables live in the kernel's mlx5 headers, which no userspace build can compile;
  # the generator reads them as text, since a table of names and numbers needs no parser. The OFED
  # driver source is preferred over a distribution kernel: it is the provider these traces come from,
  # and it carries opcodes a stock header can lack. Verified equal on every shared opcode.
  if(NOT DATACRUMBS_MLX5_KERNEL_INCLUDE)
    file(GLOB _dc_ofed_mlx5 "/usr/src/mlnx-ofed-kernel-*/include/linux/mlx5")
    list(SORT _dc_ofed_mlx5)
    list(REVERSE _dc_ofed_mlx5)
    foreach(_dc_cand IN LISTS _dc_ofed_mlx5)
      if(EXISTS "${_dc_cand}/device.h")
        set(DATACRUMBS_MLX5_KERNEL_INCLUDE "${_dc_cand}")
        break()
      endif()
    endforeach()
  endif()
  datacrumbs_set_default(DATACRUMBS_MLX5_KERNEL_INCLUDE
      "/usr/src/linux-bluefield-headers-5.15.0-1065/include/linux/mlx5")
  # DOCA headers come from the target, not the build machine: the host install is a subset (27 of
  # 93). The DPA device headers are excluded by the generator, which cannot parse __dpa_global__ and
  # would gain nothing anyway - that code runs on the DPA cores, where there is no GOT to rewrite.
  datacrumbs_set_default(DATACRUMBS_DOCA_INCLUDE
      "/home/sinurat1/projects/dpu-explainability/cross/deps/doca/include")
  set(_dc_wrap_hdrs "${DATACRUMBS_IBVERBS_INCLUDE}/infiniband/verbs.h"
                    "${DATACRUMBS_IBVERBS_INCLUDE}/infiniband/mlx5dv.h")
  if(EXISTS "${DATACRUMBS_DOCA_INCLUDE}")
    file(GLOB _dc_doca_hdrs "${DATACRUMBS_DOCA_INCLUDE}/doca_*.h")
    list(FILTER _dc_doca_hdrs EXCLUDE REGEX "doca_dpa_dev")
    list(APPEND _dc_wrap_hdrs ${_dc_doca_hdrs})
  endif()
  # FlexIO ships outside the DOCA include tree, so globbing DOCA alone leaves its 159 host symbols
  # inventoried and unwrapped. Only the host side: libflexio-dev runs on the DPA cores, where there
  # is no GOT to rewrite and the headers do not parse for a host target.
  datacrumbs_set_default(DATACRUMBS_FLEXIO_INCLUDE
      "/home/sinurat1/projects/dpu-explainability/cross/deps/flexio/include")
  if(EXISTS "${DATACRUMBS_FLEXIO_INCLUDE}/libflexio/flexio.h")
    list(APPEND _dc_wrap_hdrs "${DATACRUMBS_FLEXIO_INCLUDE}/libflexio/flexio.h")
  endif()
  # PKA is a second crypto engine, reached through its own library rather than DOCA, so nothing in
  # the DOCA or FlexIO trees declares it.
  datacrumbs_set_default(DATACRUMBS_PKA_INCLUDE
      "/home/sinurat1/projects/dpu-explainability/cross/deps/pka/include")
  if(EXISTS "${DATACRUMBS_PKA_INCLUDE}/pka.h")
    file(GLOB _dc_pka_hdrs "${DATACRUMBS_PKA_INCLUDE}/pka*.h")
    list(APPEND _dc_wrap_hdrs ${_dc_pka_hdrs})
  endif()
# dpa telemetry plugin: samples the DPA cores' own per-thread counters, which no host-side shim can
# see. The library path is derived from the header path so the plugin follows whichever DOCA the
# wrap list was generated against.
get_filename_component(DATACRUMBS_DOCA_ROOT "${DATACRUMBS_DOCA_INCLUDE}" DIRECTORY)
datacrumbs_set_default(DATACRUMBS_DOCA_LIB "${DATACRUMBS_DOCA_ROOT}/lib/aarch64-linux-gnu")
# The header alone is not enough: it sits in cross deps both targets share, so a host build found it
# and failed on an incompatible -ldoca_common. DPA cores are BlueField silicon, so aarch64 only.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$"
   AND EXISTS "${DATACRUMBS_DOCA_INCLUDE}/doca_telemetry_dpa.h"
   AND EXISTS "${DATACRUMBS_DOCA_LIB}")
  add_library(datacrumbs_plugin_dpa_telemetry MODULE
      "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/plugins/dpa_telemetry/dpa_telemetry.cpp")
  target_include_directories(datacrumbs_plugin_dpa_telemetry PRIVATE "${DATACRUMBS_DOCA_INCLUDE}")
  # Every doca_telemetry_dpa_* symbol is DOCA_EXPERIMENTAL with no stable alternative;
  # this is DOCA's own opt-in for that, not a warning silencer.
  target_compile_definitions(datacrumbs_plugin_dpa_telemetry PRIVATE DOCA_ALLOW_EXPERIMENTAL_API)
  target_link_libraries(datacrumbs_plugin_dpa_telemetry datacrumbs_runtime_config
                        ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} doca_telemetry doca_common)
  target_link_directories(datacrumbs_plugin_dpa_telemetry PRIVATE "${DATACRUMBS_DOCA_LIB}")
  install(TARGETS datacrumbs_plugin_dpa_telemetry
          LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}/datacrumbs/plugins")
else()
  message(STATUS "not an aarch64 target with DOCA libraries; skipping the DPA telemetry plugin")
endif()

# doca diag plugin: samples the device's own diagnostic counters (physical port, PCIe link bytes and
# latency, internal cache, completion engine CQEs). Same aarch64 + DOCA gate as the DPA plugin.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$"
   AND EXISTS "${DATACRUMBS_DOCA_INCLUDE}/doca_telemetry_diag.h"
   AND EXISTS "${DATACRUMBS_DOCA_LIB}")
  add_library(datacrumbs_plugin_doca_diag MODULE
      "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/plugins/doca_diag/doca_diag.cpp")
  target_include_directories(datacrumbs_plugin_doca_diag PRIVATE "${DATACRUMBS_DOCA_INCLUDE}")
  target_compile_definitions(datacrumbs_plugin_doca_diag PRIVATE DOCA_ALLOW_EXPERIMENTAL_API)
  target_link_libraries(datacrumbs_plugin_doca_diag datacrumbs_runtime_config
                        ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} doca_telemetry doca_common)
  target_link_directories(datacrumbs_plugin_doca_diag PRIVATE "${DATACRUMBS_DOCA_LIB}")
  install(TARGETS datacrumbs_plugin_doca_diag
          LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}/datacrumbs/plugins")
else()
  message(STATUS "not an aarch64 target with DOCA libraries; skipping the DOCA diag plugin")
endif()

  set(_dc_wrap_out "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client/api_wrap_list.h")
  set(_dc_wrap_split_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client")
  set(_dc_wrap_split)
  foreach(_lib doca ibverbs mlx5 flexio pka other)
    list(APPEND _dc_wrap_split "${_dc_wrap_split_dir}/${_lib}/api.h")
  endforeach()
  list(APPEND _dc_wrap_split "${_dc_wrap_split_dir}/api_decoders.h")
  set(_dc_ops_out "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client/mlx5_ops.h")
  set(_dc_tramp_out "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client/api_tramp_list.h")
  set(_dc_undecl_out
      "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client/api_undeclared_list.h")
  set(_dc_devx_h "${DATACRUMBS_MLX5_KERNEL_INCLUDE}/mlx5_ifc.h")
  set(_dc_wqe_h "${DATACRUMBS_MLX5_KERNEL_INCLUDE}/device.h")

  # Outside the libclang guard on purpose: rdma_hwts includes this table unconditionally, and
  # extracting constants is text work, so tying it to the wrap list would break the shim on a build
  # machine that merely lacks the python bindings.
  if(NOT EXISTS "${_dc_wqe_h}")
    message(FATAL_ERROR
        "mlx5 kernel headers not found at ${DATACRUMBS_MLX5_KERNEL_INCLUDE}. "
        "Set DATACRUMBS_MLX5_KERNEL_INCLUDE to a directory holding device.h and mlx5_ifc.h.")
  endif()
  add_custom_command(
    OUTPUT "${_dc_ops_out}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client"
    COMMAND "${DATACRUMBS_UTILS_PYTHON_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_gotcha.py" --only-decoders
            --decode-constants "MLX5_CMD_OP=${_dc_devx_h}"
            --decode-constants "MLX5_OPCODE=${_dc_wqe_h}"
            --output "${_dc_ops_out}"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_gotcha.py" "${_dc_devx_h}"
            "${_dc_wqe_h}"
    COMMENT "Generating mlx5 device op tables from ${DATACRUMBS_MLX5_KERNEL_INCLUDE}"
    VERBATIM)
  add_custom_target(datacrumbs_mlx5_ops DEPENDS "${_dc_ops_out}")
  if(TARGET datacrumbs_mod_ibverbs)
    add_dependencies(datacrumbs_mod_ibverbs datacrumbs_mlx5_ops)
    target_include_directories(datacrumbs_mod_ibverbs
        PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
  endif()
  if(TARGET datacrumbs_rdma_hwts_doca)
    add_dependencies(datacrumbs_rdma_hwts_doca datacrumbs_mlx5_ops)
    target_include_directories(datacrumbs_rdma_hwts_doca
        PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
  endif()

  if(EXISTS "${DATACRUMBS_LIBCLANG}" AND EXISTS "${DATACRUMBS_PYLIB}/clang/cindex.py")
    add_custom_command(
      OUTPUT "${_dc_wrap_out}" "${_dc_tramp_out}" ${_dc_wrap_split}
      COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated/datacrumbs/utils/client"
      COMMAND ${CMAKE_COMMAND} -E env "PYTHONPATH=${DATACRUMBS_PYLIB}"
              "${DATACRUMBS_UTILS_PYTHON_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_gotcha.py"
              ${_dc_wrap_hdrs}
              --libclang "${DATACRUMBS_LIBCLANG}"
              --include "${DATACRUMBS_DOCA_INCLUDE}"
              --include "${DATACRUMBS_FLEXIO_INCLUDE}"
              --include "${DATACRUMBS_PKA_INCLUDE}"
              --inventory "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/api-inventory.tsv"
              # Engine, DPA and FlexIO ops arrive inside a task or a struct rather than as a typed
              # parameter, so decoding only parameter-carried enums names a fraction of them.
              --decode-all-enums
              # A DevX call names its command in the buffer, not in a parameter. Without this table
              # the wrappers record the buffer as a pointer and no command is ever named.
              --decode-constants "MLX5_CMD_OP=${_dc_devx_h}"
              # Written by the same pass that skips them, so the trampoline list cannot drift from
              # the symbols the wrap list dropped for being variadic.
              --tramp-out "${_dc_tramp_out}"
              # One list per library beside the combined one, so a translation unit that wraps DOCA
              # includes doca/api.h and never carries the ibverbs surface.
              --split-dir "${_dc_wrap_split_dir}"
              --output "${_dc_wrap_out}"
      DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_gotcha.py"
              "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/api-inventory.tsv"
              ${_dc_wrap_hdrs}
      COMMENT "Generating GOTCHA wrap list from the headers this build compiles against"
      VERBATIM)
    # Symbols the inventory classifies but no header declares: the private version nodes and the
    # ibv_cmd kernel-command layer. A wrapper needs a prototype to forward arguments and a
    # trampoline does not, so these are reachable as entry records even though the wrap list cannot
    # carry them.
    add_custom_command(
      OUTPUT "${_dc_undecl_out}"
      COMMAND "${DATACRUMBS_UTILS_PYTHON_EXECUTABLE}"
              "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_tramp.py"
              --inventory "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/api-inventory.tsv"
              --wrap-list "${_dc_wrap_out}"
              --also-covered "${_dc_tramp_out}"
              --output "${_dc_undecl_out}"
      DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/gen_tramp.py"
              "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/api-inventory.tsv"
              "${_dc_wrap_out}" "${_dc_tramp_out}"
      COMMENT "Generating trampoline list for symbols no header declares"
      VERBATIM)

    add_library(datacrumbs_api_trace SHARED
        "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/wrap/library.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/datacrumbs/utils/client/wrap/api_tramp.cpp"
        "${_dc_wrap_out}" "${_dc_tramp_out}" "${_dc_undecl_out}")
    # No DOCA link dependency: the wrappers name DOCA types but reach the real functions through
    # pointers GOTCHA fills in, so only the headers are needed.
    target_include_directories(datacrumbs_api_trace
        PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated" "${DATACRUMBS_DOCA_INCLUDE}"
                "${DATACRUMBS_FLEXIO_INCLUDE}" "${DATACRUMBS_PKA_INCLUDE}")
    target_link_libraries(datacrumbs_api_trace ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} OpenSSL::Crypto
                          ZLIB::ZLIB gotcha yaml-cpp ${CMAKE_DL_LIBS})
    install(TARGETS datacrumbs_api_trace
            LIBRARY DESTINATION "${DATACRUMBS_UTILS_INSTALL_LIB_DIR}")
  else()
    message(STATUS "libclang or its python bindings absent "
                   "(${DATACRUMBS_LIBCLANG}, ${DATACRUMBS_PYLIB}); skipping datacrumbs_api_trace")
  endif()
endif()

set(DATACRUMBS_UTILS_PROBE_CONFIGURATOR_BIN "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/datacrumbs_probe_configurator_exec")
set(DATACRUMBS_UTILS_PROBE_CONFIGURATOR_INSTALL_BIN
    "${DATACRUMBS_UTILS_INSTALL_BIN_DIR}/datacrumbs_probe_configurator_exec"
)
set(DATACRUMBS_PROBE_CONFIGURATOR_INSTALL_BIN "${DATACRUMBS_UTILS_PROBE_CONFIGURATOR_INSTALL_BIN}")

set(_DATACRUMBS_ORIG_INSTALL_BINARYDIR "${DATACRUMBS_INSTALL_BINARYDIR}")
set(DATACRUMBS_INSTALL_BINARYDIR "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_logging.in"
  "${DATACRUMBS_UTILS_BUILD_LOGGING_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_args.in"
  "${DATACRUMBS_UTILS_BUILD_ARGS_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_track.in"
  "${DATACRUMBS_UTILS_BUILD_TRACK_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_untrack.in"
  "${DATACRUMBS_UTILS_BUILD_UNTRACK_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_wrap.in"
  "${DATACRUMBS_UTILS_BUILD_WRAP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_salloc.in"
  "${DATACRUMBS_UTILS_BUILD_SALLOC_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_sbatch.in"
  "${DATACRUMBS_UTILS_BUILD_SBATCH_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_utility.in"
  "${DATACRUMBS_UTILS_BUILD_UTILITY_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_setup.in"
  "${DATACRUMBS_UTILS_BUILD_SETUP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_run.in"
  "${DATACRUMBS_UTILS_BUILD_RUN_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_stop.in"
  "${DATACRUMBS_UTILS_BUILD_STOP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_service_wrapper.in"
  "${DATACRUMBS_UTILS_BUILD_SERVICE_WRAPPER_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_deploy_services.in"
  "${DATACRUMBS_UTILS_BUILD_DEPLOY_SERVICES_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_deploy_scheduler_hooks.in"
  "${DATACRUMBS_UTILS_BUILD_DEPLOY_HOOKS_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_install_flux_plugin.in"
  "${DATACRUMBS_UTILS_BUILD_INSTALL_FLUX_PLUGIN_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_cluster_setup.in"
  "${DATACRUMBS_UTILS_BUILD_CLUSTER_SETUP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_configure_template.in"
  "${DATACRUMBS_UTILS_BUILD_CONFIGURE_TEMPLATE_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_sqlite_extract.in"
  "${DATACRUMBS_UTILS_BUILD_SQLITE_EXTRACT_SCRIPT}"
  @ONLY
)
file(MAKE_DIRECTORY "${DATACRUMBS_UTILS_BUILD_PYTHON_DIR}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/python/configure_templates.py"
  "${DATACRUMBS_UTILS_BUILD_PYTHON_DIR}/configure_templates.py"
  COPYONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/python/datacrumbs_sqlite_extract.py"
  "${DATACRUMBS_UTILS_BUILD_PYTHON_DIR}/datacrumbs_sqlite_extract.py"
  COPYONLY
)
set(DATACRUMBS_INSTALL_BINARYDIR "${_DATACRUMBS_ORIG_INSTALL_BINARYDIR}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_logging.in"
  "${DATACRUMBS_UTILS_INSTALL_LOGGING_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_args.in"
  "${DATACRUMBS_UTILS_INSTALL_ARGS_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/probe_configurator.in"
  "${DATACRUMBS_UTILS_INSTALL_PROBE_WRAPPER}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_track.in"
  "${DATACRUMBS_UTILS_INSTALL_TRACK_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_untrack.in"
  "${DATACRUMBS_UTILS_INSTALL_UNTRACK_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_wrap.in"
  "${DATACRUMBS_UTILS_INSTALL_WRAP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_salloc.in"
  "${DATACRUMBS_UTILS_INSTALL_SALLOC_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_sbatch.in"
  "${DATACRUMBS_UTILS_INSTALL_SBATCH_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_utility.in"
  "${DATACRUMBS_UTILS_INSTALL_UTILITY_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_setup.in"
  "${DATACRUMBS_UTILS_INSTALL_SETUP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_run.in"
  "${DATACRUMBS_UTILS_INSTALL_RUN_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_stop.in"
  "${DATACRUMBS_UTILS_INSTALL_STOP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_service_wrapper.in"
  "${DATACRUMBS_UTILS_INSTALL_SERVICE_WRAPPER_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_deploy_services.in"
  "${DATACRUMBS_UTILS_INSTALL_DEPLOY_SERVICES_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_deploy_scheduler_hooks.in"
  "${DATACRUMBS_UTILS_INSTALL_DEPLOY_HOOKS_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_install_flux_plugin.in"
  "${DATACRUMBS_UTILS_INSTALL_INSTALL_FLUX_PLUGIN_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_configure_template.in"
  "${DATACRUMBS_UTILS_INSTALL_CONFIGURE_TEMPLATE_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_sqlite_extract.in"
  "${DATACRUMBS_UTILS_INSTALL_SQLITE_EXTRACT_SCRIPT}"
  @ONLY
)
file(MAKE_DIRECTORY "${DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/python/configure_templates.py"
  "${DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR}/configure_templates.py"
  COPYONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/python/datacrumbs_sqlite_extract.py"
  "${DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR}/datacrumbs_sqlite_extract.py"
  COPYONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/scripts/datacrumbs/datacrumbs_cluster_setup.in"
  "${DATACRUMBS_UTILS_INSTALL_CLUSTER_SETUP_SCRIPT}"
  @ONLY
)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/dd_preload_test.sh.in"
  "${DATACRUMBS_UTILS_DD_PRELOAD_TEST_SCRIPT}"
  @ONLY
)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_ARGS_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_LOGGING_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_TRACK_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_UNTRACK_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_WRAP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_SALLOC_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_SBATCH_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_UTILITY_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_SETUP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_RUN_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_STOP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_SERVICE_WRAPPER_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_DEPLOY_SERVICES_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_DEPLOY_HOOKS_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_INSTALL_FLUX_PLUGIN_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_CLUSTER_SETUP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_SQLITE_EXTRACT_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_BUILD_CONFIGURE_TEMPLATE_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_ARGS_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_LOGGING_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_PROBE_WRAPPER}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_TRACK_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_UNTRACK_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_WRAP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_SALLOC_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_SBATCH_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_UTILITY_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_SETUP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_RUN_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_STOP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_SERVICE_WRAPPER_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_DEPLOY_SERVICES_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_DEPLOY_HOOKS_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_INSTALL_FLUX_PLUGIN_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_CLUSTER_SETUP_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_SQLITE_EXTRACT_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_INSTALL_CONFIGURE_TEMPLATE_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
file(CHMOD "${DATACRUMBS_UTILS_DD_PRELOAD_TEST_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_ARGS_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_args")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_LOGGING_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_logging")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_PROBE_WRAPPER}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_probe_configurator")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_TRACK_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_track")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_UNTRACK_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_untrack")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_WRAP_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_wrap")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_SALLOC_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_salloc")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_SBATCH_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_sbatch")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_UTILITY_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_utility")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_SETUP_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_setup")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_RUN_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_run")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_STOP_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_stop")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_SERVICE_WRAPPER_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_service_wrapper")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_DEPLOY_SERVICES_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_deploy_services")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_DEPLOY_HOOKS_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_deploy_scheduler_hooks")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_INSTALL_FLUX_PLUGIN_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_install_flux_plugin")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_CLUSTER_SETUP_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_cluster_setup")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_SQLITE_EXTRACT_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_sqlite_extract")
install(PROGRAMS "${DATACRUMBS_UTILS_INSTALL_CONFIGURE_TEMPLATE_SCRIPT}" DESTINATION "${DATACRUMBS_INSTALL_BINARYDIR}"
        RENAME "datacrumbs_configure_template")
install(FILES
        "${DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR}/configure_templates.py"
        "${DATACRUMBS_UTILS_STAGED_INSTALL_PYTHON_DIR}/datacrumbs_sqlite_extract.py"
        DESTINATION "${DATACRUMBS_INSTALL_LIBEXEC}/python")

if(BUILD_TESTING)
  add_test(
    NAME datacrumbs_utils_dd_preload
    COMMAND "${DATACRUMBS_UTILS_DD_PRELOAD_TEST_SCRIPT}"
  )
  set_tests_properties(datacrumbs_utils_dd_preload PROPERTIES SKIP_RETURN_CODE 77)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/CMakeLists.txt")
  add_subdirectory(tools)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  add_subdirectory(tests)
endif()
