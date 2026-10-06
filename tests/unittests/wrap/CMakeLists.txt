# The dlopen guard against GOTCHA alone: no device, no daemon. Exits 77 when no candidate library
# is left to load for the first time.
add_executable(datacrumbs_dlopen_guard_test
    dlopen_guard_test.cpp
    "${CMAKE_SOURCE_DIR}/src/datacrumbs/utils/client/wrap/dlopen_guard.cpp")
target_include_directories(datacrumbs_dlopen_guard_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(datacrumbs_dlopen_guard_test ${DATACRUMBS_PUBLIC_COMMON_LIBRARY} gotcha
                      ${CMAKE_DL_LIBS})
add_test(NAME datacrumbs_dlopen_guard COMMAND datacrumbs_dlopen_guard_test)
set_tests_properties(datacrumbs_dlopen_guard PROPERTIES SKIP_RETURN_CODE 77)
