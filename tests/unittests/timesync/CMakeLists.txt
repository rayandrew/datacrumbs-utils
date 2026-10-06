# Pure-logic test for the raw HCA cycle -> ns conversion: no ibverbs, no hardware, no daemon.
add_executable(datacrumbs_timesync_raw_convert_test timesync_raw_convert_test.cpp)
target_link_libraries(datacrumbs_timesync_raw_convert_test ${DATACRUMBS_PUBLIC_COMMON_LIBRARY})
add_test(NAME datacrumbs_timesync_raw_convert COMMAND datacrumbs_timesync_raw_convert_test)
