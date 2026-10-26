# Pure-logic test for the completion queue's miss tests: no ibverbs, no hardware, no device.
add_executable(datacrumbs_cq_lap_test cq_lap_test.cpp)
target_include_directories(datacrumbs_cq_lap_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME datacrumbs_cq_lap COMMAND datacrumbs_cq_lap_test)

# The sweep's fault guard, on memory the test maps and unmaps itself.
add_executable(datacrumbs_walk_guard_test walk_guard_test.cpp)
target_include_directories(datacrumbs_walk_guard_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME datacrumbs_walk_guard COMMAND datacrumbs_walk_guard_test)
