# Pure-logic test for the completion queue's miss tests: no ibverbs, no hardware, no device.
add_executable(datacrumbs_cq_lap_test cq_lap_test.cpp)
target_include_directories(datacrumbs_cq_lap_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME datacrumbs_cq_lap COMMAND datacrumbs_cq_lap_test)
