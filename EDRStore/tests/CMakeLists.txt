add_executable(AATETest
    aate_test.cc
    ../src/client/two_phase_enc.cc
    ../src/chunker/rabin_poly.cc)

target_include_directories(AATETest PRIVATE ../include)
target_link_libraries(AATETest crypto xdeltaLib)

add_test(NAME aate_core COMMAND AATETest)

add_executable(PositionSketchTest
    position_sketch_test.cc
    ../src/chunker/finesse_util.cc
    ../src/chunker/rabin_poly.cc
    ../src/util/configure.cc)

target_include_directories(PositionSketchTest PRIVATE ../include)
target_link_libraries(PositionSketchTest crypto)

add_test(NAME position_sketch COMMAND PositionSketchTest)
set_tests_properties(position_sketch PROPERTIES
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
