add_executable(AATETest
    aate_test.cc
    ../src/client/two_phase_enc.cc
    ../src/chunker/rabin_poly.cc)

target_include_directories(AATETest PRIVATE ../include)
target_link_libraries(AATETest crypto)

add_test(NAME aate_core COMMAND AATETest)
