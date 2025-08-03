cmake_minimum_required(VERSION 3.10)

add_executable(poc_keccak1600_init poc_keccak1600_init.cpp)
target_link_libraries(poc_keccak1600_init cosigner)

# Add test that verifies the vulnerability fix
add_test(NAME poc_keccak1600_init COMMAND poc_keccak1600_init)
set_tests_properties(poc_keccak1600_init PROPERTIES 
    LABELS "vulnerability;poc;fixed"
)