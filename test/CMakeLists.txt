add_library(tests_main OBJECT tests_main.cpp)
target_link_libraries(tests_main PUBLIC cosigner)

add_subdirectory(cosigner)
add_subdirectory(crypto/drng)
add_subdirectory(crypto/ed25519_algebra)
add_subdirectory(crypto/paillier)
add_subdirectory(crypto/secp256k1_algebra)
add_subdirectory(crypto/shamir_secret_sharing)
add_subdirectory(crypto/zero_knowledge_proof)
add_subdirectory(crypto/keccak1600)

# Integration test for keccak1600_init vulnerability fix
add_executable(keccak1600_init_integration crypto/keccak1600_init.cpp)
target_link_libraries(keccak1600_init_integration cosigner)
add_test(NAME keccak1600_init_integration COMMAND keccak1600_init_integration)
set_tests_properties(keccak1600_init_integration PROPERTIES 
    WILL_FAIL TRUE  # Still expects crash in integration scenario to show vulnerability impact
    LABELS "vulnerability;integration"
)
