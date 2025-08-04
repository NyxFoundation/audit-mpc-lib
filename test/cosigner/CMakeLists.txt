list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(UUID REQUIRED)
find_package(Threads REQUIRED)

add_executable(cosigner_test
    ecdsa_offline_test.cpp
    ecdsa_online_test.cpp
    eddsa_offline_test.cpp
    eddsa_online_test.cpp
    setup_test.cpp
)

# Link the necessary libraries to the cosigner_test target
if(APPLE)
    target_link_libraries(cosigner_test PRIVATE tests_main cosigner Threads::Threads) # No UUID library on macOS
else()
    target_link_libraries(cosigner_test PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()

add_test(NAME cosigner_test COMMAND cosigner_test)

# PoC test for derivation_key_delta vulnerability
add_executable(poc_derivation_key_delta
    poc_derivation_key_delta.cpp
)

if(APPLE)
    target_link_libraries(poc_derivation_key_delta PRIVATE tests_main cosigner Threads::Threads)
else()
    target_link_libraries(poc_derivation_key_delta PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()

add_test(NAME poc_derivation_key_delta COMMAND poc_derivation_key_delta)

# Integration test for derivation_key_delta DoS vulnerability
add_executable(poc_derivation_key_delta_integration
    poc_derivation_key_delta_integration.cpp
)

if(APPLE)
    target_link_libraries(poc_derivation_key_delta_integration PRIVATE tests_main cosigner Threads::Threads)
else()
    target_link_libraries(poc_derivation_key_delta_integration PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()

add_test(NAME poc_derivation_key_delta_integration COMMAND poc_derivation_key_delta_integration)
