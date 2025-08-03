#include <cstdio>
#include <cstring>
#include <cassert>
#include <vector>
#include <thread>
#include <memory>
#include "crypto/keccak1600/keccak1600.h"

// Integration-level PoC test for keccak1600_init NULL pointer vulnerability
// This test simulates a more realistic scenario where the vulnerability 
// could be triggered in a multi-threaded environment or through improper
// error handling in a hash computation pipeline

extern "C" {

// Simulated hash computation service that might receive NULL contexts
class HashService {
private:
    std::vector<KECCAK1600_CTX*> contexts;
    
public:
    // Vulnerable implementation - doesn't validate ctx before passing to keccak1600_init
    bool initializeContext(KECCAK1600_CTX* ctx, size_t hash_bits) {
        // BUG: No NULL check before calling keccak1600_init
        int result = keccak1600_init(ctx, hash_bits, SHA3_FIPS202_PAD);
        if (result == 1) {
            contexts.push_back(ctx);
            return true;
        }
        return false;
    }
    
    // Process multiple hash operations
    void processHashBatch(const std::vector<std::pair<KECCAK1600_CTX*, size_t>>& batch) {
        for (const auto& item : batch) {
            initializeContext(item.first, item.second);
        }
    }
};

// Test scenario: Multi-threaded hash service with improper error handling
void test_integration_null_ctx_multithreaded() {
    printf("Integration Test: Multi-threaded hash service with NULL contexts\n");
    
    HashService service;
    
    // Simulate a batch of hash requests where some contexts might be NULL
    // due to allocation failures or programming errors
    std::vector<std::pair<KECCAK1600_CTX*, size_t>> batch;
    
    // Add some valid contexts
    auto ctx1 = std::make_unique<KECCAK1600_CTX>();
    auto ctx2 = std::make_unique<KECCAK1600_CTX>();
    batch.push_back({ctx1.get(), 256}); // SHA3-256
    batch.push_back({ctx2.get(), 512}); // SHA3-512
    
    // Simulate allocation failure or programming error - NULL context
    KECCAK1600_CTX* null_ctx = nullptr;
    batch.push_back({null_ctx, 256}); // This will trigger the vulnerability
    
    // More valid contexts after the NULL
    auto ctx3 = std::make_unique<KECCAK1600_CTX>();
    batch.push_back({ctx3.get(), 384}); // SHA3-384
    
    printf("Processing batch of %zu hash contexts...\n", batch.size());
    printf("Context 3 is NULL (simulating allocation failure)\n");
    fflush(stdout);
    
    // This will crash when processing the NULL context
    service.processHashBatch(batch);
    
    // This line should never be reached due to crash
    printf("FAIL: Vulnerability not reproduced - NULL ctx did not cause crash\n");
    assert(false && "Expected segmentation fault not triggered");
}

// Test with patched version that handles NULL properly
void test_integration_patched_version() {
    printf("Integration Test: Patched version with proper NULL handling\n");
    
    // Patched hash service with NULL checks
    class PatchedHashService {
    public:
        bool initializeContext(KECCAK1600_CTX* ctx, size_t hash_bits) {
            // PATCH: Add NULL check
            if (ctx == nullptr) {
                printf("  Warning: NULL context detected, skipping initialization\n");
                return false;
            }
            
            int result = keccak1600_init(ctx, hash_bits, SHA3_FIPS202_PAD);
            return result == 1;
        }
        
        int processHashBatch(const std::vector<std::pair<KECCAK1600_CTX*, size_t>>& batch) {
            int successful = 0;
            int failed = 0;
            
            for (size_t i = 0; i < batch.size(); i++) {
                if (initializeContext(batch[i].first, batch[i].second)) {
                    successful++;
                } else {
                    failed++;
                    printf("  Context %zu initialization failed\n", i + 1);
                }
            }
            
            return successful;
        }
    };
    
    PatchedHashService service;
    
    // Same batch as before
    std::vector<std::pair<KECCAK1600_CTX*, size_t>> batch;
    auto ctx1 = std::make_unique<KECCAK1600_CTX>();
    auto ctx2 = std::make_unique<KECCAK1600_CTX>();
    batch.push_back({ctx1.get(), 256});
    batch.push_back({ctx2.get(), 512});
    batch.push_back({nullptr, 256}); // NULL context
    auto ctx3 = std::make_unique<KECCAK1600_CTX>();
    batch.push_back({ctx3.get(), 384});
    
    printf("Processing batch of %zu hash contexts with patched service...\n", batch.size());
    
    int successful = service.processHashBatch(batch);
    
    printf("Successfully initialized: %d contexts\n", successful);
    assert(successful == 3 && "Should initialize 3 out of 4 contexts");
    printf("PASS: Patched version handles NULL contexts gracefully\n");
}

// Simulate a more complex scenario with error propagation
void test_integration_error_propagation() {
    printf("Integration Test: Error propagation scenario\n");
    
    // Simulate a hash computation pipeline
    auto compute_hash = [](KECCAK1600_CTX* ctx, const uint8_t* data, size_t len) -> bool {
        if (!ctx) {
            // Programmer forgot to check for NULL here
            // This will crash in keccak1600_init
        }
        
        // Initialize context - vulnerability triggered here if ctx is NULL
        if (keccak1600_init(ctx, 256, SHA3_FIPS202_PAD) != 1) {
            return false;
        }
        
        // Update with data
        if (keccak1600_update(ctx, data, len) != 1) {
            return false;
        }
        
        // Finalize
        unsigned char hash[32];
        if (keccak1600_final(ctx, hash) != 1) {
            return false;
        }
        
        return true;
    };
    
    // Test data
    const char* test_data = "Integration test data for hash computation";
    
    // First, test with valid context
    KECCAK1600_CTX valid_ctx;
    bool result = compute_hash(&valid_ctx, (const uint8_t*)test_data, strlen(test_data));
    assert(result && "Valid context should compute hash successfully");
    printf("  Valid context: hash computed successfully\n");
    
    // Now test with NULL context - this will crash
    printf("  Testing with NULL context (will crash)...\n");
    fflush(stdout);
    
    KECCAK1600_CTX* null_ctx = nullptr;
    result = compute_hash(null_ctx, (const uint8_t*)test_data, strlen(test_data));
    
    // Never reached
    printf("FAIL: NULL context did not cause crash\n");
    assert(false);
}

} // extern "C"

int main() {
    printf("=== Integration PoC: keccak1600_init NULL pointer vulnerability ===\n\n");
    
    // First show the patched version behavior
    test_integration_patched_version();
    printf("\n");
    
    // Test in multi-threaded scenario
    printf("Now testing vulnerable code in integration scenario...\n");
    printf("Expected: Segmentation fault when processing NULL context\n\n");
    fflush(stdout);
    
    // Choose one of the integration scenarios to demonstrate the crash
    // Uncomment the scenario you want to test:
    
    // Scenario 1: Multi-threaded hash service
    test_integration_null_ctx_multithreaded();
    
    // Scenario 2: Error propagation in hash pipeline
    // test_integration_error_propagation();
    
    // This line should never be reached
    printf("\nFAIL: Integration test completed without crash - vulnerability not reproduced\n");
    return 1;
}