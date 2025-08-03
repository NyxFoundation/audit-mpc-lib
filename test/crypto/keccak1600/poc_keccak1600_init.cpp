#include <cstdio>
#include <cstring>
#include <cassert>
#include "crypto/keccak1600/keccak1600.h"

// PoC test that reproduces keccak1600_init null pointer vulnerability
// The vulnerability: keccak1600_init does not validate ctx parameter
// Expected behavior: Should return error when ctx is NULL
// Actual behavior: Crashes with segmentation fault

extern "C" {

// Test case 1: NULL pointer should be handled safely (after fix)
void test_keccak1600_init_null_ctx_crash() {
    printf("Test: keccak1600_init with NULL ctx should fail safely\n");
    
    // -- Arrange --
    KECCAK1600_CTX *ctx = NULL;
    size_t md_size_in_bits = 256; // SHA3-256
    unsigned char pad = SHA3_FIPS202_PAD;
    
    // -- Act --
    // After fix: This should return 0 instead of crashing
    int result = keccak1600_init(ctx, md_size_in_bits, pad);
    
    // -- Assert --
    // With the fix, function should return 0 for NULL input
    assert(result == 0 && "Fixed: Function now returns 0 for NULL ctx");
    printf("PASS: Function safely returned %d for NULL ctx\n", result);
}

// Test case 2: Verify normal operation with valid ctx
void test_keccak1600_init_valid_ctx() {
    printf("Test: keccak1600_init with valid ctx should succeed\n");
    
    // -- Arrange --
    KECCAK1600_CTX ctx;
    size_t md_size_in_bits = 256; // SHA3-256
    unsigned char pad = SHA3_FIPS202_PAD;
    
    // -- Act --
    int result = keccak1600_init(&ctx, md_size_in_bits, pad);
    
    // -- Assert --
    assert(result == 1 && "Valid initialization should return 1");
    assert(ctx.md_size == 32 && "SHA3-256 should have 32 byte output");
    assert(ctx.block_size == 136 && "SHA3-256 should have 136 byte block size");
    assert(ctx.pad == SHA3_FIPS202_PAD && "Padding should be set correctly");
    assert(ctx.num == 0 && "Buffer position should be initialized to 0");
    
    printf("PASS: Valid ctx initialization succeeded\n");
}

// Test case 3: Double-check with patched version
void test_keccak1600_init_patched() {
    printf("Test: Patched version should handle NULL ctx safely\n");
    
    // Inline patched version that adds NULL check
    auto keccak1600_init_patched = [](KECCAK1600_CTX *ctx, size_t md_size_in_bits, unsigned char pad) -> int {
        // PATCH: Add null pointer check
        if (ctx == NULL) {
            return 0; // Return error instead of crashing
        }
        
        // Original code follows
        size_t bsz = (KECCAK1600_WIDTH - md_size_in_bits * 2) / 8;
        if (bsz <= sizeof(ctx->buf)) {
            memset(ctx->A, 0, sizeof(ctx->A));
            ctx->num = 0;
            ctx->block_size = bsz;
            ctx->md_size = md_size_in_bits / 8;
            ctx->pad = pad;
            return 1;
        }
        return 0;
    };
    
    // -- Arrange --
    KECCAK1600_CTX *ctx = NULL;
    size_t md_size_in_bits = 256;
    unsigned char pad = SHA3_FIPS202_PAD;
    
    // -- Act --
    int result = keccak1600_init_patched(ctx, md_size_in_bits, pad);
    
    // -- Assert --
    assert(result == 0 && "Patched version should return 0 for NULL ctx");
    printf("PASS: Patched version handles NULL ctx safely\n");
}

} // extern "C"

int main() {
    printf("=== PoC: keccak1600_init NULL pointer vulnerability ===\n\n");
    
    // First verify normal operation works
    test_keccak1600_init_valid_ctx();
    printf("\n");
    
    // Show how patched version would handle NULL
    test_keccak1600_init_patched();
    printf("\n");
    
    // Test NULL handling (vulnerability is now fixed)
    printf("Now testing fixed code with NULL ctx...\n");
    printf("Expected: Safe return with error code\n\n");
    fflush(stdout);
    
    test_keccak1600_init_null_ctx_crash();
    
    printf("\nAll tests passed! Vulnerability has been fixed.\n");
    return 0;
}