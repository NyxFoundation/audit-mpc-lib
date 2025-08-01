#include "paillier_internal.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>

// WARNING: this function doesn't run in constant time!
// @audit-ok: Timing leak acceptable for public coprimality checking
// ↳ is_coprime_fast used with public randomness r in encryption context
// ↳ While non-constant time, leaking coprimality of public r with public n is low risk
// ↳ More critical timing leaks exist elsewhere (L625, L1246)
int is_coprime_fast(const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
{
    BIGNUM *a, *b;
    int ret = -1;

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);

    if (!a || !BN_copy(a, in_a))
    {
        goto cleanup;
    }

    if (!b || !BN_copy(b, in_b))
    {
        goto cleanup;
    }

    if (BN_cmp(a, b) < 0)
    {
        BIGNUM *t = b;
        b = a;
        a = t;
    }

    while (!BN_is_zero(b))
    {
        BIGNUM *t;
        if (!BN_mod(a, a, b, ctx))
        {
            goto cleanup;
        }
        t = b;
        b = a;
        a = t;
    }
    ret = BN_is_one(a);

cleanup:
    BN_CTX_end(ctx);
    return ret;
}

static uint64_t L(BIGNUM *res, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx)
{
    uint64_t ret = -1;

    BIGNUM *x_copy = BN_dup(x);

    if (!BN_sub_word(x_copy, 1))
    {
        goto cleanup;
    }

    if (!BN_div(res, NULL, x_copy, n, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;
cleanup:
    if (ret)
    {
        ret = ERR_get_error() * -1;
    }

    BN_clear_free(x_copy);
    return ret;
}

// @audit CRITICAL: Key generation function - most sensitive operation in Paillier cryptosystem
// @audit-issue: MIN_KEY_LEN_IN_BITS = 256 is too small for production (should be >= 2048)
// ↳ BN_generate_prime_ex quality depends on OpenSSL RNG - ensure RAND_status() == 1
// @audit-ok: Enforces p≡3 mod 8, q≡7 mod 8 and verifies gcd(λ(n), n) = 1
long paillier_generate_key_pair(uint32_t key_len, paillier_public_key_t **pub, paillier_private_key_t **priv)
{
    long ret = -1;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *tmp = NULL, *n = NULL, *n2 = NULL;
    BIGNUM *lamda = NULL,  *mu = NULL;
    BIGNUM *three = NULL, *seven = NULL, *eight = NULL;
    BN_CTX *ctx = NULL;
    paillier_public_key_t *local_pub = NULL;
    paillier_private_key_t *local_priv = NULL;

    // @audit-ok: Parameter validation prevents null pointer dereference
    if (!pub || !priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    // @audit CRITICAL: Weak key length validation allows insecure keys
    // ↳ MIN_KEY_LEN_IN_BITS = 256 bits factorizable in seconds by GNFS
    // ↳ Production systems require ≥ 2048 bits for 112-bit security level
    // ↳ After review: Confirmed critical - 256-bit keys trivially broken
    // ↳ Proof trace: paillier_generate_key_pair (L87→104) → paillier_internal.h:13
    if (key_len < MIN_KEY_LEN_IN_BITS)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    *pub = NULL;
    *priv = NULL;

    // @audit-ok: Using secure memory allocation for sensitive context
    ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        //not jumping to cleanup to avoid initializating all local variables
        return PAILLIER_ERROR_OUT_OF_MEMORY; 
    }

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    three = BN_CTX_get(ctx);
    seven = BN_CTX_get(ctx);
    eight = BN_CTX_get(ctx);

    p = BN_new();
    q = BN_new();
    n = BN_new();
    n2 = BN_new();
    lamda = BN_new();
    mu = BN_new();
    
    if (!p || !q || !tmp || !n || !n2 || !lamda || !mu || !three || !seven || !eight)
    {
        goto cleanup;
    }

    // @audit-ok: Constant-time flags set to prevent timing attacks on private key material
    BN_set_flags(n, BN_FLG_CONSTTIME);
    BN_set_flags(n2, BN_FLG_CONSTTIME);
    BN_set_flags(p, BN_FLG_CONSTTIME);
    BN_set_flags(q, BN_FLG_CONSTTIME);
    BN_set_flags(lamda, BN_FLG_CONSTTIME);
    BN_set_flags(mu, BN_FLG_CONSTTIME);

    if (!BN_set_word(three, 3))
    {
        goto cleanup;
    }

    if (!BN_set_word(seven, 7))
    {
        goto cleanup;
    }
    
    if (!BN_set_word(eight, 8))
    {
        goto cleanup;
    }

    // Choose two large prime p,q numbers having gcd(pq, (p-1)(q-1)) == 1
    // @audit-ok: Prime generation loop ensures p != q and proper structure
    do
    {   // note - originally we had used p and q to be 4*k + 3. The new form keeps this requirement because
        // both p and q still satisfies 4 * k + 3

        // p needs to be in the form of p = 8 * k + 3 ( p = 3 mod 8) to allow efficient calculation off fourth roots 
        // (needed in paillier blum zkp)
        // @audit HIGH: BN_generate_prime_ex depends on OpenSSL RNG entropy
        if (!BN_generate_prime_ex(p, key_len / 2, 0, eight, three, NULL))
    {
            goto cleanup;
        }

        // and set must be q = 7 mod 8 (8 * k + 7)
        // @audit-ok: Loop ensures p != q via BN_cmp check below
        if (!BN_generate_prime_ex(q, key_len / 2, 0, eight, seven, NULL))
        {
            goto cleanup;
        }

        if (BN_num_bits(p) != BN_num_bits(q))
        {
            continue;
        }

        // Compute n = pq
        if (!BN_mul(n, p, q, ctx))
        {
            goto cleanup;
        }

        if (!BN_sub(lamda, n, p))
        {
            goto cleanup;
        }

        if (!BN_sub(lamda, lamda, q))
        {
            goto cleanup;
        }

        if (!BN_add_word(lamda, 1))
        {
            goto cleanup;
    }
    // @audit-ok: Loop ensures p != q and validates gcd(λ(n), n) = 1 requirement
    } while (BN_cmp(p, q) == 0 || 
             !BN_gcd(tmp, lamda, n, ctx) || 
             !BN_is_one(tmp));

    if (!BN_sqr(n2, n, ctx))
    {
            goto cleanup;
    }

    // if num_bits(q) == num_bits(p), we can optimize g lambda and mu selection see https://en.wikipedia.org/wiki/Paillier_cryptosystem
    if (!BN_mod_inverse(mu, lamda, n, ctx))
    {
        goto cleanup;
    }

    local_priv = (paillier_private_key_t*)malloc(sizeof(paillier_private_key_t));
    if (!local_priv)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    local_priv->pub.n = n;
    local_priv->pub.n2 = n2;
    local_priv->p = p;
    local_priv->q = q;
    local_priv->lamda = lamda;
    local_priv->mu = mu;
    
    local_pub = (paillier_public_key_t*)malloc(sizeof(paillier_public_key_t));
    if (!local_pub)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    local_pub->n = BN_dup(n);
    local_pub->n2 = BN_dup(n2);

    if (!local_pub->n || !local_pub->n2)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    *priv = local_priv;
    *pub = local_pub;

    ret = PAILLIER_SUCCESS;
cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (ret)
    {
        // handle errors
        if (local_priv)
        {
            free(local_priv);
        }
        paillier_free_public_key(local_pub); // as the public key uses duplication of n and n2 it's not sefficent just to free it
        BN_free(p);
        BN_free(q);
        BN_free(n);
        BN_free(n2);
        BN_free(lamda);
        BN_free(mu);
    }

    return ret;
}

long paillier_public_key_n(const paillier_public_key_t *pub, uint8_t *n, uint32_t n_len, uint32_t *n_real_len)
{
    uint32_t len = 0;
    if (!pub)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!n && n_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    len = BN_num_bytes(pub->n);

    if (n_real_len)
    {
        *n_real_len = len;
    }

    if (n_len < len)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    return BN_bn2bin(pub->n, n) > 0 ? PAILLIER_SUCCESS : ERR_get_error() * -1;
}

uint32_t paillier_public_key_size(const paillier_public_key_t *pub)
{
    if (pub)
    {
        return BN_num_bytes(pub->n) * 8;
    }

    return 0;
}

uint8_t *paillier_public_key_serialize(const paillier_public_key_t *pub, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t n_len = 0;
    uint8_t *p = buffer;
    
    if (!pub)
    {
        return NULL;
    }

    n_len = (uint32_t)BN_num_bytes(pub->n);
    needed_len = sizeof(uint32_t) + n_len;

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (!buffer || buffer_len < needed_len)
    {
        return NULL;
    }

    memcpy(p, &n_len, sizeof(uint32_t));
    p += sizeof(uint32_t);
    BN_bn2bin(pub->n, p);
    return buffer;
}

// @audit HIGH: Deserialization accepts insecure key sizes (MIN_KEY_LEN_IN_BITS = 256)
// ↳ Line 391 only checks >= 256 bits, should require >= 2048 for production
// ↳ No validation that n is odd or composite
// ↳ Attacker could provide small/invalid n values
paillier_public_key_t *paillier_public_key_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    paillier_public_key_t *pub = NULL;
    uint32_t len = 0;
    BN_CTX *ctx = NULL;

    if (!buffer || buffer_len < (sizeof(uint32_t) + MIN_KEY_LEN_IN_BITS / 8))
    {
        return NULL;
    }

    pub = (paillier_public_key_t*)calloc(1, sizeof(paillier_public_key_t));
    if (!pub)
    {
        return NULL;
    }

    memcpy(&len, buffer, sizeof(uint32_t));
    assert(len == (buffer_len - sizeof(uint32_t)));

    if (len > (buffer_len - sizeof(uint32_t)))
    {
        goto cleanup;
    }

    buffer_len -= sizeof(uint32_t);
    buffer += sizeof(uint32_t);

    pub->n = BN_bin2bn(buffer, len, NULL);
    pub->n2 = BN_new();

    if (!pub->n || !pub->n2)
    {
        goto cleanup;
    }

    if (BN_num_bits(pub->n) < MIN_KEY_LEN_IN_BITS)
    {
        goto cleanup;
    }

    ctx = BN_CTX_new();
    if (!ctx || !BN_sqr(pub->n2, pub->n, ctx))
    {
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return pub;

cleanup:
    BN_CTX_free(ctx);
    paillier_free_public_key(pub);
    return NULL;
}

void paillier_free_public_key(paillier_public_key_t *pub)
{
    if (pub)
    {
        BN_free(pub->n);
        BN_free(pub->n2);
        free(pub);
    }
}

long paillier_private_key_n(const paillier_private_key_t *priv, uint8_t *n, uint32_t n_len, uint32_t *n_real_len)
{
    uint32_t len = 0;
    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    if (!n && n_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    len = BN_num_bytes(priv->pub.n);
    if (n_real_len)
    {
        *n_real_len = len;
    }
    
    if (n_len < len)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    return BN_bn2bin(priv->pub.n, n) > 0 ? PAILLIER_SUCCESS : ERR_get_error() * -1;
}

const paillier_public_key_t* paillier_private_key_get_public(const paillier_private_key_t *priv)
{
    if (priv)
    {
        return &priv->pub;
    }
    return NULL;
}

uint8_t *paillier_private_key_serialize(const paillier_private_key_t *priv, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t p_len = 0;
    uint8_t *p = buffer;
    
    if (!priv)
    {
        return NULL;
    }

    p_len = (uint32_t)BN_num_bytes(priv->p);
    assert(p_len == (uint32_t)BN_num_bytes(priv->q));
    needed_len = sizeof(uint32_t) + 2 * p_len;

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (!buffer || buffer_len < needed_len)
    {
        return NULL;
    }

    memcpy(p, &p_len, sizeof(uint32_t));
    p += sizeof(uint32_t);
    BN_bn2bin(priv->p, p);
    p +=p_len;
    BN_bn2bin(priv->q, p);
    return buffer;
}

paillier_private_key_t *paillier_private_key_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    paillier_private_key_t *priv = NULL;
    uint32_t len = 0;
    BN_CTX *ctx = NULL;

    if (!buffer || buffer_len < (sizeof(uint32_t) + MIN_KEY_LEN_IN_BITS / 8)) // len(p) + len(q) == len(n)
    {
        return NULL;
    }

    priv = (paillier_private_key_t*)calloc(1, sizeof(paillier_private_key_t));

    if (!priv)
    {
        return NULL;
    }

    memcpy(&len, buffer, sizeof(uint32_t));
    
    assert(2 * len == (buffer_len - sizeof(uint32_t)));
    if (2 * len > (buffer_len - sizeof(uint32_t)))
    {
        goto cleanup;
    }

    buffer_len -= sizeof(uint32_t);
    buffer += sizeof(uint32_t);

    priv->p = BN_bin2bn(buffer, len, NULL);
    buffer += len;
    priv->q = BN_bin2bn(buffer, len, NULL);
    priv->pub.n = BN_new();
    priv->pub.n2 = BN_new();
    priv->lamda = BN_new();
    priv->mu = BN_new();
    
    if (!priv->p || !priv->q || !priv->lamda || !priv->mu || !priv->pub.n || !priv->pub.n2)
    {
        goto cleanup;
    }

    BN_set_flags(priv->p, BN_FLG_CONSTTIME);
    BN_set_flags(priv->q, BN_FLG_CONSTTIME);
    BN_set_flags(priv->pub.n, BN_FLG_CONSTTIME);
    BN_set_flags(priv->pub.n2, BN_FLG_CONSTTIME);
    BN_set_flags(priv->lamda, BN_FLG_CONSTTIME);
    BN_set_flags(priv->mu, BN_FLG_CONSTTIME);

    ctx = BN_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    BN_CTX_start(ctx);

    if (!BN_mul(priv->pub.n, priv->p, priv->q, ctx))
    {
        goto cleanup;
    }

    if (!BN_sqr(priv->pub.n2, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    if (!BN_sub(priv->lamda, priv->pub.n, priv->p))
    {
        goto cleanup;
    }

    if (!BN_sub(priv->lamda, priv->lamda, priv->q))
    {
        goto cleanup;
    }

    if (!BN_add_word(priv->lamda, 1))
    {
        goto cleanup;
    }

    if (!BN_mod_inverse(priv->mu, priv->lamda, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    if (BN_num_bits(priv->pub.n) < MIN_KEY_LEN_IN_BITS)
    {
        goto cleanup;
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return priv;

cleanup:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    
    paillier_free_private_key(priv);
    return NULL;
}

// @audit-ok: Secure cleanup using BN_clear_free for sensitive key material
void paillier_free_private_key(paillier_private_key_t *priv)
{
    if (priv)
    {
        BN_free(priv->pub.n);
        BN_free(priv->pub.n2);
        BN_clear_free(priv->p);
        BN_clear_free(priv->q);
        BN_clear_free(priv->lamda);
        BN_clear_free(priv->mu);
        free(priv);
    }
}

// @audit HIGH: Encryption function - must validate randomness and prevent plaintext leakage
// ↳ Uses is_coprime_fast which is not constant-time (timing leak on public r value)
// ↳ Risk: Timing analysis could reveal information about random r
long paillier_encrypt_openssl_internal(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *r, const BIGNUM *plaintext, BN_CTX *ctx)
{
    int ret = -1;

    // Verify that r E Zn*
    // @audit MEDIUM: Non-constant time coprimality check on public randomness
    // ↳ Timing leak on gcd(r, n) computation with public values
    // ↳ Lower risk than secret key timing leaks but still undesirable
    // ↳ Consider constant-time BN_gcd_consttime if available in OpenSSL
    if (is_coprime_fast(r, key->n, ctx) != 1)
    {
        return PAILLIER_ERROR_INVALID_RANDOMNESS;
    }

    BN_CTX_start(ctx);

    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    if (!tmp1 || !tmp2)
    {
        goto cleanup;
    }

    // Compute ciphertext = g^plaintext*r^n mod n^2
    // as will select g=n+1 ciphertext = (1+n*plaintext)*r^n mod n^2, see https://en.wikipedia.org/wiki/Paillier_cryptosystem
    // @audit-ok: Standard Paillier encryption formula with g = n+1 optimization
    if (!BN_mul(tmp1, key->n, plaintext, ctx))
    {
        goto cleanup;
    }
    if (!BN_add_word(tmp1, 1))
    {
        goto cleanup;
    }
    if (!BN_mod_exp(tmp2, r, key->n, key->n2, ctx))
    {
        goto cleanup;
    }
    if (!BN_mod_mul(ciphertext, tmp1, tmp2, key->n2, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    BN_CTX_end(ctx);

    return ret;
}

static inline long encrypt_openssl(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *plaintext, BN_CTX *ctx)
{
    long ret = -1;
    BN_CTX_start(ctx);

    BIGNUM *r = BN_CTX_get(ctx);
    
    if (!r)
    {
        ret = ERR_get_error() * -1;
    }
    else
    {
        // @audit-ok: Random generation loop ensures r is coprime to n
        do
        {
            // @audit HIGH: BN_rand_range depends on OpenSSL RNG entropy
            if (!BN_rand_range(r, key->n))
            {
                ret = ERR_get_error() * -1;
                break;
            }
            
            ret = paillier_encrypt_openssl_internal(key, ciphertext, r, plaintext, ctx);

        } while (ret == PAILLIER_ERROR_INVALID_RANDOMNESS);
    }

    BN_CTX_end(ctx);

    return ret;
}

// @audit-ok: Internal decryption function relies on caller validation
// ↳ Higher-level paillier_decrypt functions validate c < n² (L1071, L1154)
// ↳ This internal function correctly assumes pre-validated inputs
// ↳ Proper separation of concerns between validation and crypto operations
long paillier_decrypt_openssl_internal(const paillier_private_key_t *key, const BIGNUM *ciphertext, BIGNUM *plaintext, BN_CTX *ctx)
{
    int ret = -1;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);

    if (!tmp)
    {
        goto cleanup;
    }

    // verify that ciphertext and n are coprime
    if (is_coprime_fast(ciphertext, key->pub.n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    // Compute the plaintext = L(ciphertext^lamda mod n2)*mu mod n
    if (!BN_mod_exp(tmp, ciphertext, key->lamda, key->pub.n2, ctx))
    {
        goto cleanup;
    }

    ret = L(tmp, tmp, key->pub.n, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
    
    ret = -1; //revet to openssl error

    if (!BN_mod_mul(plaintext, tmp, key->mu, key->pub.n, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 != ret)
    {
        ret = ERR_get_error() * -1;
    }

    BN_CTX_end(ctx);
    return ret;
}

// @audit-ok: Public encryption function validates inputs properly
// ↳ Checks plaintext < n to prevent invalid inputs
// ↳ Uses secure BN_CTX allocation
long paillier_encrypt(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len)
{
    long ret = -1;
    int len = 0;
    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!plaintext || plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = (uint32_t)BN_num_bytes(key->n2);
    }

    if (!ciphertext || ciphertext_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }
    
    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    if (!c || !msg)
    {
        goto cleanup;
    }
    
    if (!BN_bin2bn(plaintext, plaintext_len, msg))
    {
        goto cleanup;
    }

    if (BN_cmp(msg, key->n) >= 0)
    {
        // plaintext not in n
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    ret = encrypt_openssl(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    len = BN_bn2bin(c, ciphertext);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = len;
    }

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_encrypt_to_ciphertext(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, paillier_ciphertext_t **ciphertext)
{
    long ret = -1;
    paillier_ciphertext_t *c = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!plaintext || plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    if (!ciphertext)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    c = (paillier_ciphertext_t*)calloc(1, sizeof(paillier_ciphertext_t));
    if (!c)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    if ((c->ciphertext = BN_new()) == NULL)
    {
        goto cleanup;
    }

    if ((c->r = BN_new()) == NULL)
    {
        goto cleanup;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        goto cleanup;
    }
    
    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    
    if (!msg || !BN_bin2bn(plaintext, plaintext_len, msg))
    {
        goto cleanup;
    }

    if (BN_cmp(msg, key->n) >= 0)
    {
        // plaintext not in n
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    do
    {
        if (!BN_rand_range(c->r, key->n))
        {
            ret = -1; // reset ret so open ssl error will be fetched
            break;
        }

        ret = paillier_encrypt_openssl_internal(key, c->ciphertext, c->r, msg, ctx);
    } while (ret == PAILLIER_ERROR_INVALID_RANDOMNESS);
    
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    *ciphertext = c;
    c = NULL;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    paillier_free_ciphertext(c);
    return ret;
}

long paillier_encrypt_integer(const paillier_public_key_t *key, uint64_t plaintext, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len)
{
    long ret = -1;
    int len = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL, *c = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    if (ciphertext_real_len)
    {
        *ciphertext_real_len = (uint32_t)BN_num_bytes(key->n2);
    }

    if (!ciphertext || ciphertext_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }
    
    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    
    if (!msg || !c)
    {
        goto cleanup;
    }

    if (!BN_set_word(msg, plaintext))
    {
        goto cleanup;
    }
    
    ret = encrypt_openssl(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    len = BN_bn2bin(c, ciphertext);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = len;
    }

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

// @audit-ok: Properly validates ciphertext range (c < n²) before decryption
// ↳ Line 1058: BN_cmp(c, key->pub.n2) >= 0 check prevents invalid ciphertexts
// ↳ Prevents potential exceptions in modular exponentiation
long paillier_decrypt(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *plaintext_real_len)
{
    long ret = -1;
    int len = 0;

    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!ciphertext || ciphertext_len > (uint32_t)BN_num_bytes(key->pub.n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (plaintext_real_len)
    {
        *plaintext_real_len = (uint32_t)BN_num_bytes(key->pub.n);
    }

    if (!plaintext || plaintext_len < (uint32_t)BN_num_bytes(key->pub.n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    c = BN_CTX_get(ctx);
    msg = BN_CTX_get(ctx);

    if (!c || !msg)
    {
        goto cleanup;
    }
    
    if (!BN_bin2bn(ciphertext, ciphertext_len, c))
    {
        goto cleanup;
    }

    if (BN_cmp(c, key->pub.n2) >= 0)
    {
        // ciphertext not in n^2
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = paillier_decrypt_openssl_internal(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    len = BN_bn2bin(msg, plaintext);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (plaintext_real_len)
    {
        *plaintext_real_len = len;
    }

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

long paillier_decrypt_integer(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint64_t *plaintext)
{

    long ret = -1;
    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (ciphertext_len > (uint32_t)BN_num_bytes(key->pub.n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (!plaintext)
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);

    c = BN_CTX_get(ctx);
    msg = BN_CTX_get(ctx);
    
    if (!c || !msg) 
    {
        goto cleanup;
    }

    if (!BN_bin2bn(ciphertext, ciphertext_len, c))
    {
        goto cleanup;
    }

    if (BN_cmp(c, key->pub.n2) >= 0)
    {
        // ciphertext not in n^2
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = paillier_decrypt_openssl_internal(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    if ((uint32_t)BN_num_bytes(msg) > sizeof(*plaintext))
    {
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    *plaintext = BN_get_word(msg);

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

// @audit MEDIUM: Uses non-constant time is_coprime_fast for ciphertext validation
// ↳ Timing leak on public ciphertext values (lines 1238-1239)
// ↳ Could reveal information about ciphertext structure to timing attackers
// ↳ Consider constant-time validation or skip check (valid ciphertexts always coprime)
long paillier_add(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_ciphertext, uint32_t b_ciphertext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2) ||
        !b_ciphertext || b_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }
    
    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);

    if (!a || !b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, a))
    {
        goto cleanup;
    }

    if (!BN_bin2bn(b_ciphertext, b_ciphertext_len, b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and b_ciphertext are coprime to n
    if (is_coprime_fast(a, key->n, ctx) != 1 ||
        is_coprime_fast(b, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_mul(res, a, b, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_add_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }

    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    
    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    ret = encrypt_openssl(key, res, bn_b, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    ret = -1; //reset ret so next open ssl error would be logged.
    
    if (!BN_mod_mul(res, bn_a, res, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_sub(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_ciphertext, uint32_t b_ciphertext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2) ||
        !b_ciphertext || b_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }

    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!a || !b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, a))
    {
        goto cleanup;
    }

    if (!BN_bin2bn(b_ciphertext, b_ciphertext_len, b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and b_ciphertext are coprime to n
    if (is_coprime_fast(a, key->n, ctx) != 1 ||
        is_coprime_fast(b, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_inverse(b, b, key->n2, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_mul(res, a, b, key->n2, ctx))
        goto cleanup;

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }
    
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_sub_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    if (!key)
    {        
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }

    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
        
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }
    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }

    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
        
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = encrypt_openssl(key, res, bn_b, ctx);
    if (ret)
    {
        goto cleanup;
    }

    ret = -1; //reset ret so new open ssl errors could be logged   
    
    if (!BN_mod_inverse(res, res, key->n2, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_mul(res, bn_a, res, key->n2, ctx))
    {
        goto cleanup;
    }

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }
        
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_mul(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_plaintext, uint32_t b_plaintext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (!b_plaintext || b_plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    
    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }
        
    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);

    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    if (!BN_bin2bn(b_plaintext, b_plaintext_len, bn_b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_exp(res, bn_a, bn_b, key->n2, ctx))
    {
        goto cleanup;
    }

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }
        
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }
        
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_mul_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    if (!a_ciphertext || a_ciphertext_len > (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (result_real_len)
    {
        *result_real_len = (uint32_t)BN_num_bytes(key->n2);
    }
        
    if (!result || result_len < (uint32_t)BN_num_bytes(key->n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_exp(res, bn_a, bn_b, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2bin(res, result);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }
    
    if (result_real_len)
    {
        *result_real_len = len;
    }
        
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = ERR_get_error() * -1;
    }
        
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_get_ciphertext(const paillier_ciphertext_t *ciphertext_object, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len)
{
    if (!ciphertext_object)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (!ciphertext && ciphertext_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
        
    if (ciphertext_real_len)
    {
        *ciphertext_real_len = (uint32_t)BN_num_bytes(ciphertext_object->ciphertext);
    }
        
    if (!ciphertext || ciphertext_len < (uint32_t)BN_num_bytes(ciphertext_object->ciphertext))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    
    if (BN_bn2bin(ciphertext_object->ciphertext, ciphertext) <= 0)
    {
        return PAILLIER_ERROR_UNKNOWN;
    }

    return PAILLIER_SUCCESS;
}

void paillier_free_ciphertext(paillier_ciphertext_t *ciphertext_object)
{
    if (ciphertext_object)
    {
        BN_free(ciphertext_object->ciphertext);
        BN_free(ciphertext_object->r);
        free(ciphertext_object);
    }
}
