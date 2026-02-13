/**
 * @file capabilities.c
 * @author University of Denver team
 * @brief Handle capabilities for kernel level permissions management.
 * @date 2026
 *
 */

#include "capabilities.h"
#include "secrets.h"
#include "wolfssl/wolfcrypt/hkdf.h" //key derivation
#include "wolfssl/wolfcrypt/sha256.h"   // for WC_SHA256
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/random.h" //wc_rng
#define AES_SHARED_SIZE 16
#define NONCE_LEN 16
#define KEY_LEN 32

static WC_RNG g_rng;
static int g_rng_init = 0;
const char info[] = "transfer-v1|tx";
int nonce_rng_init_once(void) {
    if (!g_rng_init) {
        int r = wc_InitRng(&g_rng);
        if (r != 0) return r;
        g_rng_init = 1;
    }
    return 0;
}

int generate_nonce(uint8_t nonce[NONCE_LEN]) {
    int r = nonce_rng_init_once();
    if (r != 0) return r;
    return wc_RNG_GenerateBlock(&g_rng, nonce, NONCE_LEN);
}





// AES_128_SHARED = input keying material (Our shared/global AES128 key)
// salt = per-session salt (each side generates a nonce and they are combined to create the salt)
// info = context binding (device id, protocol label, direction, etc.)
int create_key(const byte* ikm, word32 ikm_len,
                           const byte initiator_nonce[NONCE_LEN],
                           const byte responder_nonce[NONCE_LEN], const byte* info, word32 info_len,
                           byte* out_key, word32 out_key_len)
{

    byte salt[NONCE_LEN * 2];
    /* fixed canonical order */
    memcpy(salt, initiator_nonce, NONCE_LEN);
    memcpy(salt + NONCE_LEN, responder_nonce, NONCE_LEN);
    
    return wc_HKDF(WC_SHA256, AES_128_SHARED, AES_SHARED_SIZE, salt, sizeof(salt), info, info_len, out_key, out_key_len);
}