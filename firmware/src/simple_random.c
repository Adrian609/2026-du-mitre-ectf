/**
 * @file simple_random.c
 * @author University of Denver team
 * @brief Simple TRNG based random number generator
 * @date 2026
 *
 */
 
 
#include <stdint.h>

#include "kernel.h"
#include "simple_random.h"
#include "secrets.h"
#include "ti_msp_dl_config.h"

#include "wolfssl/wolfcrypt/hash.h"



KERNEL_BSS uint32_t prng_counter; // PRNG_COUNTER initialized from TRNG


/**
 * @brief Get some bytes from TRNG
 *
 * @param out: buffer for output
 * @param size: number of random bytes
 *
 * @return 0 on success, otherwise -1
 *
*/
int generate_trng_block(uint8_t* out, uint32_t size) {
    uint32_t i;
    uint32_t r;
    uint32_t to_fill;

    uint32_t time_waiting = 0; // milliseconds waited for TRNG
    
    if (size <= 0 || out == NULL) return -1;
   
    #if ON_BOARD
    for (i = 0; i < size; i+=4) {
        time_waiting = 0;
        
        // Get a word (4 bytes) from TRNG
        while (!DL_TRNG_isCaptureReady(TRNG)) {
            time_waiting++;
            
            if (time_waiting > MAX_TRNG_WAIT) return -1;
            
            delay_cycles(DELAY_1_MSEC);
        }
        
        DL_TRNG_clearInterruptStatus(
            TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
            
        r = DL_TRNG_getCapture(TRNG);
        
        // Copy over to out buffer
        to_fill = (size - i >= 4) ? 4 : (size - i);
        memcpy(out+i, &r, to_fill);        
    }
    #endif
    
    return 0;
}


/**
 * @brief Low memory RNG
 *
 * @param out: buffer for output
 * @param size: number of random bytes
 *
 * @return 0 on success, otherwise -1
 *
 * @note Uses TRNG for the random bytes, but XORs its output with
 *       SHA256(Counter | PRNG_SECRET) for layering
*/
int generate_random_bytes(uint8_t* out, uint32_t size) {   
    
    uint8_t hash[32];              
    uint8_t trng_buf[32];       
    uint8_t secret_and_counter[36];  // concatenated counter and secret
    
    for (uint32_t i = 0; i < size; i += 32) {
    
        // Get TRNG bytes
        generate_trng_block(trng_buf, 32);

        // Compute SHA256(Counter | PRNG_SECRET)
        memcpy(secret_and_counter, &prng_counter, 4);
        memcpy(secret_and_counter+4, (void *)prng_secret, 32);

        prng_counter++;

        if (wc_Sha256Hash(secret_and_counter, 36, hash) < 0) {
            return -1;
        }
    
        // XOR hash with TRNG bytes
        for (int j = 0; j < 32; j++) {
            hash[j] ^= trng_buf[j];
        }

        // Copy to output
        uint32_t to_copy = (size - i >= 32) ? 32 : (size - i);
        memcpy(out + i, hash, to_copy);
    }
    
    return 0;
}

