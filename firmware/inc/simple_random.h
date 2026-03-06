/**

 * @file simple_random.h

 * @author University of Denver team

 * @brief Simple TRNG based random number generator

 * @date 2026

 *

 */

#ifndef __SIMPLERANDOM__

#define __SIMPLERANDOM__

#define MAX_TRNG_WAIT 100 // milliseconds to wait before giving up on TRNG

/**

 * @brief Get some bytes from TRNG

 *

 * @param out: buffer for output

 * @param size: number of random bytes

 *

 * @return 0 on success, otherwise -1

 *

*/

int generate_trng_block(uint8_t *out, uint32_t size);

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

int generate_random_bytes(uint8_t *out, uint32_t size);

#endif