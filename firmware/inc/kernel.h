/**
 * @file kernel.h
 * @author University of Denver team
 * @brief Corext M0+ hardware setup for eCTF
 * @date 2026
 *
 */

#ifndef __KERNEL__
#define __KERNEL__

/**
 * Tag for kernel initialized globals (goes to kernel SRAM)
 * E.g. KERNEL_DATA int x = 5;
 */
#define KERNEL_DATA   __attribute__((section(".kernel_data"), retain))

/**
 * Tag for kernel uninitialized globals (goes to kernel SRAM)
 * E.g. KERNEL_BSS int x;
 */
#define KERNEL_BSS    __attribute__((section(".kernel_bss"), retain))

/** 
 * Tag for kernel constants (read-only; goes to kernel flash)
 * E.g. KERNEL_CONST const uint8_t pin_hash[] = 
 *        "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4";
 */
#define KERNEL_CONST __attribute__((section(".kernel_const"), retain)) volatile const

/** 
 * Tag for kernel variables in staging area of flash (goes to kernel flash)
 * E.g. KERNEL_STAGE uint8_t scratchpad[9*1024];
 *
 * NOTE: since these are stored in flash, they can be read through usual C
 *  but need special functions to write; also every variable is aligned to
 * FLASH_PAGE_SIZE (1KB)
 */ 
#define KERNEL_STAGE  __attribute__((section(".kernel_stage"), aligned(1024), retain))

/** 
 * Tag for kernel functions
 * E.g. KERNEL_CODE void func(int x) {...}
 * 
 * NOTE: internal funtion variables do not have to be tagged since
 * they will go to kernel stack during runtime
*/
#define KERNEL_CODE __attribute__((section(".kernel_code"), retain))


// MPU areas (useful in checking bounds)
#define START_USER_SRAM     0x20200000
#define END_USER_SRAM       0x20205FFF
#define START_KERNEL_SRAM   0x20206000
#define END_KERNEL_SRAM     0x20207FFF
#define START_USER_FLASH    0x00024000
#define END_USER_FLASH      0x00037FFF
#define START_KERNEL_STAGE  0x0003A400
#define END_KERNEL_STAGE    0x0003FFFF


// Macro to run code with unlocked kernel SRAM execution
// !!Needed because flash controller moves code to SRAM
#define K_SRAM_EXECUTE(code) do { \
    MPU->RNR  = 5;\
    MPU->RASR &= ~(1ul << 28); \
    __DSB();                   \
    __ISB();                   \
    {code}                     \
    MPU->RNR  = 5;\
    MPU->RASR |= (1ul << 28); \
    __DSB();                   \
    __ISB();                   \
} while(0) \


// Delay macro
#define CPU_MHZ    32
#define DELAY_1_SEC    (CPU_MHZ * 1000000)
#define DELAY_1_MSEC   (CPU_MHZ * 1000)

/** @brief Prints the current processor configuration
*/
void print_current_mode(void);


/** @brief Initializes hardware and switches to user mode
*/
KERNEL_CODE __attribute__((noinline, noreturn)) void start_kernel(void);


/** @brief Initializes peripherals for system boot.
*/
KERNEL_CODE void init();


/** @brief Setup MPU regions
*/
KERNEL_CODE void setup_mpu_layout(void);



#endif
