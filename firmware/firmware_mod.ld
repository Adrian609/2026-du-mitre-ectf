/*****************************************************************************

Modified from eCTF 2026 reference design

*****************************************************************************/

-uinterruptVectors
--stack_size=1024

#define K_FLASH_BASE        0x00006000
#define U_FLASH_BASE        0x00024000
#define K_SRAM_BASE         0x20206000
#define U_SRAM_BASE         0x20200000
#define K_STAGE_BASE        0x0003A400
#define SECURE_STORAGE_BASE 0x0000E000

#define KERNEL_STACK_SIZE 1024


MEMORY
{
    /* Physical regions matching MPU setup */
    K_FLASH (RX)        : origin = 0x00006000, length = 0x00008000   /* Kernel code */
	SECURE_STORAGE (R)  : origin = 0x0000E000, length = 0x00002000   /* Kernel read-only flash */
    U_FLASH (RX)        : origin = 0x00024000, length = 0x00014000   /* User code */
	K_STAGE (RW)        : origin = 0x0003A400, length = 0x00005C00   /* Kernel read-write flash */
    U_SRAM  (RW)        : origin = 0x20200000, length = 0x00006000   /* User SRAM */
    K_SRAM  (RW)        : origin = 0x20206000, length = 0x00002000   /* Kernel SRAM */

	/* From reference design */
	BOOTLOADER      (RX)  : origin = 0x00000000, length = 0x00006000 /* Bootloader flash - unusable */
    FAT             (RW)  : origin = 0x0003A000, length = 0x00000400 /* Used to store tag, length, pointer values for files */
	BCR_CONFIG      (R)   : origin = 0x41C00000, length = 0x000000FF
    BSL_CONFIG      (R)   : origin = 0x41C00100, length = 0x00000080
}

SECTIONS
{
    /* --- KERNEL FLASH (Region 0 and part of 2) --- */
    .intvecs   : > K_FLASH_BASE         /* Hardware expects this at the start */
    .k_code : { 		
        *(.kernel_code)  /* Tagged kernel code */
    } > K_FLASH

					
    /* Runtime init tables - putting in privileged flash for startup */
    .cinit      : palign(8) {} > K_FLASH
    .pinit      : palign(8) {} > K_FLASH
    .binit      : palign(8) {} > K_FLASH
    .TI.ramfunc : load = K_FLASH, run = K_SRAM, table(BINIT)

    .k_stage : {
        *(.kernel_stage) /* Tagged kernel stage variables */
    } > K_STAGE_BASE


	/* --- SECURE STORAGE (Region 1) --- */
    .k_const : {
        *(.kernel_const)  /* Tagged kernel constant read-only variables */
    } > SECURE_STORAGE_BASE


    /* --- USER FLASH (Region 3) --- */
    /* All standard code and constants default to User space */
    .text       : palign(8) {} > U_FLASH_BASE
    .const      : palign(8) {} > U_FLASH
    .rodata     : palign(8) {} > U_FLASH
    .ARM.exidx  : palign(8) {} > U_FLASH
    .init_array : palign(8) {} > U_FLASH

    /* --- USER SRAM (Region 4) --- */
    /* All standard variables default to User space */    
    .data       : > U_SRAM_BASE
    .bss        : > U_SRAM
    .sysmem     : > U_SRAM
    .args       : > U_SRAM
    .u_stack    : > U_SRAM (HIGH)

    /* --- KERNEL SRAM (Region 5) --- */
	.vtable     : > K_SRAM_BASE
    .k_vars : { *(.kernel_data)   /* Tagged kernel initialized global */
			    *(.kernel_bss)    /* Tagged kernel uninitialized global */
	} > K_SRAM

	.stack    : {					   /* Ensure linker does not use high area of SRAM */
        . += KERNEL_STACK_SIZE;
	} > K_SRAM (HIGH)

	.files        : palign(8)
	.BCRConfig  : {} > BCR_CONFIG
    .BSLConfig  : {} > BSL_CONFIG
}








