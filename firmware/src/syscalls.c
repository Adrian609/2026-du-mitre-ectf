/**
 * @file systemcalls.c
 * @author University of Denver team
 * @brief eCTF supported system calls
 * @date 2026
 *
 */

#include <stdint.h>
#include <stdbool.h>

#include "syscalls.h"
#include "kernel.h"
#include "host_messaging.h"
#include "status_led.h"
#include "filesystem.h"
#include "security.h"
#include "simple_random.h"


extern int start_user_loop(void); // in HSM.c
extern unsigned long __STACK_END; // linker generated kernel stack end


/** @brief Decide which system call has been invoked and process return
 *
 *  @param stacked_args: points to stack top with stack frame
 *         stacked_args[0] = r0, [1] = r1, [2] = r2, [3] = r3;
 *         access system call arguments accordingly and modify to 
 *         return values
 *
 *  @param svc_id: system call identifier
 *
*/
KERNEL_CODE void svc_handler_logic(uint32_t *stacked_args, uint8_t svc_id) 
{

    if (svc_id == SYS_PRINT) { // TODO: remove this if block later
        char *msg = (char *)stacked_args[0];
        stacked_args[0] = syscall_svc_print(msg); // return value in r0
    }
	else if (svc_id == SYS_LED) {  // manipulate LED
		bool state = (bool)stacked_args[0];
		syscall_led(state);
	}
	else if (svc_id == SYS_RAND_BYTES) {  // get some random bytes
		uint8_t *nonce = (uint8_t *)stacked_args[0];
		uint32_t size = (uint32_t)stacked_args[1];
		stacked_args[0] = syscall_get_random_bytes(nonce, size); // return value in r0
	}
	else if (svc_id == SYS_READ) {  // read a file
		slot_t slot = (slot_t)stacked_args[0];
		file_t *curr_file = (file_t *)stacked_args[1];
		stacked_args[0] = syscall_read_file(slot, curr_file); // return value in r0
	}
	else if (svc_id == SYS_READ_META) {  // read files metadata
		void *file_list_ptr = (void *)stacked_args[0];
		stacked_args[0] = syscall_read_file_meta(file_list_ptr); // return value in r0
	}
	else if (svc_id == SYS_READ_FOR_TRANSFER) {  // read file in transfer encrypted form
	    void *request_ptr = (void *)stacked_args[0];
	    void *response_ptr = (void *)stacked_args[1];
	    stacked_args[0] = syscall_read_file_for_transfer(request_ptr, response_ptr); // return value in r0
	}
	else if (svc_id == SYS_READ_META_FOR_TRANSFER) {  // read files metadata in transfer encrypted form
		void *file_list_ptr = (void *)stacked_args[0];
		stacked_args[0] = syscall_read_file_meta_for_transfer(file_list_ptr); // return value in r0
	}
	else if (svc_id == SYS_WRITE) {  // write a file
		slot_t slot = (slot_t)stacked_args[0];
		file_t *src = (file_t *)stacked_args[1];
		uint8_t *uuid = (uint8_t *)stacked_args[2];
		stacked_args[0] = syscall_write_file(slot, src, uuid); // return value in r0
	}
	else if (svc_id == SYS_WRITE_FROM_TRANSFER) {  // write a file after transfer decrypt
	    void *response_ptr = (void *)stacked_args[0];
	    uint8_t *nonce = (uint8_t *)stacked_args[1];
	    slot_t slot = (slot_t)stacked_args[2];
		stacked_args[0] = syscall_write_file_from_transfer(response_ptr, nonce, slot); // return value in r0
	}
	else if (svc_id == SYS_FILTER_META) {  // filter some entries from transfer receive files list
	    void *file_list_ptr = (void *)stacked_args[0];
		uint8_t *nonce = (uint8_t *)stacked_args[1];
		stacked_args[0] = syscall_filter_file_meta(file_list_ptr, nonce); // return value in r0
	}
	else if (svc_id == SYS_CHECK_PIN) {  // check pin
		msg_type_t cmd = (msg_type_t)stacked_args[0];
		unsigned char *pin = (unsigned char *)stacked_args[1];
		stacked_args[0] = syscall_check_pin(cmd, pin);  // return value in r0
	}
	else if (svc_id == SYS_START_USER_LOOP) {  // switch from priviledged to unprivileged mode
		syscall_start_user_loop();
		// unreachable here; never returns
	}
	
	// No match; we just return
}


/** @brief Print a message
 *
 *  @param msg: pointer to message to print
 *
 *  @return just default 1
 *  TODO: remove later
*/
KERNEL_CODE int syscall_svc_print(char *msg) {
	print_debug(msg);

	return(1);	
}


/** @brief Turn LED on/off
 *
 *  @param state: true for on, false for off
 *
*/
KERNEL_CODE void syscall_led(bool state) {
	#if ON_BOARD
	if (state == false) STATUS_LED_OFF();
	else STATUS_LED_ON();
	#endif
}


/** @brief Get TRNG bytes
 *
 *  @param nonce: buffer for bytes
 *  @param size: number of bytes
 *
 *  @return 0 on success otherwise negative number
*/
KERNEL_CODE int syscall_get_random_bytes(uint8_t *nonce, uint32_t size) {
    if (generate_random_bytes(nonce, size) < 0)
        return INTERNAL_ERR;
        
    return 0;
}


// The following syscall_* functions act as a bridge from svc_handler_logic to 
// secure_* functions in security.c. See security.c or security.h for argument meanings

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file(slot_t slot, file_t *curr_file) {
	return secure_read_file(slot, curr_file);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_meta(void *file_list_ptr) {
	return secure_read_file_meta(file_list_ptr);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_for_transfer(void *request_ptr, void *response_ptr) {
	return secure_read_file_for_transfer(request_ptr, response_ptr);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_meta_for_transfer(void *file_list_ptr) {
	return secure_read_file_meta_for_transfer(file_list_ptr);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_write_file(slot_t slot, file_t *src, uint8_t *uuid) {
	return secure_write_file(slot, src, uuid);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_write_file_from_transfer(void *response_ptr, uint8_t *nonce, slot_t slot){
	return secure_write_file_from_transfer(response_ptr, nonce, slot);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_filter_file_meta(void *file_list_ptr, uint8_t *nonce) {
	return secure_filter_file_meta(file_list_ptr, nonce);
}

KERNEL_CODE static inline __attribute__((always_inline)) int syscall_check_pin(msg_type_t cmd, unsigned char *pin) {
	int ret = secure_check_pin(cmd, pin);
	
	#if ON_BOARD
	// If pin is wrong, delay 4 seconds
	if (ret < 0) {
	    for (int i=0; i < 4; i++) delay_cycles(DELAY_1_SEC);
	}
	#endif
	
	return ret;
}



/** @brief Start the start_user_loop function in unprivileged mode
 *
 *  @note This function does not return; it sets up a dummy
 *        stack frame on PSP, changes CONTROL register, and 
 *        triggers an exception return to switch to unprivileged
 *        thread mode (uses PSP thereafter)
 *
*/
KERNEL_CODE __attribute__((noinline)) void syscall_start_user_loop(void) {
	uint32_t control;
	__asm volatile ("mrs %0, control" : "=r"(control)); // get the CONTROL register
	
	if (control & 0x1) return; // do nothing if called from unprivileged


	// Create dummy stack frame using unprivileged stack area
	uint32_t *frame = (uint32_t *) (END_USER_SRAM + 1 - 32); // frame is now top of a stack frame
	frame[0]=0; frame[1]=0; frame[2]=0; frame[3]=0; // r0, r1, r2, r3
    frame[4]=0; frame[5]=0; // r12, lr
    frame[6]=(uint32_t)start_user_loop | 1; // return address; the 1 ensures thumb address
    frame[7]=0x01000000u; // xPSR (setting thumb bit)

	 // Set PSP to the synthetic frame
    __asm volatile ("msr psp, %0\n" : : "r"(frame) : "memory");
    __asm volatile ("isb\n" ::: "memory");

	// Set Thread mode to unprivileged + PSP (takes effect on exception return)
    __asm volatile (
        "movs r0, #3        \n"
        "msr control, r0    \n"
        "isb                \n"
        :
        :
        : "r0", "memory"
    );

	// Reset the MSP
	__asm volatile(
        "msr msp, %0 \n"
        "isb         \n"
        :
        : "r" (&__STACK_END)
        : "memory"
    );

	// Exception return to thread mode using PSP
    __asm volatile(
        "ldr r0, =0xFFFFFFFD \n"
        "mov lr, r0          \n"
        "bx  lr              \n"
        :
        :
        : "r0", "memory"
    );

	__builtin_unreachable();
}



/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////
//
// SVC CALL INTERFACE
// The following are SVC call interfaces callable by unprivileged code
//
/////////////////////////////////////////////////////////////////////////


/** @brief Printing from the kernel side
 *         Just a test if it works
 *
 *  @param msg message to print
 *
 *  @return 0 on success else 1
 *  TODO: remove later
*/
int svc_print(char *msg) {
	int ret = -1;

    // We pass the pointer in r0
    __asm volatile ("mov r0, %0\n" : : "r" (msg) : "r0");
    __asm volatile ("svc %0\n" : : "i" (SYS_PRINT));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret;

}


/** @brief Kernel call to turn LED on/off
 *
 *  @param state: true for on, false for off
 *
*/
void svc_led(bool state) {
	// We pass the state in r0
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)state) : "r0");
    __asm volatile ("svc %0\n" : : "i" (SYS_LED));
}


/** @brief Kernel call to get TRNG bytes
 *
 *  @param nonce: buffer for bytes
 *  @param size: number of bytes
 *
 *  @return 0 on success otherwise -1
 *
*/
int svc_get_random_bytes(uint8_t *nonce, uint32_t size) {
    int ret = -1;

	// We pass the buffer address in r0 and size in r1
	__asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)nonce) : "r0");
    __asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)size) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_RAND_BYTES));

	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret;
}


/** @brief Kernel call to verify pin and set capability
 *
 *  @param cmd: the command initiating the call
 *  @param pin: the 6 character pin to verify
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_check_pin(msg_type_t cmd, unsigned char *pin) {
	int ret = -1;

	// We pass the command in r0 and pin address in r1
	__asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)cmd) : "r0");
    __asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)pin) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_CHECK_PIN));

	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret;
}


/** @brief Kernel call to read a file
 *
 *  @param slot: the file's slot number
 *  @param curr_file: buffer to store file data
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file(slot_t slot, file_t *curr_file) {
	int ret = -1;

    // We pass the slot in r0 and curr_file in r1
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)slot) : "r0");
	__asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)curr_file) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_READ));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to read file list
 *
 *  @param file_list: buffer to store the list
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_meta(list_response_t *file_list) {
    int ret = -1;

    // We pass the file_list in r0
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)file_list) : "r0");
    __asm volatile ("svc %0\n" : : "i" (SYS_READ_META));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to read file in transfer encrypted form
 *
 *  @param request: details of read request from neighbor HSM
 *  @param response: buffer to store transfer encrypted file
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_for_transfer(receive_request_t *request, receive_response_enc_t *response) {
	int ret = -1;

    // We pass the request in r0 and response buffer in r1
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)request) : "r0");
	__asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)response) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_READ_FOR_TRANSFER));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to read file list in transfer encrypted form
 *
 *  @param file_list: buffer to store transfer encrypted file list
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_meta_for_transfer(list_response_enc_t *file_list) {
    int ret = -1;

    // We pass the file_list in r0
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)file_list) : "r0");
    __asm volatile ("svc %0\n" : : "i" (SYS_READ_META_FOR_TRANSFER));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to write a file
 *
 *  @param slot: the slot to write to
 *  @param src: buffer holding the file
 *  @param uuid: the uuid of the file
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_write_file(slot_t slot, file_t *src, uint8_t *uuid) {
	int ret = -1;

    // We pass the slot in r0, src in r1, and uuid in r2
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)slot) : "r0");
	__asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)src) : "r1");
	__asm volatile ("mov r2, %0\n" : : "r" ((uint32_t)uuid) : "r2");
    __asm volatile ("svc %0\n" : : "i" (SYS_WRITE));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to write a transfer encrypted file
 *
 *  @param response: the received transfer encrypted file
 *  @param nonce: the local nonce used in the transfer process
 *  @param slot: the slot to write the file to
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_write_file_from_transfer(receive_response_enc_t *response, uint8_t *nonce, slot_t slot) {
	int ret = -1;

    // We pass the response buffer in r0, nonce address in r1, and slot in r2
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)response) : "r0");
	__asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)nonce) : "r1");
	__asm volatile ("mov r2, %0\n" : : "r" ((uint32_t)slot) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_WRITE_FROM_TRANSFER));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


/** @brief Kernel call to filter items from a transfer encrypted file list
 *
 *  @param file_list: the received transfer encrypted file list
 *  @param nonce: the local nonce used in the transfer process
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_filter_file_meta(list_response_enc_t *file_list, uint8_t *nonce) {
	int ret = -1;

    // We pass the file_list in r0 and nonce address in r1
    __asm volatile ("mov r0, %0\n" : : "r" ((uint32_t)file_list) : "r0");
	__asm volatile ("mov r1, %0\n" : : "r" ((uint32_t)nonce) : "r1");
    __asm volatile ("svc %0\n" : : "i" (SYS_FILTER_META));


	// Get return value from r0
	__asm volatile ("mov %0, r0" : "=r" (ret));

	return ret ;
}


