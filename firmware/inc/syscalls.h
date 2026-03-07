/**
 * @file systemcalls.h
 * @author University of Denver team
 * @brief eCTF supported system calls
 * @date 2026
 *
 */

#ifndef __SYSTEMCALLS__
#define __SYSTEMCALLS__

#include "kernel.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "commands.h"

#include <stdint.h>
#include <stdbool.h>


// SVC call IDs
#define SYS_PRINT		           0x01
#define SYS_READ                   0x02
#define SYS_READ_META              0x03
#define SYS_READ_FOR_TRANSFER      0x04
#define SYS_READ_META_FOR_TRANSFER 0x05
#define SYS_WRITE                  0x06
#define SYS_WRITE_FROM_TRANSFER    0x07
#define SYS_FILTER_META            0x08
#define SYS_CHECK_PIN              0x10
#define SYS_RAND_BYTES             0xEF
#define SYS_LED                    0xF0
#define SYS_START_USER_LOOP        0xFF


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
KERNEL_CODE void svc_handler_logic(uint32_t *stacked_args, uint8_t svc_id);


/** @brief Turn LED on/off
 *
 *  @param state: true for on, false for off
 *
*/
KERNEL_CODE void syscall_led(bool state);


/** @brief Print a message
 *
 *  @param msg: pointer to message to print
 *
 *  @return just default 1
 *  TODO: remove later
*/
KERNEL_CODE int syscall_svc_print(char *msg);


/** @brief Get TRNG bytes
 *
 *  @param nonce: buffer for bytes
 *  @param size: number of bytes
 *
 *  @return 0 on success otherwise negative number
*/
KERNEL_CODE int syscall_get_random_bytes(uint8_t *nonce, uint32_t size);



// The following syscall_* functions act as a bridge from svc_handler_logic to 
// secure_* functions in security.c. See security.c or security.h for argument meanings
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_check_pin(msg_type_t cmd, unsigned char *pin);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file(slot_t slot, file_t *curr_file);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_meta(void *file_list_ptr);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_meta_for_transfer(void *file_list_ptr);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_read_file_for_transfer(void *request, void *response);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_write_file(slot_t slot, file_t *src, uint8_t *uuid);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_write_file_from_transfer(void *response_ptr, uint8_t *nonce, slot_t slot);
KERNEL_CODE static inline __attribute__((always_inline)) int syscall_filter_file_meta(void *file_list_ptr, uint8_t *nonce);


/** @brief Start the start_user_loop function in unprivileged mode
 *
 *  @note This function does not return; it sets up a dummy
 *        stack frame on PSP, changes CONTROL register, and 
 *        triggers an exception return to switch to unprivileged
 *        thread mode (uses PSP thereafter)
 *
*/
KERNEL_CODE __attribute__((noinline)) void syscall_start_user_loop(void);


/** @brief Kernel call to turn LED on/off
 *
 *  @param state: true for on, false for off
 *
*/
void svc_led(bool state);


/** @brief Printing from the kernel side
 *         Just a test if it works
 *
 *  @param msg message to print
 *
 *  @return 0 on success else 1
 *  TODO: remove later
*/
int svc_print(char *msg);


/** @brief Kernel call to get TRNG bytes
 *
 *  @param nonce: buffer for bytes
 *  @param size: number of bytes
 *
 *  @return 0 on success otherwise -1
 *
*/
int svc_get_random_bytes(uint8_t *nonce, uint32_t size);


/** @brief Kernel call to verify pin and set capability
 *
 *  @param cmd: the command initiating the call
 *  @param pin: the 6 character pin to verify
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_check_pin(msg_type_t cmd, unsigned char *pin);


/** @brief Kernel call to read a file
 *
 *  @param slot: the file's slot number
 *  @param curr_file: buffer to store file data
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file(slot_t slot, file_t *curr_file);


/** @brief Kernel call to read file list
 *
 *  @param file_list: buffer to store the list
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_meta(list_response_t *file_list);


/** @brief Kernel call to read file list in transfer encrypted form
 *
 *  @param file_list: buffer to store transfer encrypted file list
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_meta_for_transfer(list_response_enc_t *file_list);


/** @brief Kernel call to read file in transfer encrypted form
 *
 *  @param request: details of read request from neighbor HSM
 *  @param response: buffer to store transfer encrypted file
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_read_file_for_transfer(receive_request_t *request, receive_response_enc_t *response);


/** @brief Kernel call to write a file
 *
 *  @param slot: the slot to write to
 *  @param src: buffer holding the file
 *  @param uuid: the uuid of the file
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_write_file(slot_t slot, file_t *src, uint8_t *uuid);


/** @brief Kernel call to write a transfer encrypted file
 *
 *  @param response: the received transfer encrypted file
 *  @param nonce: the local nonce used in the transfer process
 *  @param slot: the slot to write the file to
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_write_file_from_transfer(receive_response_enc_t *response, uint8_t *nonce, slot_t slot);


/** @brief Kernel call to filter items from a transfer encrypted file list
 *
 *  @param file_list: the received transfer encrypted file list
 *  @param nonce: the local nonce used in the transfer process
 *
 *  @return 0 on success, negative number on error
 *
*/
int svc_filter_file_meta(list_response_enc_t *file_list, uint8_t *nonce);

#endif
