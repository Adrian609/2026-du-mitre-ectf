/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "syscalls.h"


extern unsigned char uart_buf[MAX_MSG_SIZE];  // from HSM.c
extern const volatile group_permission_t global_permissions[MAX_PERMS]; // from secrets.h
extern group_permission_t global_permissions_u[MAX_PERMS]; // from security.c
extern uint8_t global_permissions_sig[HMAC_SIZE]; // from security.c


/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief Print error based on code
 *
 *  @param error_code: the error code (see commands.h)
 *
 *  @return 0 if no error, else -1
 *
 *  @note see ERR_CHECK macro in commands.h
 *
*/
int check_for_errors(int error_code) {
	if (error_code >= 0) return 0;

    // TODO: Instead of descriptive errors, just return a generic error 
    //      like "HSM failed with an error"
    
	switch (error_code) {
        case UNKNOWN_ERR:
            print_error("Unknown error");
            break;
        case PIN_ERR:
            print_error("Invalid PIN");
            break;
        case PERM_ERR:
            print_error("Permission failure");
            break;
        case READ_ERR:
            print_error("Failed to read file");
            break;
        case READ_META_ERR:
            print_error("Failed to read file metadata");
            break;
        case WRITE_ERR:
            print_error("Failed to write file");
            break;
        case RECEIVE_ERR:
            print_error("Failed to receive file");
            break;
        case INTERROGATE_ERR:
            print_error("Failed to receive file metadata");
            break;
		case INTERNAL_ERR:
            print_error("Kernel internal error");
            break;
		case AES_ENCRYPT_ERR:
            print_error("Data encrypt error");
            break;
		case AES_DECRYPT_ERR:
            print_error("Data decrypt error");
            break;
		case AES_TAG_ERR:
            print_error("Data integrity failure");
            break;
        default:
            print_error("Undefined error code");
            break;
    }
	return -1;
}


/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    // Check pin
    ERR_CHECK(svc_check_pin(LIST_MSG, command->pin)); // lands in secure_check_pin

    // Copy relevant fields into the final struct
    memset(&file_list, 0, sizeof(file_list));
    ERR_CHECK(svc_read_file_meta(&file_list)); // lands in secure_read_file_meta

    // Write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    // Check pin
    ERR_CHECK(svc_check_pin(READ_MSG, command->pin)); // lands in secure_check_pin      

    // Zeroizing memory is a pretty good practice
    memset(&file_info, 0, sizeof(read_response_t));
        
    // Read the file
    ERR_CHECK(svc_read_file(command->slot, &curr_file)); // lands in secure_read_file
    
    // Copy structure of the persistent file
    memcpy(file_info.name, &curr_file.name, strlen(curr_file.name));
    memcpy(file_info.contents, &curr_file.contents, curr_file.contents_len);


    // Write a success message with the file information
    pkt_len_t length = MAX_NAME_SIZE + curr_file.contents_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    return 0;
}


/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    int ret;
    file_t curr_file;

    // Check pin
    ERR_CHECK(svc_check_pin(WRITE_MSG, command->pin)); // lands in secure_check_pin
        
    // Create file object    
    if (create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents) < 0) {
        print_error("Illegal name or content length");
        return -1;
    }

    // Store the file persistently
    ERR_CHECK(svc_write_file(command->slot, &curr_file, command->uuid));  // lands in secure_write_file

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int receive(uint16_t pkt_len, uint8_t *buf) {
    receive_command_t *command = (receive_command_t *)buf;
    receive_request_t request;
    receive_response_enc_t *recv_resp;  // file will come encrypted here
    msg_type_t cmd;
    uint16_t len_recv_msg = 0;   
    
    int ret = -1;

    uint16_t write_slot = command->write_slot;
    uint8_t nonce[NONCE_SIZE];
    
    // Pin check
    ERR_CHECK(svc_check_pin(RECEIVE_MSG, command->pin)); // lands in secure_check_pin  

    // Zeroize the buffers we will use
    memset(&request, 0, sizeof(request));

    // Prep request to neighbor (slot number, local permission strucuture with signature), nonce
    request.slot = command->read_slot;
    memcpy(request.permissions, (void *)global_permissions_u, sizeof(group_permission_t) * MAX_PERMS);
    memcpy(request.permissions_sig, global_permissions_sig, HMAC_SIZE);
    ERR_CHECK(svc_get_random_bytes(request.nonce, NONCE_SIZE));  // create a nonce
    memcpy(nonce, request.nonce, NONCE_SIZE);
    
    
    // Request the file from the neighboring device
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request, sizeof(receive_request_t));


    // Recieve the response message
    memset(uart_buf, 0x0, sizeof(uart_buf));
    len_recv_msg = sizeof(uart_buf); // response must fit in uart buf
    recv_resp = (receive_response_enc_t *)uart_buf;
    if (read_packet(TRANSFER_INTERFACE, &cmd, recv_resp, &len_recv_msg) != MSG_OK) {
        print_error("Bad incoming data");
        return -1;
    }
    if (cmd == ERROR_MSG) {
        print_error((char *)recv_resp);
        return -1;
    }
    else if (cmd != RECEIVE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // Decrypt the encrypted contents and write
    ERR_CHECK(svc_write_file_from_transfer(recv_resp, nonce, write_slot));  // lands in secure_write_file_from_transfer
    
    
    // Empty success message
    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    uint8_t nonce[NONCE_SIZE];
    
    msg_type_t cmd;
    list_response_enc_t final_list_buf; // response will come encrypted here
    
    uint16_t len_recv_msg = 0;

    // Pin check
    ERR_CHECK(svc_check_pin(INTERROGATE_MSG, command->pin)); // lands in secure_check_pin  

    // Create a nonce
    ERR_CHECK(svc_get_random_bytes(nonce, NONCE_SIZE)); 
    
    // Send the nonce and request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, nonce, NONCE_SIZE);
    
     
    // Recieve the response message
    len_recv_msg = sizeof(uart_buf); // response must fit in uart buf
    memset(&final_list_buf, 0x0, sizeof(list_response_enc_t));
    if (read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg) != MSG_OK) {
        print_error("Bad incoming data");
        return -1;
    }
    if (cmd == ERROR_MSG) {
        print_error((char *)&final_list_buf);
        return -1;
    }
    else if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // Decrypt the encrypted contents and filter 
    ERR_CHECK(svc_filter_file_meta(&final_list_buf, nonce));  // lands in secure_filter_file_meta
    
    // Return the final list to the user (final_list_buf.data is now decrypted)
    pkt_len_t write_length = LIST_PKT_LEN(final_list_buf.data.n_files);
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &(final_list_buf.data), write_length);
    
    return 0;
}


/** @brief Perform the listen operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    msg_type_t cmd;    
    pkt_len_t read_length;    
    
    
    // Pin check not needed for listen but we must call it to register capability
    ERR_CHECK(svc_check_pin(LISTEN_MSG, NULL)); // lands in secure_check_pin  

    print_debug("Listening...");
        
    // Receive a packet from a neighboring hsm
    read_length = sizeof(uart_buf); // request must fit in uart buf
    memset(uart_buf, 0, sizeof(uart_buf));
    if (read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length) != MSG_OK) {
        print_error("Bad incoming data");
        return -1;
    }

    // Process command from neighbor
    switch (cmd) {
        case INTERROGATE_MSG:
            if (listen_interrogate(uart_buf) < 0) {
                char msg[] = "Remote HSM failed with an error\0";
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, msg, strlen(msg)+1);
                return -1;
            }
            break;
        case RECEIVE_MSG:
            if (listen_receive(uart_buf) < 0) {
                char msg[] = "Remote HSM failed with an error\0";
                write_packet(TRANSFER_INTERFACE, ERROR_MSG, msg, strlen(msg)+1);
                return -1;
            }
            break;
        default:
            print_error("Bad message type");
            return -1;
    }

    // Blank success message
    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
    return 0;
}

/** @brief Perform the interogate operation during listen
 *
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int listen_interrogate(uint8_t *buff) {
    list_response_enc_t file_list_enc;
    pkt_len_t write_length;
    
    // Zeroize the buffers we will use
    memset(&file_list_enc, 0, sizeof(file_list_enc));

    // Generate encrypted list of files for the other device
    // If this read fails, the other device will not receive a response and
    // may need to be reset before further testing can occur
    memcpy(file_list_enc.nonce, buff, NONCE_SIZE);  // other device sends nonce in interrogate command
    ERR_CHECK(svc_read_file_meta_for_transfer(&file_list_enc));  // lands in secure_read_file_meta_for_transfer


    // Send the list of files on this device in encrypted form
    write_length = file_list_enc.data_len + offsetof(list_response_enc_t, data);
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list_enc, write_length);
    
    return 0;
}

/** @brief Perform the receive operation during listen
 *
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int listen_receive(uint8_t *buff) {
    pkt_len_t write_length;
    receive_request_t command;
    receive_response_enc_t *recv_resp_enc;

    
    // Get the request
    memcpy(&command, buff, sizeof(receive_request_t));

    // Zeroize the buffers we will use
    memset(uart_buf, 0x0, sizeof(uart_buf));
    recv_resp_enc = (receive_response_enc_t *)uart_buf;
    
    // Generate encrypted response for the other device
    // If this read fails, the other device will not receive a response and
    // may need to be reset before further testing can occur
    ERR_CHECK(svc_read_file_for_transfer(&command, recv_resp_enc));  // lands in secure_read_file_for_transfer

    // Send the file to the neighbor hsm in encrypted form
    write_length = recv_resp_enc->data_len + offsetof(receive_response_enc_t, data);
    write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, recv_resp_enc, write_length);
    
    return 0;
}
