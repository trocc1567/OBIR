/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 04:50:21
 *  Description:
 *  Credits: 
 *
 *      This file is a modification of the original libcoap source file. Aim of the modification was to 
 *      provide cleaner, richer documented and ESP8266-optimised version of the library. Core API of the 
 *      project was not changed or expanded, although some elemenets (e.g. DTLS support) have been removed 
 *      due to lack of needings from the modifications' authors. 
 * 
 * ============================================================================================================ */

/* -------------------------------------------- [Original header] --------------------------------------------- */

/* block.c -- block transfer
 *
 * Copyright (C) 2010--2012,2015-2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

# include <assert.h>
#include "coap_config.h"
#include "coap_debug.h"
#include "coap_hashkey.h"
#include "libcoap.h"
#include "block.h"
#include "resource.h"

/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

unsigned int coap_opt_block_num(const coap_opt_t *block_opt) {

    // Get options' length
    uint16_t len = coap_opt_length(block_opt);
    if (len == 0)
        return 0;

    // Get upper 'len - 1' bytes of the option's value as an integer
    unsigned int num = 0;
    if (len > 1)
        num = coap_decode_var_bytes(coap_opt_value(block_opt), len - 1);

    // Put 'num' and 4 upper bits of the least significant byte into a single number (i.e block's num)
    return (num << 4) | ( (*COAP_OPT_BLOCK_LAST_BYTE(block_opt) & 0xF0) >> 4);
}


int coap_get_block(
    coap_pdu_t *pdu, 
    uint16_t type, 
    coap_block_t *block
){
    assert(block);
    assert(pdu);

    // Clear the block
    memset(block, 0, sizeof(coap_block_t));

    // Find desired block option in the @p pdu 
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    if( (option = coap_check_option(pdu, type, &opt_iter)) != NULL) {

        // Initialize block's parameters
        block->szx = COAP_OPT_BLOCK_SZX(option);
        if (COAP_OPT_BLOCK_MORE(option))
            block->m = 1;

        // Get block number and check if it's in the range
        unsigned int num = coap_opt_block_num(option);
        if (num > 0xFFFFF)
            return 0;
        block->num = num;

        return 1;
    }

    return 0;
}


int coap_write_block_opt(
    coap_block_t *block, 
    uint16_t type,
    coap_pdu_t *pdu, 
    size_t data_length
){
    assert(pdu);
    assert(pdu->max_size > 0);

    // Decode block's size
    size_t block_size = 1 << (block->szx + 4);

    // Check if requested block is in range of the data 
    size_t start = block->num * block_size;
    if (data_length <= start) {
        coap_log(LOG_DEBUG, "illegal block requested\n");
        return 0;
    }

    // Compute free space that will be available for data in the pdu after writing an option
    size_t available = pdu->max_size - pdu->used_size - 2 - 1;
    if(block->num < 0xf)
        available -= 1;
    else if(block->num < 0xfff)
        available -= 2;
    else
        available -= 3;    

    /**
     * @note: In the statement before the if-else ladder, '-1' referes to the payload marker that
     *    will be written to the PDU before data and '-2' is the max size of the Block2 option
     *    header.
     * 
     * @note: The if-else ladder updates the available space with respect to the length of the
     *    Block2 option value's length.
     */

    // Check if entire block fits in message
    if (block_size <= available) {
        block->m = (block_size < data_length - start);
    }
    // If requested block is larger than the remaining space in pdu, check if remaining
    // data to send in face need so much space and when not, if it can be fit into the pdu
    else {

        // Turns out that it's the final block and everything fits in the message
        if (data_length - start <= available)
            block->m = 0;
        // Otherwise try to decrease the block size 
        else {

            // 16 bytes is the smallest block size
            if (available < 16) {
                coap_log(LOG_DEBUG, "not enough space, even the smallest block does not fit");
                return -1;
            }

            // Compute exponent for the new block size
            unsigned int new_block_size = coap_flsll((long long) available) - 5;
            coap_log(LOG_DEBUG, "decrease block size for %lu to %d\n", (unsigned long) available, 1 << (new_block_size + 4));

            // If we decrease the block's size, there will be aleways more blocks to be send
            block->m = 1;

            // Compute actual block's index (num) and it's size's exponent
            block->num <<= block->szx - new_block_size;
            block->szx = new_block_size;
        }
    }

    // Encode option to the bytes-vector
    unsigned char buf[4];
    size_t options_length = 
        coap_encode_var_safe(buf, sizeof(buf), ((block->num << 4) | (block->m << 3) | block->szx));

    // Write option to the PDU
    coap_add_option(pdu, type, options_length, buf);

    return 1;
}


int coap_add_block(
    coap_pdu_t *pdu, 
    unsigned int len, 
    const uint8_t *data,
    coap_block_t *block
){

    // Check whether requested block is in data's range
    unsigned int start = block->num << (block->szx + 4);
    if (len <= start)
        return 0;

    // Compute actual size of the data (can be smaller than block's size when the last block is sent)
    size_t block_size = 
        min(len - start, (1U << (block->szx + 4)));

    // Append data to the PDU
    return coap_add_data(pdu, block_size, data + start);
}


void coap_add_data_blocked_response(
    coap_resource_t *resource,
    coap_session_t *session,
    coap_pdu_t *request,
    coap_pdu_t *response,
    const coap_binary_t *token,
    uint16_t media_type,
    int maxage,
    size_t length,
    const uint8_t* data
) {

    coap_subscription_t *subscription =
        coap_find_observer(resource, session, token);

    /*
    * Need to check that a valid block is getting asked for so that the
    * correct options are put into the PDU.
    */
    coap_block_t block2 = { 0, 0, 0 };
    int block2_requested = 0;

    // If created message is associated with some request ...
    if(request){

        // Check requested block parameters
        if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)) {

            // Denote that Block2 was requested
            block2_requested = 1;

            // If requested block outside of the data scope ...
            if (length <= (block2.num << (block2.szx + 4))) {
                coap_log(LOG_DEBUG, "Illegal block requested (%d > last block = %lu)\n",
                            block2.num, (unsigned long) (length >> (block2.szx + 4)));

                // Response with 4.00 Bad Request
                response->code = COAP_RESPONSE_BAD_REQUEST;

                goto error;
            }
        }
    }
    // Otherwise, check if subscriber to be notified has the Block2 option set
    else if (subscription && subscription->has_block2) {
        
        // Denote that Block2 was requested
        block2_requested = 1;

        block2 = subscription->block2;
        block2.num = 0;
    }

    // Set default response code
    response->code = COAP_RESPONSE_CONTENT;

    // Add etag for the resource
    coap_key_t etag;
    memset(etag, 0, sizeof(etag));
    coap_hash(data, length, etag);
    coap_add_option(response, COAP_OPTION_ETAG, sizeof(etag), etag);

    // If message is sent as the first block of notification ...
    if (block2.num == 0 && subscription != NULL){

        // Add 'Observe' option to the PDU
        unsigned char opt_val[4];
        size_t opt_len = coap_encode_var_safe(opt_val, sizeof(opt_val), resource->observe);
        coap_add_option(
            response,
            COAP_OPTION_OBSERVE,
            opt_len,
            opt_val
        );
    }

    // Add 'Content-type' option to the PDU
    unsigned char opt_val[4];
    size_t opt_len = coap_encode_var_safe(opt_val, sizeof(opt_val), media_type);
    coap_add_option(
        response, 
        COAP_OPTION_CONTENT_FORMAT,
        opt_len,
        opt_val
    );

    // If maxage is set ...
    if (maxage >= 0) {

        // Add 'Maxage' option to the PDU
        unsigned char opt_val[4];
        size_t opt_len = coap_encode_var_safe(opt_val, sizeof(opt_val), maxage);
        coap_add_option(
            response,
            COAP_OPTION_MAXAGE,
            opt_len,
            opt_val
        );
    }

    // Send data divided into blocks ...
    if(block2_requested){

        // Compute Size2 option's size so that the coap_write_block_opt() function could
        // take it into account in the free-space-mesuting process
        size_t size_two_opt_len = 
            coap_encode_var_safe(opt_val, sizeof(opt_val), length);

        // Write 'Block2' option as the last one
        int res = 
            coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response, length + (size_two_opt_len + 1));

        /**
         * @note: At this place we know exactly how much will the Size2 option as
         *    the delta between Block2 and Size2 is known, and the Size2's length
         *    will be surely not higher than 12 (@v length is of size sizeof(size_t)).
         */

        switch (res) {
            case 0: // Illegal block                     
                response->code = COAP_RESPONSE_BAD_REQUEST;
                goto error;
            case -1: // Requested block cannot fit into PDU and cannot be reduced
                response->code = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
                goto error;
        }

        // Write 'Size2' option
        coap_add_option(
            response,
            COAP_OPTION_SIZE2,
            size_two_opt_len,
            opt_val
        );

        // Write data block into PDU
        coap_add_block(response, length, data, &block2);
    
    }
    // Otherwise, TRY to send data as a whole ...
    else if (!coap_add_data(response, length, data)) {

        // ... cannot send data as a whole ...

        // Write 'Size2' option
        size_t opt_len = coap_encode_var_safe(opt_val, sizeof(opt_val), length);
        coap_add_option(
            response,
            COAP_OPTION_SIZE2,
            opt_len,
            opt_val
        );

        // Write 'Block2' option
        block2.num = 0;
        block2.szx = COAP_MAX_BLOCK_SZX;
        coap_write_block_opt(&block2, COAP_OPTION_BLOCK2, response, length);

        // Write data block into PDU
        coap_add_block(response, length, data, &block2);
    }

    return;

error:
    // On error, set payload to the human-readable error code
    coap_add_data(
        response,
        strlen(coap_response_phrase(response->code)),
        (const unsigned char *)coap_response_phrase(response->code)
    );
}
