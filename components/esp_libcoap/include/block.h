/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-30 21:26:20
 *  Description:
 * 
 *      File contains API of the block-wise CoAP transfers described in [RFC7959] document.
 *      
 *  Credits: 
 *
 *      This file is a modification of the original libcoap source file. Aim of the modification was to 
 *      provide cleaner, richer documented and ESP8266-optimised version of the library. Core API of the 
 *      project was not changed or expanded, although some elemenets (e.g. DTLS support) have been removed 
 *      due to lack of needings from the modifications' authors. 
 * 
 * ============================================================================================================ */

/* -------------------------------------------- [Original header] --------------------------------------------- */

/*
 * block.h -- block transfer
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_BLOCK_H_
#define COAP_BLOCK_H_

#include "encode.h"
#include "option.h"
#include "pdu.h"

struct coap_resource_t;
struct coap_session_t;


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: The largest value for the SZX component in a Block option.
 */
#ifndef COAP_MAX_BLOCK_SZX
#define COAP_MAX_BLOCK_SZX 6
#endif

/**
 * @returns: 
 *    the value of the least significant byte of a Block option @p opt.
 * 
 * @note: for zero-length options (i.e. num == m == szx == 0), COAP_OPT_BLOCK_LAST_BYTE
 *    returns NULL.
 */
#define COAP_OPT_BLOCK_LAST_BYTE(opt) \
  (coap_opt_length(opt) ? (coap_opt_value(opt) + (coap_opt_length(opt)-1)) : 0)

/** 
 * @returns:
 *    the value of the More-bit field of a Block option @p opt. 
 */
#define COAP_OPT_BLOCK_MORE(opt) \
  (coap_opt_length(opt) ? (*COAP_OPT_BLOCK_LAST_BYTE(opt) & 0x08) : 0)

/**
 * @returns:
 *    the value of the SZX field of a Block option @p opt.
 */
#define COAP_OPT_BLOCK_SZX(opt)  \
  (coap_opt_length(opt) ? (*COAP_OPT_BLOCK_LAST_BYTE(opt) & 0x07) : 0)


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Structure of Block options.
 */
typedef struct {

    // Index of the block in the sequence
    unsigned int num;
    // Bit flag: 1 if more blocks follow current block, 0 otherwise
    unsigned int m:1;
    // Encoded size of the block (size = 1 << (SZX + 4))
    unsigned int szx:3;
    
} coap_block_t;

/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @returns:
 *    the value of num field in the given block option @p block_opt.
 */
unsigned int coap_opt_block_num(const coap_opt_t *block_opt);

/**
 * @brief: initializes @p block structure from @p pdu structure.
 *
 * @param pdu:
 *    the pdu to search for option @p type.
 * @param type:
 *    the option to search for. Must be either COAP_OPTION_BLOCK1 or COAP_OPTION_BLOCK2.
 *    When option @p type was not found in @p pdu, @p block is initialized with values 
 *    from this option.
 * @param block [out]:
 *    The block structure to initilize.
 * @return:
 *    1 on success, 0 otherwise.
 */
int coap_get_block(coap_pdu_t *pdu, uint16_t type, coap_block_t *block);

/**
 * @brief: Writes a block option of type @p type to message @p pdu basing on @p block
 *    structure. If the requested block size is too large to fit in @p pdu, it is reduced
 *    accordingly. An exception  is made for the final block when less space is required. 
 * 
 *    The actual length of the resource is specified in @p data_length (i.e. length of the
 *    whole data that has to be sent with sequence of block transfers)
 *
 * @param block [in/out]:
 *    The block structure to use. On return, this object is updated according to the values
 *    that have been written to @p pdu.
 * @param type:
 *    COAP_OPTION_BLOCK1 or COAP_OPTION_BLOCK2.
 * @param pdu:
 *    The message where the block option should be written.
 * @param data_length:
 *    The length of the actual data that will be added the @p pdu by calling coap_add_block().
 * @returns:
 *    1 on success
 *    0 when requested block is out of data range
 *   -1 when requested block is to big to fit into pdu and it cannot be reduced
 * 
 * @note: This function may change @p block to reflect the values written to @p pdu. As the 
 *    function takes into consideration the remaining space in the @p pdu, no more options
 *    should be added after coap_write_block_opt() has returned.
 */
int coap_write_block_opt(
    coap_block_t *block,
    uint16_t type,
    coap_pdu_t *pdu,
    size_t data_length
);

/**
 * @brief: Adds the block with num-field @p block_num of size 1 << (@p block_szx + 4) from source
 *    @p data to @p pdu.
 *
 * @param pdu:
 *    the message to add the block.
 * @param len:
 *    the length of @p data.
 * @param data:
 *    the source data to fill the block with.
 * @param block:
 *    block description
 * @returns:
 *    1 on success, 0 otherwise.
 */
int coap_add_block(
    coap_pdu_t *pdu,
    unsigned int len,
    const uint8_t *data,
    coap_block_t *block
);

/**
 * @brief: Adds the data of size @p length to @p data or (if block transfer is required)
 *    it's appropriate to the @p response pdu. Adds a ETAG option that is the hash of the
 *    entire data if the data is to be split into blocks.
 * 
 *    Usually used by the default GET request handler.
 *
 * @param resource:
 *    the resource the data is associated with.
 * @param session:
 *    the coap session.
 * @param request:
 *    the requesting pdu.
 * @param response:
 *    the response pdu.
 * @param token:
 *    the token taken from the (original) requesting pdu.
 * @param media_type:
 *    the format of the data.
 * @param maxage:
 *    the maxmimum life of the data. If 1, then there is no maxage.
 * @param length:
 *    the total length of the data.
 * @param data:
 *    the entire data block to transmit.
 *
 */
void
coap_add_data_blocked_response(
    struct coap_resource_t *resource,
    struct coap_session_t *session,
    coap_pdu_t *request,
    coap_pdu_t *response,
    const coap_binary_t *token,
    uint16_t media_type,
    int maxage,
    size_t length,
    const uint8_t* data
);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Checks if more than @p num blocks are required to deliver @p data_len
 *    bytes of data for a block size of 1 << (@p szx + 4).
 * 
 * @param data_len:
 *     length of data to send
 * @param num:
 *     desired number of blocks to transfer
 * @param szx:
 *     encoded size of blocks (size = (1 << (4 + szx)))
 * @returns:
 *    0 if more blocks are needed, value different from 0 otherwise 
 */
COAP_STATIC_INLINE int
coap_more_blocks(size_t data_len, unsigned int num, uint16_t szx) {
    return ((num+1) << (szx + 4)) < data_len;
}

#endif /* COAP_BLOCK_H_ */
