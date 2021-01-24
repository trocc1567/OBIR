/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 04:39:29
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

/* pdu.c -- CoAP message structure
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


# include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "coap_session.h"
#include "coap_config.h"
#include "coap_debug.h"
#include "libcoap.h"
#include "option.h"
#include "encode.h"
#include "pdu.h"
#include "mem.h"

static int coap_pdu_check_resize(coap_pdu_t *pdu, size_t size);
static size_t coap_add_option_later_impl(coap_pdu_t *pdu, uint16_t type, size_t len, const uint8_t *data);
static size_t next_option_safe(coap_opt_t **optp, size_t *length);


/* -------------------------------------------- [Macrofeinitions] --------------------------------------------- */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif


/* -------------------------------------------- [Data structures] --------------------------------------------- */

#ifndef SHORT_ERROR_RESPONSE

/**
 * @brief: Helper structure used to hold readable descriptions of the responses
 */
typedef struct {
    unsigned char code;
    const char *phrase;
} response_desc_t;

/**
 * @note: If you change anything here, make sure, that the longest string does not
 *    exceed COAP_ERROR_PHRASE_LENGTH. 
 */
response_desc_t coap_error[] = {
    { COAP_RESPONSE_CODE(201), "Created" },
    { COAP_RESPONSE_CODE(202), "Deleted" },
    { COAP_RESPONSE_CODE(203), "Valid" },
    { COAP_RESPONSE_CODE(204), "Changed" },
    { COAP_RESPONSE_CODE(205), "Content" },
    { COAP_RESPONSE_CODE(231), "Continue" },
    { COAP_RESPONSE_CODE(400), "Bad Request" },
    { COAP_RESPONSE_CODE(401), "Unauthorized" },
    { COAP_RESPONSE_CODE(402), "Bad Option" },
    { COAP_RESPONSE_CODE(403), "Forbidden" },
    { COAP_RESPONSE_CODE(404), "Not Found" },
    { COAP_RESPONSE_CODE(405), "Method Not Allowed" },
    { COAP_RESPONSE_CODE(406), "Not Acceptable" },
    { COAP_RESPONSE_CODE(408), "Request Entity Incomplete" },
    { COAP_RESPONSE_CODE(412), "Precondition Failed" },
    { COAP_RESPONSE_CODE(413), "Request Entity Too Large" },
    { COAP_RESPONSE_CODE(415), "Unsupported Content-Format" },
    { COAP_RESPONSE_CODE(500), "Internal Server Error" },
    { COAP_RESPONSE_CODE(501), "Not Implemented" },
    { COAP_RESPONSE_CODE(502), "Bad Gateway" },
    { COAP_RESPONSE_CODE(503), "Service Unavailable" },
    { COAP_RESPONSE_CODE(504), "Gateway Timeout" },
    { COAP_RESPONSE_CODE(505), "Proxying Not Supported" },
    { 0, NULL }
};

#endif


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

int coap_pdu_clear(coap_pdu_t *pdu, size_t size) {
    assert(pdu);

    // If memory was allocated to the PDU, free it
    if(pdu->token != NULL)
        coap_free(pdu->token - COAP_HEADER_SIZE);

    // Clear the PDU
    memset(pdu, 0, sizeof(coap_pdu_t));

    // Allocate memory for the PDU
    uint8_t *buf = 
        (uint8_t*) coap_malloc(size + COAP_HEADER_SIZE);
    if(buf == NULL)
        return -1;

    // Set size of the allocated memory 
    pdu->alloc_size = size;

    // Set the token to point to a byte after the header
    pdu->token = buf + COAP_HEADER_SIZE;

    return 0;

}


coap_pdu_t *coap_pdu_init(
    uint8_t type, 
    uint8_t code, 
    uint16_t tid, 
    size_t size
){

    // Allocate memory for the new PDU
    coap_pdu_t *pdu = (coap_pdu_t *) coap_malloc(sizeof(coap_pdu_t));
    if (pdu == NULL) 
        return NULL;

    // Clear the allocated region
    memset(pdu, 0, sizeof(coap_pdu_t));

    // Clear the PDU (and allocate some memory for it)
    if(coap_pdu_clear(pdu, size) < 0){
        coap_free(pdu);
        return NULL;
    }

    // Set the max_size
    pdu->max_size = size;   

    // Set PDU's parameters
    pdu->tid = tid;
    pdu->type = type;
    pdu->code = code;

    return pdu;
}


coap_pdu_t *coap_new_pdu(const struct coap_session_t *session) {

    // Create the PDU
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, coap_session_max_pdu_size(session));
    
    #ifndef NDEBUG
    if (!pdu)
        coap_log(LOG_CRIT, "coap_new_pdu: cannot allocate memory for new PDU\n");
    #endif
    
    return pdu;
}


void coap_delete_pdu(coap_pdu_t *pdu) {

    if (pdu != NULL) {
        if (pdu->token != NULL)
            coap_free(pdu->token - COAP_HEADER_SIZE);
        coap_free(pdu);
    }
}


int coap_pdu_resize(coap_pdu_t *pdu, size_t new_size) {

    // Resize only when the requested size is bigger than the allocated one
    if (new_size > pdu->alloc_size) {

        // If PDU has a size limit and this limit is not exceeded by the new size, return error
        if (pdu->max_size && new_size > pdu->max_size) {
            coap_log(LOG_WARNING, "coap_pdu_resize: pdu too big\n");
            return 0;
        }

        // Calculate data offset from the token
        size_t data_offset;
        if (pdu->data != NULL) {
            assert(pdu->data > pdu->token);
            data_offset = pdu->data - pdu->token;
        } else
            data_offset = 0;

        // Reallocate the data
        uint8_t *new_hdr = 
            (uint8_t*) realloc(pdu->token - COAP_HEADER_SIZE, new_size + COAP_HEADER_SIZE);
        if (new_hdr == NULL) {
            coap_log(LOG_WARNING, "coap_pdu_resize: realloc failed\n");
            return 0;
        }

        // Set a new token pointer
        pdu->token = new_hdr + COAP_HEADER_SIZE;

        // Set a new data pointer
        if (data_offset > 0)
            pdu->data = pdu->token + data_offset;
        else
            pdu->data = NULL;

    }

    // Change allocated size state
    pdu->alloc_size = new_size;

    return 1;
}


int coap_add_token(
    coap_pdu_t *pdu, 
    size_t len, 
    const uint8_t *data
){
    if (!pdu || len > 8)
        return 0;

    // If data is aldready stored in the PDU, return error
    if (pdu->used_size) {
        coap_log(LOG_WARNING, "coap_add_token: The token must defined first. Token ignored\n");
        return 0;
    }

    // Check if pdu can store the token and resize if required
    if (!coap_pdu_check_resize(pdu, len))
        return 0;

    // Update token
    pdu->token_length = (uint8_t)len;
    pdu->used_size = len;
    if(len)
        memcpy(pdu->token, data, len);

    // Reset delta option's delta counter
    pdu->max_delta = 0;

    // Reset data pointer
    pdu->data = NULL;

    return 1;
}


size_t coap_add_option(coap_pdu_t *pdu, uint16_t type, size_t len, const uint8_t *data) {
    
    // Encode the option
    size_t optsize = 
        coap_add_option_later_impl(pdu, type, len, data);

    if(optsize == 0)
        return 0;

    return optsize;
}


uint8_t* coap_add_option_later(coap_pdu_t *pdu, uint16_t type, size_t len) {
    
    // Encode the option's header
    size_t optsize = 
        coap_add_option_later_impl(pdu, type, len, NULL);

    if(optsize == 0)
        return NULL;

    // Inside the *_impl function @p pdu->used_size is updated. Therefore
    // @p pdu->token + @p pdu->used_size points to the next byt after the
    // encoded option. We need to substract @p len to get address that the
    // option's value should be written to
    return  pdu->token + pdu->used_size - len;    
}


int coap_add_data(coap_pdu_t *pdu, size_t len, const uint8_t *data) {

    if (len == 0)
        return 1;
    else {
        
        // Check if data fit the pdu and set paylod pointer
        uint8_t *payload = coap_add_data_after(pdu, len);

        // If data fit pdu, copy it into payload
        if (payload != NULL)
            memcpy(payload, data, len);
            
        return payload != NULL;
    }
}


uint8_t *coap_add_data_after(coap_pdu_t *pdu, size_t len) {

    assert(pdu);
    assert(pdu->data == NULL);

    if (len == 0)
        return NULL;

    // Try to resize data to fit payload (and the payload marker)
    if (!coap_pdu_resize(pdu, pdu->used_size + len + 1))
        return 0;

    // Set the payload marker
    pdu->token[pdu->used_size++] = COAP_PAYLOAD_START;

    // Set the payload pointer
    pdu->data = pdu->token + pdu->used_size;

    // Update size-info
    pdu->used_size += len;

    return pdu->data;
}


int coap_get_data(const coap_pdu_t *pdu, size_t *len, uint8_t **data) {
  
    assert(pdu);
    assert(len);
    assert(data);

    // Set @p data to the payload region
    *data = pdu->data;

    // If no payload was pointer
    if(pdu->data == NULL) {
        *len = 0;
        return 0;
    }

    // Compute actual length of the payload
    *len = pdu->used_size - (pdu->data - pdu->token);

    return 1;
}


#ifndef SHORT_ERROR_RESPONSE

const char *coap_response_phrase(unsigned char code) {

    // Search for the response's description in the table
    for (int i = 0; coap_error[i].code; ++i) {
        if (coap_error[i].code == code)
            return coap_error[i].phrase;
    }

    return NULL;
}

#endif


int coap_pdu_parse_header(coap_pdu_t *pdu) {

    // Get pointer to the header
    uint8_t *hdr = pdu->token - COAP_HEADER_SIZE;
    
    // Check header's version
    if ((hdr[0] >> 6) != COAP_DEFAULT_VERSION) {
        coap_log(LOG_DEBUG, "coap_pdu_parse: UDP version not supported\n");
        return 0;
    }

    // Get type of the pdu (NON, CON, ACK, RST)
    pdu->type = (hdr[0] >> 4) & 0x03;

    // Get token's length
    pdu->token_length = hdr[0] & 0x0f;

    // Get request method / response code
    pdu->code = hdr[1];

    // Get message ID
    pdu->tid = (uint16_t)hdr[2] << 8 | hdr[3];

    // Check if token's length fit into the pdu's allocated region
    if (pdu->token_length > pdu->alloc_size) {
        coap_log(LOG_DEBUG, "coap_pdu_parse: PDU header token size broken\n");
        pdu->token_length = (uint8_t) pdu->alloc_size;
        return 0;
    }

    return 1;
}


int coap_pdu_parse_opt(coap_pdu_t *pdu) {

    // Validate the message (check if empty message is in fact empty)
    if (pdu->code == 0) {
        if (pdu->used_size != 0 || pdu->token_length) {
            coap_log(LOG_DEBUG, "coap_pdu_parse: empty message is not empty\n");
            return 0;
        }
    }

    // Validate token'n length
    if (pdu->token_length > pdu->used_size || pdu->token_length > 8) {
        coap_log(LOG_DEBUG, "coap_pdu_parse: invalid Token\n");
        return 0;
    }

    // If empty message, reset the payload pointer
    if (pdu->code == 0)
        pdu->data = NULL;
    // Otherwise, ...
    else {
        
        // Get option's pointer
        coap_opt_t *opt = pdu->token + pdu->token_length;

        // Get size of memory used by options, payload marker and payload itself
        size_t length = pdu->used_size - pdu->token_length;

        // Iterate over options to check if payload marker is present
        while (length > 0 && *opt != COAP_PAYLOAD_START) {
            if ( !next_option_safe( &opt, (size_t *)&length ) ) {
                coap_log(LOG_DEBUG, "coap_pdu_parse: missing payload start code\n");
                return 0;
            }
        }

        // Reset payload pointer in case it turns out that there is no payload
        pdu->data = NULL;

        // If options' iteration stopped before the pdu's end
        if (length > 0) {

            // It means that the payload marker MUST have been met
            assert(*opt == COAP_PAYLOAD_START);

            // Forward 'opt' to the next byte after the marker
            opt++;

            // Check if there is payload after the marker
            if (--length == 0) {
                coap_log(LOG_DEBUG,
                        "coap_pdu_parse: message ending in payload start marker\n");
                return 0;
            }
        }

        if (length > 0)
            pdu->data = (uint8_t*)opt;
    }

    return 1;
}


int coap_pdu_parse(
    const uint8_t *data,
    size_t length,
    coap_pdu_t *pdu
){
    // Check if data is readable
    if (length == 0)
        return 0;

    // Check data is long enogh to hold at least the header
    if (COAP_HEADER_SIZE > length)
        return 0;

    // Resize the PDU to fit the data
    if (!coap_pdu_resize(pdu, length - COAP_HEADER_SIZE))
        return 0;

    // Copy data to the PDU's buffer
    memcpy(pdu->token - COAP_HEADER_SIZE, data, length);
    pdu->used_size = length - COAP_HEADER_SIZE;

    // perform consistency check of the PDU
    return coap_pdu_parse_header(pdu) && coap_pdu_parse_opt(pdu);
}


void coap_pdu_encode_header(coap_pdu_t *pdu) {
    
    uint8_t* header = pdu->token - COAP_HEADER_SIZE;

    // Encode the first byte (protocol version, message type, token length)
    header[0] = COAP_DEFAULT_VERSION << 6 | pdu->type << 4 | pdu->token_length;
    // Encode the second byte (request method / response code)
    header[1] = pdu->code;
    // Encode the third and the fourth bytes (message ID)
    header[2] = (uint8_t)(pdu->tid >> 8);
    header[3] = (uint8_t)(pdu->tid);
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */

/**
 * @brief: Checks if @p bytes of data can be fitted into the @p pdu.
 *   If not, functions tries to expand the actual allocated region
 *   by factor 2^x. If it can be done so that @a max_size is not violated
 *   and @p size bytes can fit, the pdu is resized.
 * 
 * @param pdu:
 *    PDU to check 
 * @param size:
 *     desired size
 * @return
 *    1 on success
 *    0 on error
 */
static int coap_pdu_check_resize(coap_pdu_t *pdu, size_t size) {

    // If data of size @p size cannot be fitted ...
    if (size > pdu->alloc_size) {

        // Find minimal suitable size for data
        size_t new_size = max(256, pdu->alloc_size * 2);
        while (size > new_size)
            new_size *= 2;
        
        // Check if a new size doesn't violate a @a max_size
        if (pdu->max_size && new_size > pdu->max_size) {
            // If so, try to shrink size to @a max_size
            new_size = pdu->max_size;
            if (new_size < size)
                return 0;
        }

        // If a suitable size was found, resize the PDU
        if (!coap_pdu_resize(pdu, new_size))
            return 0;
    }
    
    return 1;
}

/**
 * @brief: implementation of the @f coap_add_option_later. The code is reused by the
 *    @f coap_add_option.
 * 
 * @param pdu:
 *    PDU to write option to
 * @param type:
 *    option's type
 * @param len:
 *    length of the option's value
 * @param data:
 *    option's value to be copied int option field
 * @returns:
 *     size of the encoded option on success
 *     0 on error
 */
static size_t coap_add_option_later_impl(
    coap_pdu_t *pdu, 
    uint16_t type, 
    size_t len, 
    const uint8_t *data
){

    assert(pdu);

    // Reset data pointer when an option is added
    pdu->data = NULL;

    // As options are delta-coded, an option with the code lower than the code of 
    // the last option cannot be added
    if (type < pdu->max_delta) {
        coap_log(LOG_WARNING,
                "coap_add_option: options are not in correct order (%u)\n", type);
        return 0;
    }

    // Check if PDU has enough free space for the option and realloc if needed
    if (!coap_pdu_check_resize(pdu, pdu->used_size + coap_opt_encode_size(type - pdu->max_delta, len)))
        return 0;

    // Initialize pointer to the new option
    coap_opt_t *opt = pdu->token + pdu->used_size;

    // Encode option and check length
    size_t optsize = coap_opt_encode(
        opt, pdu->alloc_size - pdu->used_size,
        type - pdu->max_delta, len, data
    );

    // If an option could not be encoded, return error
    if (optsize == 0) {
        coap_log(LOG_WARNING, "coap_add_option: cannot add option\n");
        return 0;
    } 

    // Otherwise, update @ max_delta and @ a used_size
    pdu->max_delta = type;
    pdu->used_size += (uint16_t) optsize;

    return optsize;
}


/**
 * @brief: Advances @p *optp to next option if still in PDU. 
 * 
 * @param optopt [in/out]:
 *    pointer to the option to be parsed
 * @param length:
 *    max option's length
 * @returns:
 *     the number of bytes @p *optopt has been advanced 
 *     @c 0 on error
 */
static size_t next_option_safe(coap_opt_t **optp, size_t *length) {

    assert(optp); assert(*optp);
    assert(length);

    // Parse the option into a @t coap_option_t structure
    coap_option_t option;
    size_t optsize = coap_opt_parse(*optp, *length, &option);

    if(optsize == 0)
        return 0;

    // Advance pointers to the new values
    *optp += optsize;
    *length -= optsize;

    return optsize;
}