/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-21 16:33:16
 *  Description:
 * 
 *      Basic encoding for unsigned integer values.
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
 * encode.h -- encoding and decoding of CoAP data types
 *
 * Copyright (C) 2010-2012 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_ENCODE_H_
#define COAP_ENCODE_H_

#include <strings.h>
#include <stdint.h>
#include <libcoap.h>


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Equivalent of BSD fls.
 * 
 * @returns:
 *    index of the first LSB set.
 */
extern int coap_fls(unsigned int i);

/**
 * @brief: Equivalent of BSD flsll.
 * 
 * @returns:
 *    index of the first LSB set.
 */
extern int coap_flsll(long long i);

/**
 * @brief: Decodes multiple-length byte sequences into unsigned integer
 *
 * @param buf:
 *    the input byte sequence to decode from
 * @param length:
 *    the length of the input byte sequence
 * @returns:
 *    the decoded value
 */
unsigned int coap_decode_var_bytes(const uint8_t *buf, unsigned int length);

/**
 * @brief: Encodes unsigned integer value into multiple-length byte sequence. @p buf points
 *    to an output buffer of sufficient length to store the encoded bytes.
 *
 * @param buf:
 *    the output buffer to decode into
 * @param length:
 *    length of the output buffer size to encode into; must be sufficient (max. sizeof(unsigned int))
 * @param value:
 *    the value to encode into the buffer
 *
 * @returns:
 *    the number of bytes used to encode @p value on success
 *    0 on error
 */
unsigned int coap_encode_var_safe(
    uint8_t *buf,
    size_t length,
    unsigned int value
);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * 
 * @brief: Provided for backward compatibility. As @p value has a maximum value of 0xffffffff,
 *    and @p buf is usually defined as an array, it is unsafe to continue to use this variant
 *    if @p buf's length is less than 4.
 *
 * 
 * @deprecated Use coap_encode_var_safe() instead.
 * 
 * @param buf:
 *    the output buffer to decode into
 * @param value:
 *    the value to encode into the buffer
 * @returns:
 *    the number of bytes used to encode @p value or 0 on error
 */
COAP_STATIC_INLINE COAP_DEPRECATED int
coap_encode_var_bytes(uint8_t *buf, unsigned int value){
    return (int) coap_encode_var_safe(buf, sizeof(value), value);
}

#endif /* COAP_ENCODE_H_ */
