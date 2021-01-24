/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-20 13:46:22
 *  Description:
 * 
 *      Basic implementation of simple string hashes.
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
 * coap_hashkey.h -- definition of hash key type and helper functions
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_hashkey.h
 * @brief definition of hash key type and helper functions
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_HASHKEY_H_
#define COAP_HASHKEY_H_

#include "libcoap.h"
#include "uthash.h"
#include "str.h"


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: type used to hold libcoap-specific string hashes
 */
typedef unsigned char coap_key_t[4];


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

#ifndef coap_hash

/**
 * @brief: Calculates a fast hash over the given string @p s of length @p len and stores
 * the result into @p h. Depending on the exact implementation, this function
 * cannot be used as one-way function to check message integrity or simlar.
 *
 * @param s:
 *    the string used for hash calculation
 * @param len:
 *    the length of @p s
 * @param h:
 *    the result buffer to store the calculated hash key
 */
void coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h);


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: Calculates a fast hash over the given string @p String of length @p Length
 *    and stores the result into @p Result buffer. Depending on the exact implementation,
 *    this function cannot be used as one-way function to check message integrity or simlar.
 *
 * @param s:
 *    The NULL-terminated string used for hash calculation
 * @param len:
 *    The length of @p s
 * @param h:
 *    @t coap_key_t buffer to store the calculated hash key
 */
#define coap_hash(String, Length, Result) \
    coap_hash_impl((String),(Length),(Result))

/**
 * @brief: This is used to control the pre-set hash-keys for resources.
 */
#define COAP_DEFAULT_HASH

#else /* coap_hash */

#undef COAP_DEFAULT_HASH

#endif /* coap_hash */

/**
 * @brief: Calls coap_hash() with given @p Str structure of type @t coap_string_t 
 *    as parameter.
 *
 * @param Str:
 *    pointer to a @t coap_string_t structure
 * @param H:
 *    A @t coap_key_t structure to store the result
 *
 * @hideinitializer
 */
#define coap_str_hash(Str,H) {               \
        assert(Str);                             \
        memset((H), 0, sizeof(coap_key_t));      \
        coap_hash((Str)->s, (Str)->length, (H)); \
    }

#endif /* COAP_HASHKEY_H_ */
