/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-26 00:30:25
 *  Description:
 * 
 *      File contains libcoap-specific binary & string data manipulation API.
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
 * str.h -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_STR_H_
#define COAP_STR_H_

#include <string.h>

typedef struct coap_str_const_t coap_str_const_t;


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: Fills @t coap_string_t structure with given data
 * 
 * @param str:
 *    @t coap_string_t structure
 * @param l:
 *    length of the data
 * @param v:
 *    data buffer
 */
#define COAP_SET_STR(str,l,v) { (str)->length = (l), (str)->s = (v); }

/**
 * @brief: Take the specified byte array (text) and create a @t coap_str_const_t *
 *
 * @param string:
 *    the const byte array to convert to a coap_str_const_t *
 * 
 * @note: The byte array must be in the local scope and not a parameter in the function
 *    call as sizeof() will return the size of the pointer, not the size of the byte array,
 *    leading to unxepected results.
 */
#define coap_make_str_const(string) \
  ( &(coap_str_const_t){ sizeof(string)-1, (const uint8_t *)(string) } )

/**
 * @brief: Compares the two strings for equality
 *
 * @param string1:
 *    the first string.
 * @param string2:
 *    the second string.
 * @returns:
 *    1 if the strings are equal
 *    0 otherwise
 */
#define coap_string_equal(string1,string2) \
        ((string1)->length == (string2)->length && ((string1)->length == 0 || \
         memcmp((string1)->s, (string2)->s, (string1)->length) == 0))


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @biref: libcoap-specific string data definition
 */
typedef struct coap_string_t {
  size_t length;    /**< length of string */
  uint8_t *s;       /**< string data */
} coap_string_t;

/**
 * @biref: libcoap-specific string data definition with const data
 */
struct coap_str_const_t {
  size_t length;    // length of string
  const uint8_t *s; // string data
};



/**
 * @biref: libcoap-specific binary data structure
 */
typedef struct coap_binary_t {
  size_t length; // Length of the binary data
  uint8_t *s;    // data buffer
} coap_binary_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Returns a new string object with at least size + 1 bytes storage allocated.
 *    The string must be released using coap_delete_string().
 *
 * @param size:
 *    the size to allocate for the binary string data.
 * @returns:
 *    a pointer to the new object or @c NULL on error.
 */
coap_string_t *coap_new_string(size_t size);

/**
 * @biref: Deletes the given string and releases any memory allocated.
 *
 * @param string:
 *    the string to free off.
 */
void coap_delete_string(coap_string_t *string);

/**
 * @brief: Returns a new const string object with at least size+1 bytes storage allocated, 
 *    and the provided data copied into the string object. The string must be released using
 *    coap_delete_str_const().
 *
 * @param data:
 *    the data to put in the new string object
 * @param size:
 *    the size to allocate for the binary string data
 * @returns:
 *    a pointer to the new object or @c NULL on error.
 */
coap_str_const_t *coap_new_str_const(const uint8_t *data, size_t size);

/**
 * @brief: Deletes the given const string and releases any memory allocated.
 *
 * @param string:
 *    the string to free off
 */
void coap_delete_str_const(coap_str_const_t *string);


#endif /* COAP_STR_H_ */
