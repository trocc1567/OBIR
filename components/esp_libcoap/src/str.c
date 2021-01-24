/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-24 15:35:59
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

/* str.c -- strings to be used in the CoAP library
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include <stdio.h>
#include "libcoap.h"
#include "coap_config.h"
#include "coap_debug.h"
#include "mem.h"
#include "str.h"


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

coap_string_t *coap_new_string(size_t size) {

    // Alloc mememory for a new string structure and the string itself
    coap_string_t *s = (coap_string_t *)coap_malloc(sizeof(coap_string_t) + size + 1);
    if ( !s ) {
      #ifndef NDEBUG
          coap_log(LOG_CRIT, "coap_new_string: malloc\n");
      #endif
      return NULL;
    }

    // Initialize string structure and a string itself as an empty one
    memset(s, 0, sizeof(coap_string_t));
    s->s = ((unsigned char *)s) + sizeof(coap_string_t);
    s->s[size] = '\000';
    
    return s;
}


void coap_delete_string(coap_string_t *s) {
    coap_free(s);
}


coap_str_const_t *coap_new_str_const(const uint8_t *data, size_t size) {

    // Create a new string of the given size
    coap_string_t *s = coap_new_string(size);
    if (!s)
        return NULL;

    // Initialize the string
    memcpy (s->s, data, size);
    s->length = size;

    return (coap_str_const_t *) s;
}


void coap_delete_str_const(coap_str_const_t *s) {
    coap_free(s);
}

