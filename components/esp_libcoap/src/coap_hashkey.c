/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-24 12:50:05
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

/* coap_hashkey.c -- definition of hash key type and helper functions
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include "coap_hashkey.h"


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

void
coap_hash_impl(const unsigned char *s, unsigned int len, coap_key_t h){

    for(int i = 0; i < len; ++i){
        for(size_t j = sizeof(coap_key_t) - 1; j > 0; --j)
            h[j] = ((h[j] << 7) | (h[j-1] >> 1)) + h[j];

        h[0] = (h[0] << 7) + h[0] + *s++;
    }
}

