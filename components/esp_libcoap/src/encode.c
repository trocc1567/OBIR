/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-24 15:20:02
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

/* encode.c -- encoding and decoding of CoAP data types
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#ifndef NDEBUG
#include <stdio.h>
#endif

#include "coap_config.h"
#include "coap.h"
#include "mem.h"
#include "encode.h"


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

int coap_fls(unsigned int i) {
    return coap_flsll(i);
}

int coap_flsll(long long i){
    int n;
    for (n = 0; i; n++)
        i >>= 1;
    return n;
}

unsigned int coap_decode_var_bytes(const uint8_t *buf,unsigned int len) {
    unsigned int n = 0;
    for (unsigned int i = 0; i < len; ++i)
            n = (n << 8) + buf[i];
    return n;
}

unsigned int coap_encode_var_safe(uint8_t *buf, size_t length, unsigned int val) {
    
    unsigned int n = 0;

    // Check how many bytes will be required to encode the value
    for (unsigned int i = val; i && n < sizeof(val); ++n)
        i >>= 8;
    if (n > length){
        assert(n<=length);
        return 0;
    }

    // Encode the value
    for(unsigned int i = n; i-- > 0;){
        buf[i] = val & 0xff;
        val >>= 8;
    }

    return n;
}