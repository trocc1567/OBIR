/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-22 23:46:52
 *  Description:
 * 
 *      Library-specific RNG API.
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
 * prng.h -- Pseudo Random Numbers
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file prng.h
 * @brief Pseudo Random Numbers
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_PRNG_H_
#define COAP_PRNG_H_

#include <stdlib.h>
#include "libcoap.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: Fills @p Buf with @p Length bytes of random data.
 *
 * @param Buf:
 *    buffer to be filled
 * @param Length:
 *    number of random bytes to generate
 */
#ifndef prng
#define prng(buf,length) coap_prng_impl((buf), (length))
#endif

/**
 * @brief: Called to set the PRNG seed. You may want to re-define this to allow for a
 * better PRNG.
 *
 * @param Value:
 *    value used to generate a seed
 */
#ifndef prng_init
#define prng_init(value) srand((unsigned long)(value))
#endif


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

 /**
 * @brief: Fills @p buf with @p len random bytes. This is the default implementation for
 *    prng(). You might want to change prng() to use a better PRNG on your specific platform.
 * 
 * @param buf:
 *    buffer to be filled
 * @param len:
 *    number of random bytes to generate
 */
COAP_STATIC_INLINE int
coap_prng_impl( unsigned char *buf, size_t len ) {
    while ( len-- ) *buf++ = rand() & 0xFF;
    return 1;
}

#endif /* COAP_PRNG_H_ */
