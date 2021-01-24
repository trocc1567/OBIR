/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 01:39:58
 *  Description:
 * 
 *      Constarined-devices, libcoap-specific memory allocation API.
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
 * mem.h -- CoAP memory handling
 *
 * Copyright (C) 2010-2011,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_MEM_H_
#define COAP_MEM_H_

#include <stdlib.h>
#include <libcoap.h>


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: libcoap wrapper around malloc
 */
COAP_STATIC_INLINE void*
coap_malloc(size_t size) {
    return malloc(size);
}

/**
 * @brief: libcoap wrapper around free
 */
COAP_STATIC_INLINE void 
coap_free(void *object) {
    free(object);
}

#endif /* COAP_MEM_H_ */
