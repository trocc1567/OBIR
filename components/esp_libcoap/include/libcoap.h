/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-20 16:33:34
 *  Description:
 * 
 *      Initialization & deinitialization code of the library.
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
 * libcoap.h -- platform specific header file for CoAP stack
 *
 * Copyright (C) 2015 Carsten Schoenert <c.schoenert@t-online.de>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_LIBCOAP_H_
#define COAP_LIBCOAP_H_

#include <netinet/in.h>
#include <sys/socket.h>


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

#ifndef COAP_STATIC_INLINE
#define COAP_STATIC_INLINE static inline
#endif

#ifndef COAP_DEPRECATED
#define COAP_DEPRECATED __attribute__ ((deprecated))
#endif


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Initializes libcoap
 */
void coap_startup(void);

/**
 * @brief: Frees resources acquired by the libcoap
 */
void coap_cleanup(void);

#endif /* COAP_LIBCOAP_H_ */
