/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-24 15:50:37
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

/* subscribe.c -- subscription handling for CoAP
 *                see draft-ietf-coap-observe-16
 *
 * Copyright (C) 2010--2013,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include <assert.h>
#include "coap_config.h"
#include "subscribe.h"


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

void coap_subscription_init(coap_subscription_t *s){
    assert(s);
    memset(s, 0, sizeof(coap_subscription_t));
}
