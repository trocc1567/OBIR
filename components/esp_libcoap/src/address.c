/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-23 17:32:56
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

/* address.c -- representation of network addresses
 *
 * Copyright (C) 2015-2016,2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "address.h"
#include "coap_config.h"


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

int coap_address_equals(const coap_address_t *a, const coap_address_t *b){

    // Don't pass NULL pointers 
    assert(a); assert(b);

    // Compare sizes and families
    if (a->size != b->size || a->addr.sa.sa_family != b->addr.sa.sa_family)
        return 0;

    // Depending on the IP version compare address and port number
    switch (a->addr.sa.sa_family){
        case AF_INET:
            return a->addr.sin.sin_port == b->addr.sin.sin_port &&
                  (memcmp(&a->addr.sin.sin_addr, &b->addr.sin.sin_addr, sizeof(struct in_addr)) == 0 );
        case AF_INET6:
            return a->addr.sin6.sin6_port == b->addr.sin6.sin6_port &&
                  (memcmp(&a->addr.sin6.sin6_addr, &b->addr.sin6.sin6_addr, sizeof(struct in6_addr)) == 0);
    }

    return 0;
}


int coap_is_mcast(const coap_address_t *address) {
  
    // Treate NULL pointer as no-mcast 
    if(! address)
        return 0;

    // Check address group
    switch (address->addr.sa.sa_family) {
        case AF_INET:
            return IN_MULTICAST(ntohl(address->addr.sin.sin_addr.s_addr));
        case  AF_INET6:
            return IN6_IS_ADDR_MULTICAST(&address->addr.sin6.sin6_addr);
    }

    return 0;
}
