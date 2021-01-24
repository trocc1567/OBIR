/* ============================================================================================================
 *  File: address.h
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-20 10:19:02
 *  Description:
 * 
 *      File contains abstraction layer constituting IP adresses API used by the library.
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
 * address.h -- representation of network addresses
 *
 * Copyright (C) 2010-2011,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file address.h
 * @brief Representation of network addresses
 */

/* ------------------------------------------------------------------------------------------------------------ */

#ifndef COAP_ADDRESS_H_
#define COAP_ADDRESS_H_

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include "libcoap.h"

/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Multi-purpose, CoAP-specific IP address abstraction
 */
typedef struct coap_address_t {

  // Size of the addr field
  socklen_t size;          

  /**
   * @brief: Structure describing applicable IP address 
   * @note: ESP8266-SDK (ver.3.0+ "IDF-style") partially supports POSIX (BSD) sockets API
   */
  union {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
  } addr;
  
} coap_address_t;

/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Compares given address objects @p a and @p b
 * 
 * @param a:
 *    first address to compare
 * @param b:
 *    second address to compare
 * @returns:
 *    1 if addresses are equal, 0 otherwise
 * 
 * @note: parameters cannot be NULL
 */
int coap_address_equals(const coap_address_t *a, const coap_address_t *b);

/**
 * @brief: Checks if given address @p a denotes a multicast address. This function
 * @returns:
 *    1 if @p a is multicast, @c 0 otherwise.
 */
int coap_is_mcast(const coap_address_t *a);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Implementation of the 
 * 
 * @param a: 
 *    address to check
 * @returns: 
 *    0 if @p a is not equal to INADDR_ANY, value different from 0 otherwise
 */
COAP_STATIC_INLINE int
_coap_address_isany_impl(const coap_address_t *a) {

    switch (a->addr.sa.sa_family) {
        case AF_INET:
            return (a->addr.sin.sin_addr.s_addr == INADDR_ANY);
        case AF_INET6:
            return ( memcmp(
                &in6addr_any,
                &a->addr.sin6.sin6_addr,
                sizeof(in6addr_any)
            ) == 0 );
    }

    return 0;
}

/**
 * @brief: Resets the given coap_address_t stucture @p addr to its default values. 
 *
 * @param addr: 
 *    the coap_address_t object to initialize.
 * 
 * @note: parameter cannot be NULL
 */
COAP_STATIC_INLINE void
coap_address_init(coap_address_t *addr) {
    assert(addr);
    memset(addr, 0, sizeof(coap_address_t));
    addr->size = sizeof(addr->addr);
}

/**
 * @brief: Coppies address info from @p src structure to the @p dst structure
 * 
 * @param dst:
 *    destination structure
 * @param src: 
 *    source structure
 */
COAP_STATIC_INLINE void
coap_address_copy( coap_address_t *dst, const coap_address_t *src ) {

    // Clean destination structure
    memset( dst, 0, sizeof( coap_address_t ) );
    // Copy adress's size
    dst->size = src->size;

    // Depending on the address's family copy appropriate fields
    if ( src->addr.sa.sa_family == AF_INET6 ) {
      dst->addr.sin6.sin6_family   = src->addr.sin6.sin6_family;
      dst->addr.sin6.sin6_addr     = src->addr.sin6.sin6_addr;
      dst->addr.sin6.sin6_port     = src->addr.sin6.sin6_port;
      dst->addr.sin6.sin6_scope_id = src->addr.sin6.sin6_scope_id;
    } 
    else if( src->addr.sa.sa_family == AF_INET ) {
      dst->addr.sin = src->addr.sin;
    } 
    else {
      memcpy( &dst->addr, &src->addr, src->size );
    }
  
}

/**
 * @brief: Checks if given address object @p a denotes the wildcard address.
 * 
 * @returns: 
 *    1 if this is the case, 0 otherwise
 * 
 * @note: parameter cannot be NULL;
 */
COAP_STATIC_INLINE int
coap_address_isany(const coap_address_t *a) {
  assert(a);
  return _coap_address_isany_impl(a);
}


#endif /* COAP_ADDRESS_H_ */
