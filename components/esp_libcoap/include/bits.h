/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-19 19:00:54
 *  Description:
 * 
 *      File contains API for basic operations performed on multi-bytes bit masks (i.e. bit-vectors)
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
 * bits.h -- bit vector manipulation
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file bits.h
 * @brief Bit vector manipulation
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_BITS_H_
#define COAP_BITS_H_

#include <stdint.h>


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */


/**
 * @brief: Sets the bit @p bit in the bit-vector @p vec of size @p size * sizeof(uint8_t).
 *
 * @param vec:
 *    The bit-vector to change.
 * @param size:
 *    The size of @p vec in bytes.
 * @param bit:
 *    The bit to set in @p vec.
 * @returns:
 *    1 if bit was set in the vector or -1 on error (i.e. when the given bit does not fit
 *    in the * vector).
 * 
 * @note: term 'vector' is just a fancy description of the set of contiguous uint8_t fields
 *    treated as a set of bit flags
 */
COAP_STATIC_INLINE int
bits_setb(uint8_t *vec, size_t size, uint8_t bit) {

	// Check if bit fits into the vector
    if( size <= ((size_t) bit >> 3) )
      return -1;

	// If so, set desired bit
    *(vec + (bit >> 3)) |= (uint8_t)(1 << (bit & 0x07));
    return 1;
}

/**
 * @brief: Clears the bit @p bit from bit-vector @p vec of size @p size * sizeof(uint8_t).
 *
 * @param vec:
 *    The bit-vector to change.
 * @param size:
 *    The size of @p vec in bytes.
 * @param bit:
 *    The bit to clear from @p vec.
 * @returns:
 *    1 if bit was cleared or -1 on error (i.e. when the given bit does not fit in
 *    the vector).
 * 
 * @note: term 'vector' is just a fancy description of the set of contiguous uint8_t fields
 *    treated as a set of bit flags
 */
COAP_STATIC_INLINE int
bits_clrb(uint8_t *vec, size_t size, uint8_t bit) {

	// Check if bit fits into the vector
  	if (size <= ((size_t)bit >> 3))
  	  return -1;

	// If so, clear desired bit
  	*(vec + (bit >> 3)) &= (uint8_t)(~(1 << (bit & 0x07)));
  	return 1;
}

/**
 * @brief: Gets the status of bit @p bit from bit-vector @p vec of size @p size * sizeof(uint8_t).
 *
 * @param vec:
 *    The bit-vector to read from.
 * @param size:
 *    The size of @p vec in bytes.
 * @param bit:
 *    The bit to get from @p vec.
 * @returns:
 *    1 if the bit is set, @c 0 otherwise (even in case of an error).
 * 
 * @note: term 'vector' is just a fancy description of the set of contiguous uint8_t fields
 *    treated as a set of bit flags
 */
COAP_STATIC_INLINE int
bits_getb(const uint8_t *vec, size_t size, uint8_t bit) {

	// Check if bit fits into the vector
  	if (size <= ((size_t)bit >> 3))
  	  return -1;

	// If so, return desired bit
  	return (*(vec + (bit >> 3)) & (1 << (bit & 0x07))) != 0;
}

#endif /* COAP_BITS_H_ */
