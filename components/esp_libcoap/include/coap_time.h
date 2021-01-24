/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-20 15:23:10
 *  Description:
 * 
 *      Basic time functions wrappers for the libcoap usage.
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
 * coap_time.h -- Clock Handling
 *
 * Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_time.h
 * @brief Clock Handling
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_TIME_H_
#define COAP_TIME_H_

#include <stdint.h>


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: Uses [ms] resolution on POSIX systems
 */
#define COAP_TICKS_PER_SECOND ((coap_tick_t)(1000U))


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Type representing internal timer ticks with (1 / COAP_TICKS_PER_SECOND)
 *    resolution.
 */
typedef uint64_t coap_tick_t;

/**
 * @brief: CoAP time in seconds since epoch.
 */
typedef time_t coap_time_t;

/**
 * @brief: Data type is used to represent the difference between two clock_tick_t
 *    values. This data type must have the same size in memory as coap_tick_t to
 *    allow wrapping.
 */
typedef int64_t coap_tick_diff_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Initializes the internal clock.
 */
void coap_clock_init(void);

/**
 * @brief: Sets @p t to the internal time with (1 / COAP_TICKS_PER_SECOND) resolution.
 */
void coap_ticks(coap_tick_t *t);

/**
 * @brief: Helper function that converts coap ticks to wallclock time. On POSIX, this
 *    function returns the number of seconds since the epoch. On other systems, it
 *    may be the calculated number of seconds since last reboot or so.
 *
 * @param t:
 *    internal system ticks.
 * @returns:
 *    the number of seconds that has passed since a specific reference point (seconds 
 *    since epoch on POSIX).
 */
coap_time_t coap_ticks_to_rt(coap_tick_t t);

/**
 * @brief: Helper function that converts coap ticks to POSIX wallclock time in us.
 *
 * @param t:
 *    internal system ticks.
 * @returns:
 *    the number of seconds that has passed since a specific reference point (seconds
 *    since epoch on POSIX).
 */
uint64_t coap_ticks_to_rt_us(coap_tick_t t);

/**
 * @brief: Helper function that converts POSIX wallclock time in us to coap ticks.
 *
 * @param t:
 *    POSIX time is us
 * @returns:
 *    coap ticks
 */
coap_tick_t coap_ticks_from_rt_us(uint64_t t);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @returns:
 *    1 if and only if @p a is less than @p b where less is defined on a signed data
 *    type.
 */
COAP_STATIC_INLINE int
coap_time_lt(coap_tick_t a, coap_tick_t b) {
  return ((coap_tick_diff_t)(a - b)) < 0;
}

/**
 * @returns:
 *    1 if and only if @p a is less than or equal @p b where less is defined on 
 *    a signed data type.
 */
COAP_STATIC_INLINE int coap_time_le(coap_tick_t a, coap_tick_t b) {
  return a == b || coap_time_lt(a,b);
}

#endif /* COAP_TIME_H_ */
