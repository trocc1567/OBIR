/* ============================================================================================================
 *  File: coap_time.c
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-23 02:39:36
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

/* coap_time.c -- Clock Handling
 *
 * Copyright (C) 2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#include "coap_config.h"

#include <time.h>
#include "libcoap.h"
#include "coap_time.h"

/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

// Use real-time clock for correct timestamps in coap_log()
#define COAP_CLOCK CLOCK_REALTIME

// Creates a Qx.frac from fval
#define Q(frac,fval) ((coap_tick_t)(((1 << (frac)) * (fval))))

// Number of frac bits for sub-seconds
#define FRAC 10

// Rounds val up and right shifts by frac positions
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))


/* -------------------------------------------- [Static symbols] ---------------------------------------------- */

// Number of second retrived from thr COAP_CLOCK at the library's startup
static coap_tick_t coap_clock_offset = 0;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

void coap_clock_init(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    coap_clock_offset = tv.tv_sec;
}


void coap_ticks(coap_tick_t *t){
  
    // Get time from the configured system timer
    struct timespec tv;
    clock_gettime(COAP_CLOCK, &tv);

    // Convert tv_nsec from ns resolution to COAP_TICKS_PER_SECOND resolution using Qm.n operation inside
    coap_tick_t tmp = SHR_FP(tv.tv_nsec * Q(FRAC, (COAP_TICKS_PER_SECOND/1000000000.0)), FRAC);

    // Sumup nanosecond part with second part
    *t = tmp + (tv.tv_sec - coap_clock_offset) * COAP_TICKS_PER_SECOND;
}


coap_time_t coap_ticks_to_rt(coap_tick_t t){
    return coap_clock_offset + (t / COAP_TICKS_PER_SECOND);
}


uint64_t coap_ticks_to_rt_us(coap_tick_t t){
    return (uint64_t)coap_clock_offset * 1000000 + (uint64_t)t * 1000000 / COAP_TICKS_PER_SECOND;
}


coap_tick_t coap_ticks_from_rt_us(uint64_t t){
    return (coap_tick_t)((t - (uint64_t)coap_clock_offset * 1000000) * COAP_TICKS_PER_SECOND / 1000000);
}
