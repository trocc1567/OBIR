/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 00:46:14
 *  Description:
 * 
 *      File contains API for intra-library logging and debugging mechanisms.
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
 * coap_debug.h -- debug utilities
 *
 * Copyright (C) 2010-2011,2014 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_DEBUG_H_
#define COAP_DEBUG_H_

#include "pdu.h"

struct coap_address_t;

/* -------------------------------------------- [Data structures] --------------------------------------------- */

/** 
 * @brief: Pre-defined log levels akin to what is used in 'syslog'. 
 */
typedef enum {
    // Emergency
    LOG_EMERG = 0,
    // Alert 
    LOG_ALERT,
    // Critical
    LOG_CRIT,
    // Error
    LOG_ERR,
    // Warning
    LOG_WARNING,
    // Notice
    LOG_NOTICE,
    // Info
    LOG_INFO,
    // Debug
    LOG_DEBUG
} coap_log_t;

/**
 * @brief: Logging call-back handler definition.
 *
 * @param level:
 *    One of the LOG_* values.
 * @param message:
 *    Zero-terminated string message to log.
 */
typedef void (*coap_log_handler_t) (coap_log_t level, const char *message);

/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

coap_log_t coap_get_log_level(void);
void coap_log_impl(coap_log_t level, const char *format, ...);

/**
 * @brief: Used as output for messages from @c LOG_DEBUG level to @c LOG_ERR level
 */
#ifndef COAP_DEBUG_FD
#define COAP_DEBUG_FD stdout
#endif


/**
 * @brief: Used as output for messages from @c LOG_CRIT level to @c LOG_EMERG level
 */
#ifndef COAP_ERR_FD
#define COAP_ERR_FD stderr
#endif

/**
 * @brief: Logging function. Writes the given text to @c COAP_ERR_FD (for @p level <= @c LOG_CRIT)
 *    to or @c COAP_DEBUG_FD (for @p level >= @c LOG_ERR). The text is output only when @p level
 *    is below or equal to the log level that set by coap_set_log_level().
 *
 * @param level:
 *    One of the LOG_* values.
 */
#ifndef coap_log
#define coap_log(level, ...) do { \
    if ((int)((level))<=(int)coap_get_log_level()) \
        coap_log_impl((level), __VA_ARGS__); \
} while(0)
#endif

/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Get the current logging level.
 *
 * @returns:
 *    One of the LOG_* values.
 */
coap_log_t coap_get_log_level(void);

/**
 * @brief: Sets the log level to the specified value.
 *
 * @param level:
 *    One of the LOG_* values.
 */
void coap_set_log_level(coap_log_t level);


/**
 * @brief: Add a custom log callback handler.
 *
 * @param handler:
 *    The logging handler to use or @p NULL to use default handler.
 */
void coap_set_log_handler(coap_log_handler_t handler);

/**
 * @brief: Get the library package name.
 *
 * @returns:
 *    Zero-terminated string with the name of this library.
 */
const char *coap_package_name(void);

/**
 * @brief: Get the library package version.
 *
 * @returns:
 *    Zero-terminated string with the library version.
 */
const char *coap_package_version(void);

/**
 * @brief: Writes the given text to @c COAP_ERR_FD (for @p level <= @c LOG_CRIT) or 
 *    @c COAP_DEBUG_FD (for @p level >= @c LOG_ERR). The text is output only when
 *    @p level is below or equal to the log level that set by coap_set_log_level().
 *
 *    Internal function.
 *
 * @param level:
 *    One of the LOG_* values.
 * @param format:
 *    The format string to use.
 */
void coap_log_impl(coap_log_t level, const char *format, ...);

/**
 * @brief: Defines the output mode for the coap_show_pdu() function.
 *
 * @param use_fprintf:
 *    1 if the output is to use fprintf() (the default)
 *    0 if the output is to use coap_log().
 */
void coap_set_show_pdu_output(int use_fprintf);

/**
 * @brief: Display the contents of the specified @p pdu.
 * 
 * @param level:
 *    The required minimum logging level.
 * @param pdu:
 *    The PDU to decode.
 * 
 * @note: The output method of coap_show_pdu() is dependent on the setting of
 *    coap_set_show_pdu_output().
 */
void coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu);

/**
 * @brief: Print the address into the defined buffer.
 *
 *   Internal Function.
 *
 * @param address:
 *    the address to print
 * @param buffer:
 *    the buffer to print into
 * @param size:
 *    the size of the buffer to print into
 * @returns:
 *    the amount of bytes written into the buffer
 */
size_t coap_print_addr(
    const struct coap_address_t *address,
    unsigned char *buffer, 
    size_t size
);

/**
 * @brief: Set the packet loss level for testing.  This can be in one of two forms.
 *
 *    Percentage : "0%"" to "100%"".  Use the specified probability.
 *    "0%"" is send all packets, "100%"" is drop all packets.
 *   
 *    List: A comma separated list of numbers (i.e "x,y,z, ...") or number ranges that
 *    are the packets to drop (i.e. "x-y").
 *
 * @param loss_level:
 *    The defined loss level (percentage or list).
 *
 * @returns:
 *    1 If loss level set, 0 if there is an error.
 */
int coap_debug_set_packet_loss(const char *loss_level);

/**
 * @brief: Check to see whether a packet should be sent or not.
 *
 *    Internal function
 *
 * @returns:
 *    1 if packet is to be sent, 0 if packet is to be dropped.
 * 
 * @note: this function bases on the intervals' list, if set with @f coap_debug_set_packet_loss
 *    and on the loss_level (percentage value) otherwise.
 */
int coap_debug_send_packet(void);


#endif /* COAP_DEBUG_H_ */
