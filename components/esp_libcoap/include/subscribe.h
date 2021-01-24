/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-26 00:30:20
 *  Description:
 * 
 *      File defines basic API related to CoAP's subcription model.
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
 * subscribe.h -- subscription handling for CoAP
 *                see RFC7641
 *
 * Copyright (C) 2010-2012,2014-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_SUBSCRIBE_H_
#define COAP_SUBSCRIBE_H_

#include "address.h"
#include "coap_io.h"
#include "coap_session.h"
#include "block.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: The value COAP_OBSERVE_ESTABLISH in a GET request indicates a new observe
 *    relationship for (sender address, token) is requested.
 */
#define COAP_OBSERVE_ESTABLISH 0

/**
 * @brief: The value COAP_OBSERVE_CANCEL in a GET request indicates that the observe
 *    relationship for (sender address, token) must be cancelled.
 */
#define COAP_OBSERVE_CANCEL 1


/**
 * @brief: Number of notifications that may be sent non-confirmable before a confirmable
 *    message is sent to detect if observers are alive. The maximum allowed value here
 *    is @c 15.
 */
#ifndef COAP_OBS_MAX_NON
#define COAP_OBS_MAX_NON 5
#endif

/**
 * @brief: Number of confirmable notifications that may fail (i.e. time out without being
 *    ACKed) before an observer is removed. The maximum value for COAP_OBS_MAX_FAIL is @c 3.
 */
#ifndef COAP_OBS_MAX_FAIL
#define COAP_OBS_MAX_FAIL 3
#endif


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/** 
 * @brief: Subscriber description 
 */
typedef struct coap_subscription_t {

    // Value used to create forward list
    struct coap_subscription_t *next;

    // Session used for communication with subscriber
    coap_session_t *session;

    // Non-confirmable notifies allowed (up to 15)
    unsigned int non_cnt:4;
    // Confirmable notifies can fail (up to 3)
    unsigned int fail_cnt:2;
    // Set if the notification temporarily could not be sent
    unsigned int dirty:1;

    /**
     * @note: When notification temporarily could not be sent the resource's
     *    partially dirty flag is set too.
     */

    // Set if GET request had Block2 definition
    unsigned int has_block2:1;
    // GET request's Block2 definition
    coap_block_t block2;

    // Actual length of token
    size_t token_length;
    // Token used for subscription
    unsigned char token[8];

    // Query string used for subscription (if any)
    coap_string_t *query;

} coap_subscription_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Initializes @p sub structure.
 */
void coap_subscription_init(coap_subscription_t *sub);

#endif /* COAP_SUBSCRIBE_H_ */
