/* ============================================================================================================
 *  File: async.h
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-19 20:02:38
 *  Description: 
 *
 *      This file is a modification of the original libcoap source file. Aim of the modification was to 
 *      provide cleaner, richer documented and ESP8266-optimised version of the library. Core API of the 
 *      project was not changed or expanded, although some elemenets (e.g. DTLS support) have been removed 
 *      due to lack of needings from the modifications' authors. 
 * 
 *  Note: 
 *      
 *      This file contains depreciated API that is no longer supported by the libcoap. Header file and 
 *      implementations has been left unchanged for back compatibilty.
 * 
 * ============================================================================================================ */

/* -------------------------------------------- [Original header] --------------------------------------------- */

/*
 * async.h -- state management for asynchronous messages
 *
 * Copyright (C) 2010-2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file async.h
 * @brief State management for asynchronous messages
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_ASYNC_H_
#define COAP_ASYNC_H_

#include "net.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/** 
 * @brief: Definitions for Async Status Flags These flags can be used to control the
 *    behaviour of asynchronous response generation.
 */
#define COAP_ASYNC_CONFIRM   0x01  // Send confirmable response
#define COAP_ASYNC_SEPARATE  0x02  // Send separate response
#define COAP_ASYNC_OBSERVED  0x04  // The resource is being observed

// Release application data on destruction
#define COAP_ASYNC_RELEASE_DATA  0x08


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Structure for managing asynchronous state of CoAP resources. A
 *    coap_resource_t object holds a list of coap_async_state_t objects that can be
 *    used to generate a separate response in case a result of an operation cannot
 *    be delivered in time, or the resource has been explicitly subscribed to with
 *    the option @c observe.
 */
typedef struct coap_async_state_t {

    // Value used for creating forward lists
    struct coap_async_state_t *next;

    /**
     * @brief: This field can be used to register opaque application data with the
     *    asynchronous state object.
     */
    void *appdata;

    // Flags used to control behaviour
    unsigned char flags;

    /**
     * @brief: Holds the internal time when the object was registered with a
     *    resource. This field will be updated whenever @f coap_register_async()
     *    is called for a specific resource.
     */
    coap_tick_t created;

    // ID of last message seen
    uint16_t message_id;
    // Transaction's session
    coap_session_t *session;
    // Transaction's id
    coap_tid_t id;
    // Length of the token
    size_t tokenlen;
    // The token to use in a response
    uint8_t token[8];

} coap_async_state_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Allocates a new coap_async_state_t object and fills its fields according to
 *    the given @p request. The @p flags are used to control generation of empty
 *    ACK responses to stop retransmissions and to release registered @p data when
 *    the resource is deleted by coap_free_async(). This function returns a pointer
 *    to the registered coap_async_t object or @c NULL on error. Note that this
 *    function will return @c NULL in case that an object with the same identifier
 *    is already registered.
 *
 * @param context:
 *    the context to use.
 * @param session:
 *    the session that is used for asynchronous transmissions.
 * @param request:
 *    the request that is handled asynchronously.
 * @param flags:
 *    flags to control state management.
 * @param data:
 *    opaque application data to register. 
 *
 * @returns:
 *    a pointer to the registered coap_async_state_t object on success 
 *    NULL in case of an error
 * 
 * @note: The storage occupied by @p data is released on destruction only if flag
 *    COAP_ASYNC_RELEASE_DATA is set.
 */
coap_async_state_t *
coap_register_async(
    coap_context_t *context,
    coap_session_t *session,
    coap_pdu_t *request,
    unsigned char flags,
    void *data
);

/**
 * @brief: Removes the state object identified by @p id from @p context. The removed
 *    object is returned in @p s, if found. Otherwise, @p s is undefined. This
 *    function returns @c 1 if the object was removed, @c 0 otherwise. Note that
 *    the storage allocated for the stored object is not released by this
 *    functions. You will have to call coap_free_async() to do so.
 *
 * @param context:
 *    the context where the async object is registered.
 * @param session:
 *    the session that is used for asynchronous transmissions.
 * @param id:
 *    the identifier of the asynchronous transaction.
 * @param async [out]:
 *    will be set to the object identified by @p id after removal.
 *
 * @returns:
 *    if object was removed and @p s updated
 *    0 if no object was found with the given id. 
 * 
 * @note: @p s is valid only if the return value is @c 1.
 */
int coap_remove_async(coap_context_t *context,
                      coap_session_t *session,
                      coap_tid_t id,
                      coap_async_state_t **async);

/**
 * @brief: Releases the memory that was allocated by coap_async_state_init() for the
 *    object @p s. The registered application data will be released automatically
 *    if COAP_ASYNC_RELEASE_DATA is set.
 *
 * @param state:
 *    the object to delete.
 */
void coap_free_async(coap_async_state_t *state);

/**
 * @brief: Retrieves the object identified by @p id from the list of asynchronous
 *    transactions that are registered with @p context. This function returns a
 *    pointer to that object or @c NULL if not found.
 *
 * @param context:
 *    the context where the asynchronous objects are registered with
 * @param session:
 *    the session that is used for asynchronous transmissions
 * @param id:
 *    the id of the object to retrieve
 *
 * @returns:
 *    a pointer to the object identified by @p id on success
 *    NULL if not found.
 */
coap_async_state_t *coap_find_async(
    coap_context_t *context,
    coap_session_t *session, 
    coap_tid_t id
);


/* --------------------------------------- [Static-Inline Functions] ------------------------------------------ */

/**
 * @brief: Updates the time stamp of @p s.
 *
 * @param async:
 *    the state object to update.
 */
COAP_STATIC_INLINE void
coap_touch_async(coap_async_state_t *async) { coap_ticks(&async->created); }

#endif /* COAP_ASYNC_H_ */
