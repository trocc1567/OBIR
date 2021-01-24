/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-23 17:40:22
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

/* async.c -- state management for asynchronous messages
 *
 * Copyright (C) 2010,2011 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/**
 * @file async.c
 * @brief state management for asynchronous messages
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include "coap_config.h"
#include "coap.h"
#include "async.h"
#include "coap_debug.h"
#include "mem.h"
#include "utlist.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

// Utlist-style macros for searching pairs in linked lists
#define SEARCH_PAIR(head,out,field1,val1,field2,val2)   \
    SEARCH_PAIR2(head,out,field1,val1,field2,val2,next)

#define SEARCH_PAIR2(head,out,field1,val1,field2,val2,next)                \
    do {                                                                   \
        LL_FOREACH2(head,out,next) {                                       \
            if ((out)->field1 == (val1) && (out)->field2 == (val2)) break; \
        }                                                                  \
    } while(0)


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

coap_async_state_t *coap_register_async(
    coap_context_t *context,
    coap_session_t *session,
    coap_pdu_t *request,
    unsigned char flags,
    void *data
){
 
    /**
     * @brief: Serach @p context->async_state hash table to find @t coap_async_state_t object
     *   with session field equal to @p session and id field equal to @p request->tid
     * 
     *   If entry is found, return NULL.
     */
    coap_async_state_t *enry;
    coap_tid_t id = request->tid;        
    SEARCH_PAIR(context->async_state,enry,session,session,id,id);
    if (enry != NULL) {
        coap_log(LOG_DEBUG, "asynchronous state for transaction %d already registered\n", id);
        return NULL;
    }

    // Otherwise, allocate memory for the new @t coap_async_state_t object
    enry = (coap_async_state_t*) coap_malloc(sizeof(coap_async_state_t));
    if (!enry) {
        coap_log(LOG_CRIT, "coap_register_async: insufficient memory\n");
        return NULL;
    }

    memset(enry, 0, sizeof(coap_async_state_t));

    // Set COAP_ASYNC_CONFIRM according to request's type
    if (request->type == COAP_MESSAGE_CON)
        enry->flags |= COAP_ASYNC_CONFIRM;

    // Set data and ID
    enry->appdata = data;
    enry->id = id;

    // Create a new reference to the @p session
    enry->session = coap_session_reference( session );


    // Copy token from request to async
    if (request->token_length) {
        enry->tokenlen = (request->token_length > 8) ? 8 : request->token_length;
        memcpy(enry->token, request->token, enry->tokenlen);
    }

    // Set async's time stamp
    coap_touch_async(enry);

    // Prepend async to the qeueue
    LL_PREPEND(context->async_state, enry);

    return enry;
}


coap_async_state_t *coap_find_async(
    coap_context_t *context,
    coap_session_t *session,
    coap_tid_t id
){
    coap_async_state_t *tmp;
    SEARCH_PAIR(context->async_state,tmp,session,session,id,id);
    return tmp;
}


int coap_remove_async(
    coap_context_t *context,
    coap_session_t *session,
    coap_tid_t id, 
    coap_async_state_t **async
){
    // Find async in the hash tab;e
    coap_async_state_t *tmp = 
        coap_find_async(context, session, id);

    // If found, delete it
    if (tmp)
        LL_DELETE(context->async_state,tmp);

    // Put pointer to the deleted async
    *async = tmp;

    return tmp != NULL;
}


void coap_free_async(coap_async_state_t *async){
  
    if (async) {
        // Release reference to the session
        if (async->session)
            coap_session_release(async->session);
        // Conditionally free application's data stored in the async
        if((async->flags & COAP_ASYNC_RELEASE_DATA) != 0)
            coap_free(async->appdata);
        // Free async's reources
        coap_free(async);
    }
}
