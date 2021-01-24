/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-30 22:50:29
 *  Description:
 * 
 *      File contains base API related with the CoAP context stack manipulation.
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
 * net.h -- CoAP network interface
 *
 * Copyright (C) 2010-2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_NET_H_
#define COAP_NET_H_

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "coap_io.h"
#include "coap_time.h"
#include "option.h"
#include "pdu.h"
#include "prng.h"
#include "coap_session.h"

struct coap_queue_t;
struct coap_resource_t;
struct coap_context_t;
struct coap_async_state_t;


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Maximum frequency of the RST responses for a single session [s]
 */
#define MAX_RST_FREQ 4

/**
 * @brief: Structure descibing a node of a queue holding informations about
 *    CoAP packets to be send.
 */
typedef struct coap_queue_t {
    
    // Value used to form a forward-list
    struct coap_queue_t *next;

    // The CoAP session associated with the packet
    coap_session_t *session;      

    // CoAP transaction ID (message ID of the PDU itself)
    coap_tid_t id;
    
    // the CoAP PDU to send */
    coap_pdu_t *pdu;

    /* -------------------------- Time-related informations -------------------------- */

    // Description of when to send PDU for the next time
    coap_tick_t t;
    // Retransmission counter (node and it's PDU will be removed when reaches zero)
    unsigned char retransmit_cnt;
    // The randomized timeout value
    unsigned int timeout;

} coap_queue_t;


/**
 * @brief: Response handler that is used as call-back in coap_context_t.
 *
 * @param context:
 *    CoAP session.
 * @param session:
 *    CoAP session.
 * @param sent:
 *    The PDU that was transmitted.
 * @param received:
 *    The PDU that was received.
 * @param id:
 *    CoAP transaction ID
 */
typedef void (*coap_response_handler_t)(
    struct coap_context_t *context,
    coap_session_t *session,
    coap_pdu_t *sent,
    coap_pdu_t *received,
    const coap_tid_t id
);

/**
 * @brief: Negative Acknowedge handler that is used as call-back in coap_context_t
 *
 * @param context:
 *    CoAP session.
 * @param session:
 *    CoAP session.
 * @param sent:
 *    The PDU that was transmitted.
 * @param reason:
 *    The reason for the NACK.
 * @param id:
 *    CoAP transaction ID.
 */
typedef void (*coap_nack_handler_t)(
    struct coap_context_t *context,
    coap_session_t *session,
    coap_pdu_t *sent,
    coap_nack_reason_t reason,
    const coap_tid_t id
);

/**
 * @brief: Recieved Ping handler that is used as call-back in coap_context_t
 *
 * @param context:
 *    CoAP session
 * @param session:
 *    CoAP session
 * @param received:
 *    The PDU that was received
 * @param id:
 *    CoAP transaction ID
 */
typedef void (*coap_ping_handler_t)(
    struct coap_context_t *context,
    coap_session_t *session,
    coap_pdu_t *received,
    const coap_tid_t id
);

/**
 * @brief: Structure describing the CoAP stack's global state.
 * 
 * @note: There may be many active contexts hold on a signle machine or even within
 *    a single programm.
 */
typedef struct coap_context_t {
    
    // Application-specific data
    void *app;
    
    /* ------------------------------- Context's state ------------------------------- */
    
    // Hash table or list of known resources
    struct coap_resource_t *resources; 
    // Hash table or list of unknown resources (can be used for handling requests related to unknown resources )
    struct coap_resource_t *unknown_resource; 
    
    // List of asynchronous transactions [?]
    struct coap_async_state_t *async_state;

    // Queue of of sent packets (waiting for ACK) (retransmisssion queue)
    coap_queue_t *sendqueue;
    // Base time for time stamps of packets in a sendqueue
    coap_tick_t sendqueue_basetime;

    /**
     * @note: The time stamp in the first element of the sendqeue is relative
     *    to sendqueue_basetime. 
     */
    
    // The list of endpoints used for listening (for servers)
    coap_endpoint_t *endpoint;
    // The list of sessions (for clients)
    coap_session_t *sessions;
    
    /**
     * @brief: The last message id that was used by the context. The initial
     *    value is set by coap_new_context() and is usually a random value. A new
     *    message id can be created with coap_new_message_id().
     */
    uint16_t message_id;
    
    /* -------------------------- Context-specific routines -------------------------- */

    /**
     * @brief: Set of handlers for incoming packages
     */
    coap_response_handler_t response_handler;
    coap_nack_handler_t nack_handler;
    coap_ping_handler_t ping_handler;
    
    // Network IO routines used by the context
    ssize_t (*network_send)(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen);
    ssize_t (*network_read)(coap_socket_t *sock, struct coap_packet_t *packet);
    

    /* ----------------------------- Context's parameters ---------------------------- */

    // Set of CoAP message options known within the context   
    coap_opt_filter_t known_options;
    
    // Number of seconds of inactivity after which an unused session will be closed (0 means use default)
    unsigned int session_timeout;        
    // Maximum number of simultaneous unused sessions per endpoint (0 means no maximum)
    unsigned int max_idle_sessions;      
    // Minimum inactivity time before sending a ping message (0 means disabled)
    unsigned int ping_timeout;                     
  
} coap_context_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Adds @p node to given @p queue, ordered by variable t in @p node.
 *
 * @param queue:
 *    Queue to add to
 * @param node:
 *    Node entry to add to Queue
 * @return @c 1 added to queue, @c 0 failure.
 */
int coap_insert_node(coap_queue_t **queue, coap_queue_t *node);

/**
 * @brief: Destroys specified @p node.
 *
 * @param node:
 *    Node entry to remove
 * @returns:
 *    1 if node deleted from queue
 *    0 on failure
 */
int coap_delete_node(coap_queue_t *node);

/**
 * @brief: Removes all items from given @p queue and frees the allocated storage.
 *
 * @param queue:
 *    The queue to delete
 */
void coap_delete_all(coap_queue_t *queue);

/**
 * @brief: Creates a new node suitable for adding to the CoAP sendqueue.
 *
 * @returns:
 *    New node entry on success
 *    NULL if failure
 */
coap_queue_t *coap_new_node(void);

/**
 * @brief: Sets sendqueue_basetime in the given context object @p context to @p now.
 * 
 * @param context:
 *    CoAP context to be adjusted
 * @param now:
 *     current time
 * @returns:
 *    the number of elements in the @pcontext->sendqueue that have timed out.
 */
unsigned int coap_adjust_basetime(coap_context_t *context, coap_tick_t now);

/**
 * @param context:
 *    context to be checked
 * @returns:
 *    the next pdu from the sedqueue if the queue is not empty
 *    NULL if @p context is null or sendqueue is empty
 */
coap_queue_t *coap_peek_next( coap_context_t *context );

/**
 * @param context:
 *    context to adjust basetime for 
 * @returns:
 *    the next pdu to send and removes it from the sendqeue.
 */
coap_queue_t *coap_pop_next( coap_context_t *context );

/**
 * @brief: Creates a new @t coap_context_t object that will hold the CoAP stack status.
 * 
 * @param listen_addr:
 *    context to adjust basetime for 
 * @returns:
 *    created context on success
 *    NULL on failure
 */
coap_context_t *coap_new_context(const coap_address_t *listen_addr);

/**
 * @brief: Set the context keepalive timer for sessions. A keepalive message will be
 *    sent after if a session has been inactive, i.e. no packet sent or received, for
 *    the given number of seconds. 
 *
 * @param context:
 *    The coap_context_t object
 * @param seconds:
 *    Number of seconds for the inactivity timer, or zero to disable CoAP-level keepalive
 *    messages.
 * @returns:
 *    1 if successful
 *    0 else
 */
void coap_context_set_keepalive(coap_context_t *context, unsigned int seconds);

/**
 * @brief: CoAP stack context must be released with coap_free_context(). This function
 *    clears all entries from the receive queue and send queue and deletes the
 *    resources that have been registered with @p context, and frees the attached
 *    endpoints.
 *
 * @param context:  
 *    the current coap_context_t object to free off
 */
void coap_free_context(coap_context_t *context);

/**
 * @brief: Stores @p data with the given CoAP context. This function
 *    overwrites any value that has previously been stored with @p
 *    context.
 *
 * @param context:
 *    The CoAP context
 * @param data:
 *    the data to store with wih the context. Note that this data must be valid during
 *    the lifetime of @p context
 */
void coap_set_app_data(coap_context_t *context, void *data);

/**
 * @brief: Returns any application-specific data that has been stored with @p
 *    context using the function coap_set_app_data(). This function will
 *    return @c NULL if no data has been stored.
 *
 * @param:
 *    context The CoAP context.
 *
 * @returns:
 *    the data previously stored or @c NULL if not data stored.
 */
void *coap_get_app_data(const coap_context_t *context);

/**
 * @brief: Creates a new ACK PDU with specified error @p code. The options specified by
 *   the filter expression @p opts will be copied from the original request
 *   contained in @p request. Unless @c SHORT_ERROR_RESPONSE was defined at build
 *   time, the textual reason phrase for @p code will be added as payload, with
 *   Content-Type 0.
 * 
 *   This function returns a pointer to the new response message, or @c NULL on
 *   error. The storage allocated for the new message must be relased with
 *   coap_free().
 *
 * @param request:
 *    specification of the received (confirmable) request.
 * @param code:
 *    the error code to set.
 * @param opts:
 *    an option filter that specifies which options to copy from
 *    the original request in @p node.
 * @returns:
 *    a pointer to the new message on success
 *    NULL on error
 */
coap_pdu_t *coap_new_error_response(
    coap_pdu_t *request,
    unsigned char code,
    coap_opt_filter_t opts
);

/**
 * @brief: Sends an error response with code @p code for request @p request using
 *    @p session. @p opts will be passed to coap_new_error_response() to copy marked
 *    options from the request.
 *
 * @param session:
 *    the CoAP session.
 * @param request:
 *    the original request to respond to.
 * @param code:
 *    the response code.
 * @param opts:
 *    a filter that specifies the options to copy from the @p request.
 * @returns:
 *    the transaction id if the message was sent
 *    @c COAP_INVALID_TID otherwise.
 */
coap_tid_t coap_send_error(
    coap_session_t *session,
    coap_pdu_t *request,
    unsigned char code,
    coap_opt_filter_t opts
);

/**
 * @brief: Helper funktion to create and send a message with @p type (usually ACK or RST).
 *
 * @param session:
 *    the CoAP session
 * @param request:
 *    the request that should be responded to
 * @param type:
 *    which type to set
 * @returns:
 *    transaction id on success or @c COAP_INVALID_TID otherwise.
 */
coap_tid_t
coap_send_message_type(coap_session_t *session, coap_pdu_t *request, unsigned char type);

/**
 * @brief: Sends an ACK message with code 0 for the specified @p request using @p session.
 *
 * @param session:
 *    the CoAP session.
 * @param request:
 *    the request to be acknowledged.
 * @returns:
 *    the transaction id if ACK was sent or @c COAP_INVALID_TID on error.
 */
coap_tid_t coap_send_ack(coap_session_t *session, coap_pdu_t *request);


/**
 * @brief: Sends a CoAP message to the peer given with @p session. The memory that is allocated
 *     by pdu will be released by coap_send(). The caller must not use the pdu after calling 
 *     coap_send().
 *
 * @param session:
 *    the CoAP session
 * @param pdu:
 *    the CoAP PDU to send
 * @returns:
 *    the message id of the sent message or @c COAP_INVALID_TID on error.
 */
coap_tid_t coap_send( coap_session_t *session, coap_pdu_t *pdu );

/**
 * @brief: Handles retransmissions of confirmable messages
 *
 * @param context:
 *    the CoAP context
 * @param node:
 *    the packet to retransmit given with @t coap_queue_t node object
 *
 * @returns:
 *    the message id of the sent message 
 *    @c COAP_INVALID_TID on error
 */
coap_tid_t coap_retransmit(coap_context_t *context, coap_queue_t *node);

/**
 * @brief: For applications with their own message loop, send all pending retransmits and returns the
 *    list of sockets with events to wait for. Returns also the next timeout. The application should
 *    call coap_read() when any data is available on any of the sockets.
 *
 * @param ctx:
 *    the CoAP context
 * @param sockets [out]:
 *    the array of socket descriptors (filled on output)
 * @param max_sockets:
 *    the size of socket array
 * @param num_sockets [out]:
 *    the pointer to the number of valid entries in the socket arrays on output
 * @param now:
 *    the Current time
 * @returns:
 *    timeout as maxmimum number of milliseconds that the application should wait for network events on success
 *    0 if the application should wait forever
 */
unsigned int coap_write(
    coap_context_t *ctx,
    coap_socket_t *sockets[],
    unsigned int max_sockets,
    unsigned int *num_sockets,
    coap_tick_t now
);

/**
 * @brief: For applications with their own message loop, reads all data from the network.
 *
 * @param ctx:
 *    the CoAP context
 * @param now:
 *    current time
 */
void coap_read(
    coap_context_t *ctx,
    coap_tick_t now
);

/**
 * @brief: The main message processing loop.
 *
 * @param ctx:
 *    the CoAP context
 * @param timeout_ms:
 *    minimum number of milliseconds to wait for new messages before returning. If zero the call will block until
 *    at least one packet is sent or received
 *
 * @returns:
 *    number of milliseconds spent on success
 *    -1 on error
 */

int coap_run_once(
    coap_context_t *ctx, 
    unsigned int timeout_ms
);

/**
 * @brief: Parses and interprets a CoAP datagram with context @p ctx.
 *
 * @param ctx:
 *    the current CoAP context
 * @param session:
 *    the current CoAP session
 * @param data:
 *    the received packet'd data
 * @param data_len:
 *    the received packet'd data length
 *
 * @returns:
 *    0 if message was handled successfully
 *    less than zero on error
 */
int coap_handle_dgram(
    coap_session_t *session, 
    uint8_t *data, 
    size_t data_len
);

/**
 * @brief: This function removes the element with given @p id from the given list. If @p id was found,
 *    @p node is updated to point to the removed element. 
 * 
 * @param queue:
 *    the queue to search for @p id
 * @param session:
 *    the session to look for
 * @param id:
 *    the transaction id to look for
 * @param node:
 *    if found, @p node is updated to point to the removed node. You must release the storage pointed to
 *    by @p node manually.
 * @returns:
 *    1 if @p id was found
 *    0 otherwise.
 * 
 * @note: For a return value of 0, the contents of @p node is undefined.
 * @note: The storage allocated by @p node is @b not released. The caller must do this manually using 
 *    coap_delete_node(). 
 */
int coap_remove_from_queue(
    coap_queue_t **queue,
    coap_session_t *session,
    coap_tid_t id,
    coap_queue_t **node
);

/**
 * @brief: Insertes @p node to the retransmit @p session->context->sendqueue queue. Timeout of the packet is
 *    set to the initial value that is relative to the @p session->context->sendqueue_basetime (if sendqueue 
 *    is not empty) or absolute (otherwise). Reference ounter on the @p sessio is incremented.
 * 
 * @param session:
 *    session associated with the @p node
 * @param node:
 *    packet node to be retransmitted
 * @return:
 *    transaction ID of the node 
 */
coap_tid_t coap_wait_ack(
    coap_session_t *session,
    coap_queue_t *node
);

/**
 * @brief: Retrieves transaction related to given @p sesssion OR of the given @p id
 *    from the queue.
 *
 * @param queue:
 *    the transaction queue to be searched
 * @param session:
 *    the session to find
 * @param id:
 *    the transaction id to find
 *
 * @returns:
 *    a pointer to the transaction object on success
 *    NULL if not found
 */
coap_queue_t *coap_find_transaction(
    coap_queue_t *queue, 
    coap_session_t *session, 
    coap_tid_t id
);

/**
 * @brief: Cancels all outstanding messages for session @p session that have the 
 *    specified token.
 *
 * @param session:
 *    session of the messages to remove
 * @param token:
 *    message token
 * @param token_length:
 *    act length of @p token
 */
void coap_cancel_all_messages(
    coap_session_t *session,
    const uint8_t *token,
    size_t token_length
);

/**
 * @brief: Cancels all outstanding messages for @p session.
 *
 * @param session:
 *    tession of the messages to remove.
 * @param reason:
 *    the reason for the session cancellation
 */
void
coap_cancel_session_messages(
    coap_session_t *session,
    coap_nack_reason_t reason
);

/**
 * @brief: Dispatches the PDUs from the receive queue in given context.
 * 
 * @param session 
 *    session associated with the @p pdu
 * @param pdu 
 *    PDU to be dispatched
 */
void coap_dispatch(
    coap_session_t *session,
    coap_pdu_t *pdu
);

/**
 * @returns:
 *    1 if there are no messages to send or to dispatch in the context's queues.
 *    0 otherwise
 **/
int coap_can_exit(coap_context_t *context);

/**
 * @returns:
 *    the current value of an internal tick counter
 * 
 * @note: The counter counts COAP_TICKS_PER_SECOND ticks every second.
 */
void coap_ticks(coap_tick_t *);

/**
 * @brief: Verifies that @p pdu contains no unknown critical options. Options must be
 *    registered at @p context, using the function coap_register_option(). A basic set of options
 *    is registered automatically by coap_new_context(). The given filter object @p unknown 
 *    will be updated with the unknown options. As only @c COAP_MAX_OPT options can be 
 *    signalled this way, remaining options must be examined manually.
 *
 * @param context:
 *    the context where all known options are registered
 * @param pdu:
 *    the PDU to check
 * @param unknown:
 *    the output filter that will be updated to indicate the unknown critical options found
 *    in @p pdu.
 *
 * @returns:
 *    1 if everything was ok
 *    0 otherwise
 * 
 * @code:
 * 
 *   coap_opt_filter_t f = COAP_OPT_NONE;
 *   coap_opt_iterator_t opt_iter;
 *   
 *   if (coap_option_check_critical(context, pdu, f) == 0) {
 *     coap_option_iterator_init(pdu, &opt_iter, f);
 *   
 *     while (coap_option_next(&opt_iter)) {
 *       if (opt_iter.type & 0x01) {
 *         ... handle unknown critical option in opt_iter ...
 *       }
 *     }
 *   }
 * 
 * @endcode
 */
int coap_option_check_critical(
    coap_context_t *context,
    coap_pdu_t *pdu,
    coap_opt_filter_t unknown
);

/**
 * @brief: Creates a new response for given @p request with the contents of @c .well-known/core.
 *    The result newly allocated PDU that must be either sent with coap_sent() or released
 *    by coap_delete_pdu().
 * 
 * @param session:
 *    the CoAP session to use
 * @param request:
 *    the request for @c .well-known/core 
 * @returns:
 *    a new 2.05 response for @c .well-known/core on success
 *    NULL on error
 */
coap_pdu_t *coap_wellknown_response(
    coap_session_t *session,
    coap_pdu_t *request
);

/**
 * @brief: Calculates the initial timeout based on the @p session's CoAP transmission
 *    parameters 'ack_timeout', 'ack_random_factor' and COAP_TICKS_PER_SECOND.
 *    The calculation requires 'ack_timeout' and 'ack_random_factor' to be in
 *    Qx.FRAC_BITS (@c FRAC_BITS defined in net.c) fixed point notation, whereas the
 *    passed parameter @p r is interpreted as the fractional part of a Q0.MAX_BITS
 *    random value.
 *
 * @param session:
 *    session timeout is associated with
 * @param random:
 *    random value as fractional part of a Q0.MAX_BITS fixed point value
 * @returns:
 *    COAP_TICKS_PER_SECOND * @p session->ack_timeout * (1 + (@p session->ack_random_factor - 1) * r)
 */
unsigned int coap_calc_timeout(coap_session_t *session, unsigned char random);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Registers a new message handler that is called whenever a response was
 *   received that matches an ongoing transaction.
 *
 * @param context:
 *    The context to register the handler for
 * @param handler:
 *    The response handler to register
 */
COAP_STATIC_INLINE void
coap_register_response_handler(coap_context_t *context, coap_response_handler_t handler){
  context->response_handler = handler;
}

/**
 * @brief: Registers a new message handler that is called whenever a confirmable
 *    message (request or response) is dropped after all retries have been
 *    exhausted, or a rst message was received, or a network level event was received
 *    that indicates delivering the message is not possible.
 *
 * @param context:
 *    The context to register the handler for
 * @param handler:
 *    The nack handler to register
 */
COAP_STATIC_INLINE void
coap_register_nack_handler(coap_context_t *context, coap_nack_handler_t handler){
  context->nack_handler = handler;
}

/**
 * @brief: Registers a new message handler that is called whenever a CoAP Ping
 *    message is received.
 *
 * @param context:
 *    The context to register the handler for
 * @param handler:
 *    The ping handler to register
 */
COAP_STATIC_INLINE void
coap_register_ping_handler(coap_context_t *context, coap_ping_handler_t handler){
  context->ping_handler = handler;
}

/**
 * @brief: Registers the option type @p type with the given context object @p context.
 *    (add option to the context's known-options)
 *
 * @param :context
 *    The context to use.
 * @param :type
 *   The option type to register.
 */
COAP_STATIC_INLINE void
coap_register_option(coap_context_t *context, uint16_t type){
  coap_option_filter_set(context->known_options, type);
}

/**
 * @brief: Returns a new message id and updates @p session->tx_mid accordingly. The
 *    message id is returned in network byte order to make it easier to read in
 *    tracing tools.
 *
 * @param session:
 *    The current coap_session_t object
 * @returns:
 *    Incremented message id in network byte order
 */
COAP_STATIC_INLINE uint16_t
coap_new_message_id(coap_session_t *session) {
  return ++session->tx_mid;
}


/**
 * @brief: Sends an RST message with code 0 for the specified @p request.
 *
 * @param session:
 *    The CoAP session.
 * @param request:
 *    The request to be reset.
 *
 * @returns:
 *    The transaction id if RST was sent or @c
 *    COAP_INVALID_TID on error.
 */
COAP_STATIC_INLINE coap_tid_t
coap_send_rst(coap_session_t *session, coap_pdu_t *request){
  return coap_send_message_type(session, request, COAP_MESSAGE_RST);
}


#endif /* COAP_NET_H_ */
