/* ============================================================================================================
 *  File: net.c
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 05:04:05
 *  Description:
 * 
 *      
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

/* net.c -- CoAP network interface
 *
 * Copyright (C) 2010--2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "utlist.h"
#include "pdu.h"
#include "libcoap.h"
#include "utlist.h"
#include "coap_debug.h"
#include "coap_config.h"
#include "mem.h"
#include "str.h"
#include "async.h"
#include "resource.h"
#include "option.h"
#include "encode.h"
#include "block.h"
#include "net.h"

void coap_free_endpoint(coap_endpoint_t *ep);

COAP_STATIC_INLINE coap_queue_t *coap_malloc_node(void);
COAP_STATIC_INLINE void coap_free_node(coap_queue_t *node);
static ssize_t coap_send_pdu(coap_session_t *session, coap_pdu_t *pdu, coap_queue_t *node);
static void coap_read_session(coap_session_t *session, coap_tick_t now);
static int coap_read_endpoint(coap_endpoint_t *endpoint, coap_tick_t now);
COAP_STATIC_INLINE int token_match(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen);
COAP_STATIC_INLINE size_t get_wkc_len(coap_context_t *context, coap_opt_t *query_filter);
static int coap_cancel(coap_context_t *context, const coap_queue_t *sent);
static enum respond_t no_response(coap_pdu_t *request, coap_pdu_t *response);
static void handle_request(coap_session_t *session, coap_pdu_t *pdu);
static void handle_response(coap_session_t *session, coap_pdu_t *sent, coap_pdu_t *rcvd);

/* -------------------------------------------- [Macrofeinitions] --------------------------------------------- */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief: The number of bits for the fractional part of ACK_TIMEOUT and
 *    ACK_RANDOM_FACTOR. Must be less or equal 8.
 */
#define FRAC_BITS 6
#if FRAC_BITS > 8
#error FRAC_BITS must be less or equal 8
#endif

/**
* @brief: The maximum number of bits for fixed point integers that are used
*    for retransmission time calculation. Currently this must be @c 8.
*/
#define MAX_BITS 8

/** 
 * @brief: Creates a Qx.frac number from fval (given as @t coap_fixed_point_t)
 * 
 * @param frac:
 *    number of fractional bits
 * @param fval
 *    @t coap_fixed_point_t structure containing result number's parts
 */
#define Q(frac,fval) ((uint16_t)(((1 << (frac)) * fval.integer_part) + \
                      ((1 << (frac)) * fval.fractional_part + 500)/1000))

/**
 * @brief: creates a Qx.FRAC_BITS from session's 'ack_random_factor'
 *    (given as @t coap_fixed_point_t)
 * 
 * @param session:
 *    a coap_session_t object being a source of ack_random_factor
 */
#define ACK_RANDOM_FACTOR(session)                  \
  Q(FRAC_BITS, session->ack_random_factor)

/** 
 * @brief: creates a Qx.FRAC_BITS from session's 'ack_timeout'
 * 
 * @param session:
 *    a coap_session_t object being a source of ack_timeout
 */
#define ACK_TIMEOUT(session) Q(FRAC_BITS, session->ack_timeout)


/**
 * @brief: The integer 1.0 as a Qx.FRAC_BITS
 */
#define FP1 Q(FRAC_BITS, ((coap_fixed_point_t){1,0}))

/**
 * @brief: Rounds @p val up and right shifts by @p frac positions
 * 
 * @param frac:
 *    number of fractional bits
 * @param fval
 *    value to be bit-shifted
 */
#define SHR_FP(val,frac) (((val) + (1 << ((frac) - 1))) >> (frac))


/**
 * @brief: Convert's Block2 option's exponent into the actual block's size
 */
#define SZX_TO_BYTES(SZX) ((size_t)(1 << ((SZX) + 4)))



/* ---------------------------------------- [Global and static data] ------------------------------------------ */

/**
 * @brief: Internal flags to control the treatment of responses (specifically
 *   in presence of the No-Response option)
 */
enum respond_t { RESPONSE_DEFAULT, RESPONSE_DROP, RESPONSE_SEND };


/**
 * @brief: Default URI-Path for the /.well-known/core resource
 */
static coap_str_const_t coap_default_uri_wellknown = {
    .length = sizeof(COAP_DEFAULT_URI_WELLKNOWN) - 1,
         .s = (const uint8_t *) COAP_DEFAULT_URI_WELLKNOWN 
};


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

unsigned int coap_adjust_basetime(
    coap_context_t *context, 
    coap_tick_t now
) {
    // Number of elements in the @p context->sendqueue that has expired due to basetime change
    unsigned int result = 0;
    
    // Difference between current and @p new timestamp
    coap_tick_diff_t delta = now - context->sendqueue_basetime;

    // If @p context->sendqueue is not empty check packets' timeouts
    if (context->sendqueue) {

        // If new timestamp is earlier than a current, not timeouts will be updated
        if (delta <= 0)
            context->sendqueue->t -= delta;
        // Otherwise, some timeouts can expire
        else {

            /**
             * @brief: The time must be advanced forward, thus possibly leading to timed
             *    out elements at the queue's start. For every element that has timed out,
             *    its relative time is set to zero and the result counter is increased. 
             */

            coap_queue_t *packet = context->sendqueue;
            coap_tick_t timeout = 0;

            // Iterate over all expired packets (sendqueue is sorted in an ascending order with respect to timeouts)
            while (packet && (packet->t < (coap_tick_t) delta - timeout)) {
                
                /**
                 * @brief: Time out of the packet is calculated as a sum of the context's basetime
                 *    and '->t' component of all previous packets in the queue.
                 */

                timeout += packet->t;

                // Expired packet's '->t' component set to 0 signals an 'expired' state
                packet->t = 0;

                result++;
                packet = packet->next;
            }

            // Finally adjust the first element that has not expired
            if (packet)
                packet->t = (coap_tick_t) delta - timeout;
        }
    }

    // Adjust basetime
    context->sendqueue_basetime += delta;

    return result;
}


int coap_insert_node(
    coap_queue_t **queue, 
    coap_queue_t *node
) {
    if (!queue || !node)
        return 0;
    

    // Set queue head if empty
    if (!*queue) {
        *queue = node;
        return 1;
    }

    // Replace queue head if PDU's time is less than head's time
    if (node->t < (*queue)->t) {
        node->next = *queue;
        *queue = node;

        /**
         * @brief: Time out of the packet in queue is calculated as a sum of the context's basetime
         *    and '->t' component of all previous packets in the queue. For that reasone we need to
         *    make head->t relative to node->t.
         */

        (*queue)->t -= node->t;
        return 1;
    }

    // Search for right place to insert
    coap_queue_t *p, *q = *queue;
    do {
        // Make node's timeout relative to q's timeout
        node->t -= q->t;

        // Advance through the list
        p = q;
        q = q->next;
        
    } while (q && q->t <= node->t);

    // Make q'a timeout relative to the node'a timeout
    if (q)
        q->t -= node->t;                

        // Insert a new item
    node->next = q;
    p->next = node;
    
    return 1;
}


int coap_delete_node(coap_queue_t *node) {
    
    if (!node)
        return 0;

    // Delete an actual packet's data
    coap_delete_pdu(node->pdu);


    // Remove node out of context->sendqueue (it could be added in by coap_wait_ack())
    if ( node->session ) {
        if (node->session->context->sendqueue)
            LL_DELETE(node->session->context->sendqueue, node);
        coap_session_release(node->session);
    }

    // Free the packet's node itself
    coap_free_node(node);

    return 1;
}


void coap_delete_all(coap_queue_t *queue) {
    
    if (!queue)
        return;

    // Recurently cooal the function to delete packets' nodes from the end of list
    coap_delete_all(queue->next);
    coap_delete_node(queue);
}


coap_queue_t *coap_new_node(void) {

    // Allocate memory for the new packet's node
    coap_queue_t *node = coap_malloc_node();
    if (!node) {
        #ifndef NDEBUG
        coap_log(LOG_WARNING, "coap_new_node: malloc\n");
        #endif
        return NULL;
    }

    // Clear node's memory
    memset(node, 0, sizeof(*node));
    
    return node;
}


coap_queue_t *coap_peek_next(coap_context_t *context) {

    if (!context)
        return NULL;

    return context->sendqueue;
}


coap_queue_t *coap_pop_next(coap_context_t *context) {

    if (!context || !context->sendqueue)
        return NULL;

    // Detach the head node from the queue
    coap_queue_t *next = context->sendqueue;
    context->sendqueue = context->sendqueue->next;
    next->next = NULL;

    // Update head->next node's timeout, as it was relative to the head's timeout
    if (context->sendqueue)
        context->sendqueue->t += next->t;
    
    return next;
}


void coap_context_set_keepalive(coap_context_t *context, unsigned int seconds) {
    context->ping_timeout = seconds;
}


coap_context_t *coap_new_context(const coap_address_t *listen_addr){

    // Make sure library has been initialized
    coap_startup();

    // Allocate memory for the context
    coap_context_t *context = 
        (coap_context_t *) coap_malloc(sizeof(coap_context_t));

    // Check if allocation succeded
    if (!context) {
        #ifndef NDEBUG
        coap_log(LOG_EMERG, "coap_init: malloc:\n");
        #endif
        return NULL;
    }

    // Clear the memory inside context
    memset(context, 0, sizeof(coap_context_t));

    // Initialize message id
    prng((unsigned char *) &context->message_id, sizeof(uint16_t));

    // If @p listen_addr has been given, create an initial endpoint to listen on
    if (listen_addr) {
        coap_endpoint_t *endpoint = coap_new_endpoint(context, listen_addr);
        if (endpoint == NULL)
            goto onerror;
    }

    // Initialize read & send methods to default
    context->network_send = coap_network_send;
    context->network_read = coap_network_read;

    return context;

    // On error, free allocated context and return NULL
onerror:
    coap_free(context);
    return NULL;
}


void coap_set_app_data(coap_context_t *context, void *app_data) {
    assert(context);
    context->app = app_data;
}


void *coap_get_app_data(const coap_context_t *context) {
    assert(context);
    return context->app;
}


void coap_free_context(coap_context_t *context) {

    if (!context)
        return;    

    // Delete all packet's that wait for an acknowledgement
    coap_delete_all(context->sendqueue);

    // Free all server's resources
    coap_delete_all_resources(context);

    // Free all (server's) endpoints
    coap_endpoint_t *ep, *tmp;
    LL_FOREACH_SAFE(context->endpoint, ep, tmp)
        coap_free_endpoint(ep);

    // Free all (client's) sessions
    coap_session_t *sp, *stmp;
    LL_FOREACH_SAFE(context->sessions, sp, stmp)
        coap_session_release(sp);
    
    coap_free(context);
}


int coap_option_check_critical(
    coap_context_t *context,
    coap_pdu_t *pdu,
    coap_opt_filter_t unknown
) {
    int ok = true;
    bool unknown_filter_full = false;

    // Create @p pdu's options iterator
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

    // Iterate over options
    while (coap_option_next(&opt_iter)) {

        // Break when we are sure that unknown critical options reside in the @p pdu
        // and we cannot add more of them to the @p unknown
        if(!ok && unknown_filter_full)
            break;

        // Filter odd options types (i.e. critical)
        if (opt_iter.type & 0x01) {

            switch (opt_iter.type) {

                // The implemented critical options
                case COAP_OPTION_IF_MATCH:
                case COAP_OPTION_URI_HOST:
                case COAP_OPTION_IF_NONE_MATCH:
                case COAP_OPTION_URI_PORT:
                case COAP_OPTION_URI_PATH:
                case COAP_OPTION_URI_QUERY:
                case COAP_OPTION_ACCEPT:
                case COAP_OPTION_PROXY_URI:
                case COAP_OPTION_PROXY_SCHEME:
                case COAP_OPTION_BLOCK2:
                case COAP_OPTION_BLOCK1:
                    break;
                // Unknown critical options
                default:
                    // Check whether an option was registered in the context
                    if (coap_option_filter_get(context->known_options, opt_iter.type) == 0) {
                        coap_log(LOG_DEBUG, "unknown critical option %d\n", opt_iter.type);
                        ok = 0;

                        // When no more space for filters in @p unknown, break the loop
                        if (coap_option_filter_set(unknown, opt_iter.type) == 0)
                            unknown_filter_full = true;
                    }
            }
        }
    }

    return ok;
}


coap_tid_t coap_send_ack(coap_session_t *session, coap_pdu_t *request) {

    coap_tid_t result = COAP_INVALID_TID;

    // Send ACK only for CON requests
    if (request && request->type == COAP_MESSAGE_CON) {
        coap_pdu_t *response = coap_pdu_init(COAP_MESSAGE_ACK, 0, request->tid, 0);
        if (response)
            result = coap_send(session, response);
    }
    
    return result;
}


ssize_t coap_session_send_pdu(coap_session_t *session, coap_pdu_t *pdu) {

    // Send a CoAP message using a given @p session 
    ssize_t bytes_written = 
        coap_session_send(session, pdu->token - COAP_HEADER_SIZE, pdu->used_size + COAP_HEADER_SIZE);

    coap_show_pdu(LOG_DEBUG, pdu);
    return bytes_written;
}


coap_tid_t coap_send_error(
    coap_session_t *session,
    coap_pdu_t *request,
    unsigned char code,
    coap_opt_filter_t opts
) {
    assert(request);
    assert(session);

    // Create an error message
    coap_pdu_t *response = coap_new_error_response(request, code, opts);
    coap_tid_t result = COAP_INVALID_TID;

    // Send the message
    if (response)
        result = coap_send(session, response);

    return result;
}


coap_tid_t coap_send_message_type(
    coap_session_t *session, 
    coap_pdu_t *request, 
    unsigned char type
) {
    coap_tid_t result = COAP_INVALID_TID;

    if (request) {
        coap_pdu_t *response = coap_pdu_init(type, 0, request->tid, 0);
        if (response)
            result = coap_send(session, response);
    }
    
    return result;
}


unsigned int coap_calc_timeout(coap_session_t *session, unsigned char random) {

    /**
     * Inner term: multiply ACK_RANDOM_FACTOR by Q0.MAX_BITS[r] and
     * make the result a rounded Qx.FRAC_BITS 
     */
    unsigned int result = SHR_FP((ACK_RANDOM_FACTOR(session) - FP1) * random, MAX_BITS);

    /**
     * Add 1 to the inner term and multiply with ACK_TIMEOUT, then
     * make the result a rounded Qx.FRAC_BITS 
     */
    result = SHR_FP(((result + FP1) * ACK_TIMEOUT(session)), FRAC_BITS);

    /**
     * Multiply with COAP_TICKS_PER_SECOND to yield system ticks
     * (yields a Qx.FRAC_BITS) and shift to get an integer 
     */
    return SHR_FP((COAP_TICKS_PER_SECOND * result), FRAC_BITS);
}


coap_tid_t coap_wait_ack(
    coap_session_t *session,
    coap_queue_t *node
) {
    // Increment session's refere counter
    node->session = coap_session_reference(session);

    /**
     * @note: We need to set timer for pdu retransmission. If this is the first element in
     *    the retransmission queue, the base time is set to the current time and the 
     *    retransmission time is node->timeout. If there is already an entry in the sendqueue,
     *    we must check if this node is to be retransmitted earlier. Therefore, node->timeout
     *    is first normalized to the base time and then inserted into the queue with an adjusted
     *    relative time.
     */

    coap_tick_t now;
    coap_ticks(&now);

    // An empty retransmission queue
    if (session->context->sendqueue == NULL) {
        node->t = node->timeout;
        session->context->sendqueue_basetime = now;
    } 
    // An non-empty retransmission queue (make node->t relative to session->context->sendqueue_basetime )
    else 
        node->t = (now - session->context->sendqueue_basetime) + node->timeout;

    // Add packet to the queue
    coap_insert_node(&session->context->sendqueue, node);

    coap_log(LOG_DEBUG, "** %s: tid=%d added to retransmit queue (%ums)\n",
        coap_session_str(node->session), node->id, (unsigned)(node->t * 1000 / COAP_TICKS_PER_SECOND));

    return node->id;
}


coap_tid_t coap_send(
    coap_session_t *session, 
    coap_pdu_t *pdu
) {
    // Write the header to the pdu's data
    coap_pdu_encode_header(pdu);

    // Send the PDU
    ssize_t bytes_written = coap_send_pdu( session, pdu, NULL );
    // PDU's dispatch was delayed
    if (bytes_written == COAP_PDU_DELAYED)
        return pdu->tid;
    // Error occured
    else if (bytes_written < 0) {
        coap_delete_pdu(pdu);
        return (coap_tid_t) bytes_written;
    }

    // Delete PDU only when it was not put into the retransmission queue (i.e. does not wait for ACK)
    if (pdu->type != COAP_MESSAGE_CON) {
        coap_tid_t id = pdu->tid;
        coap_delete_pdu(pdu);
        return id;
    }

    // Create a new node for the retransmission queue
    coap_queue_t *node = coap_new_node();
    if (!node) {
        coap_log(LOG_DEBUG, "coap_wait_ack: insufficient memory\n");
        goto error;
    }

    // Generate a random seed for timeout's length's generation
    uint8_t random;
    prng(&random, sizeof(random));

    // Initialize the retransmission node
    node->id = pdu->tid;
    node->pdu = pdu;
    node->timeout = coap_calc_timeout(session, random);

    // Put the node to the retransmission queue
    return coap_wait_ack(session, node);

error:
    coap_delete_pdu(pdu);
    return COAP_INVALID_TID;
}


coap_tid_t coap_retransmit(
    coap_context_t *context, 
    coap_queue_t *node
) {
    if (!context || !node)
        return COAP_INVALID_TID;

    // Check if maximum number of retransmissions is not reached yet
    if (node->retransmit_cnt < node->session->max_retransmit) {

        node->retransmit_cnt++;

        coap_tick_t now;
        coap_ticks(&now);

        /**
         * Add the packet's @p node to the context's retransmission queue.
         * 
         * @note: Node's timeout is set to some value contingent on the basic timeout.
         *    It's actual value grows exponentially with respect the number of retransmissions.
         */
        if (context->sendqueue == NULL) {
            node->t = node->timeout << node->retransmit_cnt;
            context->sendqueue_basetime = now;
        }
        // If queue is not empty, make node->t relative to context->sendqueue_basetime
        else
            node->t = (now - context->sendqueue_basetime) + (node->timeout << node->retransmit_cnt);

        coap_insert_node(&context->sendqueue, node);
        coap_log(LOG_DEBUG, "** %s: tid=%d: retransmission #%d\n",
                coap_session_str(node->session), node->id, node->retransmit_cnt);

        // Decrement number of the session's active CON messages waiting for the ACK
        if (node->session->con_active)
            node->session->con_active--;

        /**
         * Retransmit the packet. If PDU was not retransmitted immediately, because a new
         * handshake is in progress, node was delayed. In this case, return the node's ID.
         */
        ssize_t bytes_written = coap_send_pdu(node->session, node->pdu, node);
        if (bytes_written < 0 && bytes_written != COAP_PDU_DELAYED)
            return (int) bytes_written;

        return node->id;
    }

    /* At this point the PDU should not be sent, as the retransmission counter exceeded the limit */

    coap_log(LOG_DEBUG, "** %s: tid=%d: give up after %d attempts\n",
            coap_session_str(node->session), node->id, node->retransmit_cnt);

    /**
     * If the retransmitted message is a response, handle a possile failed subscriber's
     * notification (i.e check if subscriptions exist that should be canceled after
     * because of exceeded number of fail notifications).
     */
    if (node->pdu->code >= COAP_RESPONSE_CODE(200)) {

        coap_binary_t token = { 0, NULL };
        token.length = node->pdu->token_length;
        token.s = node->pdu->token;

        coap_handle_failed_notify(node->session, &token);
    }

    // Decrement number of the session's active CON messages waiting for the ACK
    if (node->session->con_active) {
        node->session->con_active--;

        /**
        * As there may be another CON in a different @p session->delayqueue's entry on the same
        * session that needs to be immediately sent, coap_session_connected() is called. However,
        * there is the possibility that coap_wait_ack() may be called from inside of the
        * coap_session_connect() for the node handled by this coap_retransmit() call. It would
        * cause the entry to be re-added from @p session->delayqueue to @p context->sendqueue.
        * coap_delete_node() called shortly will handle this and remove it.
        */
        if (node->session->state == COAP_SESSION_STATE_ESTABLISHED)
            coap_session_connected(node->session);
    }

    // Call a context-wide NACK handler for the failed retransmission
    if (node->pdu->type == COAP_MESSAGE_CON && context->nack_handler)
        context->nack_handler(context, node->session, node->pdu, COAP_NACK_TOO_MANY_RETRIES, node->id);

    // And finally delete the node
    coap_delete_node(node);
    
    return COAP_INVALID_TID;
}



unsigned int coap_write(
    coap_context_t *context,
    coap_socket_t *sockets[],
    unsigned int max_sockets,
    unsigned int *num_sockets,
    coap_tick_t now
){
    // Set start number of sockets in the @p sockets to 0
    *num_sockets = 0;

    // Notify Observers if the corresponding resource has been changed
    coap_check_notify(context);

    // Set timeout of the sessions that will be used for the data transfer
    coap_tick_t session_timeout;
    if (context->session_timeout > 0)
        session_timeout = context->session_timeout * COAP_TICKS_PER_SECOND;
    else
        session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;

    // Prepare a bunch of working data 
    coap_tick_t timeout = 0;
    coap_queue_t *nextpdu;
    coap_endpoint_t *endpoint;
    coap_session_t *session;
    coap_session_t *session_tmp;

    // Iterate over all endpoints used by the context
    LL_FOREACH(context->endpoint, endpoint) {

        // If the endpoint's socket was marked as read-needing or write-needing ...
        if (endpoint->sock.flags & COAP_SOCKET_WANT_READ) {
            // ... check if more sockets can be used
            if (*num_sockets < max_sockets)
                // If so, hold the socket used by the endpoint
                sockets[(*num_sockets)++] = &endpoint->sock;
        }

        // Iterate over al sessions hold by the endpoint
        LL_FOREACH_SAFE(endpoint->sessions, session, session_tmp) {

            /**
             * If: 
             *   - session is a server session (i.e. it waits to receive data from a client)
             *   - it is not referenced by any transaction (i.e. any transaction in progress does not use the session)
             *   - there are no more packets delayed to send within the session
             *   - time that passed since the last transaction (rx or tx) is greater than session's timeout OR
             *     a session is in a NON state
             * consider the session as unused and free it's resources.+
             */
            if(session->type == COAP_SESSION_TYPE_SERVER && session->ref == 0 && session->delayqueue == NULL &&
               (session->last_rx_tx + session_timeout <= now || session->state == COAP_SESSION_STATE_NONE)){
                coap_session_free(session);
            } 
            // If session is in use ...
            else {
                
                // If the session is of a 'server' type, it's not referred by any current transaction and it has no
                // packets delayed to be sent ...
                if (session->type == COAP_SESSION_TYPE_SERVER && session->ref == 0 && session->delayqueue == NULL) {

                    // Get time remaining to the timeout 
                    coap_tick_t s_timeout = (session->last_rx_tx + session_timeout) - now;

                    // If the remaining time is shorter than the shortes remaining time
                    // from all session that have been already checked
                    if (timeout == 0 || s_timeout < timeout)
                        timeout = s_timeout;
                }
                // If the session's socket was marked as read-needing or write-needing ...
                if (session->sock.flags & COAP_SOCKET_WANT_READ) {
                    // ... check if more sockets can be used
                    if (*num_sockets < max_sockets)
                        // If so, hold the socket used by the endpoint
                        sockets[(*num_sockets)++] = &session->sock;
                }
            }
        }
    }

    // Iterate over all sessions associated with the context
    LL_FOREACH_SAFE(context->sessions, session, session_tmp) {

        // If the context's socket was marked as read-needing or write-needing ...
        if (session->sock.flags & COAP_SOCKET_WANT_READ) {
            // ... check if more sockets can be used
            if (*num_sockets < max_sockets)
                // If so, hold the socket used by the endpoint
                sockets[(*num_sockets)++] = &session->sock;
        }
    }

    /**
     * @note:  Here, we've already checked all of the sockets that potentially 
     *   need to be written or read
     */

    // Get the next packet from the sendqueue 
    nextpdu = coap_peek_next(context);

    /**
     * For all packets in the sendqueue if:
     *    - context's base time lies in the past
     *    - retransmission interval time for the has passed
     * try to retransmit the packet
     */
    while (nextpdu && now >= context->sendqueue_basetime && nextpdu->t <= now - context->sendqueue_basetime) {
        coap_retransmit(context, coap_pop_next(context));
        nextpdu = coap_peek_next(context);
    }

    /**
     * If the time to retransmission the next, packet from the sendqueue (if any) is shorter than the
     * timeout of any of the checked sessions, update the timeout.
     */
    if (nextpdu && (timeout == 0 || nextpdu->t - ( now - context->sendqueue_basetime ) < timeout))
        timeout = nextpdu->t - (now - context->sendqueue_basetime);

    /**
     * @note: 'timeout' is the shortest time for the next packet from context->sendqueue to be retransmited
     *    or the active session to become unactive if no TX/RX will be porformed with it.
     */

    // Return timeout in [ms]
    return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}


void coap_read(
    coap_context_t *context, 
    coap_tick_t now
) {
    coap_endpoint_t *endpoint, *endpoint_tmp;
    coap_session_t *session, *session_tmp;

    // Iterate over all endpoints registered in the @p context 
    LL_FOREACH_SAFE(context->endpoint, endpoint, endpoint_tmp) {

        // Let the endpoint receive the data, if needed
        if ((endpoint->sock.flags & COAP_SOCKET_CAN_READ) != 0)
            coap_read_endpoint(endpoint, now);

        // Iterate over all sessions hold by the endpoint
        LL_FOREACH_SAFE(endpoint->sessions, session, session_tmp) {

            /**
             * @note: Incrementing of session's reference counter before and decrementing
             *    it after the read/write is performed to make sure, that the session object
             *    is not deleted in one of the callbacks.
             */

            //Let the session receive the data, if needed.
            if ((session->sock.flags & COAP_SOCKET_CAN_READ) != 0) {
                coap_session_reference(session);
                coap_read_session(session, now);
                coap_session_release(session);
            }

        }
    }

    // Iterate over all sessions hold by the @p context
    LL_FOREACH_SAFE(context->sessions, session, session_tmp) {

        /**
         * @note: Incrementing of session's reference counter before and decrementing
         *    it after the read/write is performed to make sure, that the session object
         *    is not deleted in one of the callbacks.
         */

        //Let the session receive the data, if needed.
        if ((session->sock.flags & COAP_SOCKET_CAN_READ) != 0) {
            coap_session_reference(session);
            coap_read_session(session, now);
            coap_session_release(session);
        }
    }
}


int coap_handle_dgram(
    coap_session_t *session,
    uint8_t *msg,
    size_t msg_len
) {
    // Create a new PDU object
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, msg_len - COAP_HEADER_SIZE);
    if (!pdu)
        goto error;

    // Parse the @p msg buffer to get the informations about the PDU
    if (!coap_pdu_parse(msg, msg_len, pdu)) {
        coap_log(LOG_WARNING, "discard malformed PDU\n");
        goto error;
    }

    // Dispatch the message and send the response
    coap_dispatch(session, pdu);

    // Clean the PDU up
    coap_delete_pdu(pdu);

    return 0;

error:
    // [TODO] Send a (?) RST message back
    coap_delete_pdu(pdu);
    return -1;
}


int coap_remove_from_queue(
    coap_queue_t **queue, 
    coap_session_t *session, 
    coap_tid_t id, 
    coap_queue_t **removed_node
) {
    if (!queue || !*queue)
        return 0;

    // Check whether the searched node is located at the head of the @p queue
    if (session == (*queue)->session && id == (*queue)->id) {
        
        // Detach the head from the rest of the queue
        *removed_node = *queue;
        (*removed_node)->next = NULL;

        // Update the queue's head
        *queue = (*queue)->next;
        
        // Adjust relative time of new queue's head
        if (*queue)
            (*queue)->t += (*removed_node)->t;
    
        coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                coap_session_str(session), id);
        return 1;
    }

    coap_queue_t *p, *q;

    // Iterate over the rest of the queue
    LL_FOREACH_SAFE(*queue, p, q){

        // If the node is found
        if (q && session == q->session && id == q->id){

            // Detach the node from the rest of the queue
            p->next = q->next;
            q->next = NULL;

            // Adjust relative time of the node following the detached one
            if (p->next)
                p->next->t += q->t;

            // Return the remove node to the caller
            *removed_node = q;

            coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                coap_session_str(session), id);

            return 1;

        }
    }

    return 0;
}


void coap_cancel_session_messages(
    coap_session_t *session,
    coap_nack_reason_t reason
) {
    coap_queue_t *p, *q;

    // Iterate over the head nodes of the @p context->sendqueue and delete all associated with the @p session
    while (session->context->sendqueue && session->context->sendqueue->session == session) {

        // Detach the head from the queue
        q = session->context->sendqueue;

        // Update queue's head
        session->context->sendqueue = q->next;

        // Call the NACK handler if the node represented the CON message
        if (q->pdu->type == COAP_MESSAGE_CON && session->context->nack_handler)
            session->context->nack_handler(session->context, session, q->pdu, reason, q->id);

        coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                coap_session_str(session), q->id);
                
        // Delete the node itself
        coap_delete_node(q);
    }

    // Check whether the queue is empty yet
    if (!session->context->sendqueue)
        return;

    // Iterate over the rest of nodes
    LL_FOREACH_SAFE(session->context->sendqueue, p, q){
        
        // If the node is associated with a session
        if(q && q->session == session){
            
            // Detach the node from the queue
            p->next = q->next;

            // Call the NACK handler if the node represented the CON message
            if (q->pdu->type == COAP_MESSAGE_CON && session->context->nack_handler)
                session->context->nack_handler(session->context, session, q->pdu, reason, q->id);

            coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                    coap_session_str(session), q->id);

            // Delete the node itself
            coap_delete_node(q);
        }
    }
}


void coap_cancel_all_messages(
    coap_session_t *session,
    const uint8_t *token, 
    size_t token_length
) {
    coap_queue_t *p, *q;
    
    bool token_matches = false;
    if(session->context->sendqueue && session->context->sendqueue->session == session)
        token_matches = 
            token_match(token, token_length, session->context->sendqueue->pdu->token, session->context->sendqueue->pdu->token_length);

    // Iterate over the head nodes of the @p session->context->sendqueue and delete all associated with the @p session
    while (session->context->sendqueue && session->context->sendqueue->session == session && token_matches) {

        // Detach the head from the queue
        q = session->context->sendqueue;

        // Update queue's head
        session->context->sendqueue = q->next;

        coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                coap_session_str(session), q->id);
                
        // Delete the node itself
        coap_delete_node(q);

        // Check the token match for the next node
        if(session->context->sendqueue)
            token_matches = token_match(
                token, 
                token_length, 
                session->context->sendqueue->pdu->token, 
                session->context->sendqueue->pdu->token_length
            );
    }

    // Check whether the queue is empty yet
    if (!session->context->sendqueue)
        return;

    p = session->context->sendqueue;
    q = p->next;

    // Iterate over the rest of nodes
    LL_FOREACH_SAFE(session->context->sendqueue, p, q){

        if(q)
            token_matches = token_match(token, token_length, q->pdu->token, q->pdu->token_length);
        
        // If the node is associated with a session
        if(q && q->session == session && session->context->sendqueue->session == session && token_matches){
            
            // Detach the node from the queue
            p->next = q->next;

            coap_log(LOG_DEBUG, "** %s: tid=%d: removed\n",
                    coap_session_str(session), q->id);
                    
            // Delete the node itself
            coap_delete_node(q);

            // Check the token match for the next node
            if(session->context->sendqueue)
                token_matches = token_match(
                    token, 
                    token_length, 
                    session->context->sendqueue->pdu->token, 
                    session->context->sendqueue->pdu->token_length
                );
        }
    }
}


coap_queue_t *coap_find_transaction(
    coap_queue_t *queue, 
    coap_session_t *session, 
    coap_tid_t id
) {
    while (queue && queue->session != session && queue->id != id)
        queue = queue->next;

    return queue;
}


coap_pdu_t *coap_new_error_response(
    coap_pdu_t *request, 
    unsigned char code,  
    coap_opt_filter_t opts_filter
) {
    assert(request);

    // Size of the whole response PDU
    size_t size = request->token_length;

#if COAP_ERROR_PHRASE_LENGTH > 0

    /**
     * Create a short human-readable paylod describing the error. Count one
     * more byte for the payload marker
     */
    const char *phrase = coap_response_phrase(code);
    if (phrase)
        size += strlen(phrase) + 1;

#endif

    // Establish response message's type
    unsigned char type = 
        (request->type == COAP_MESSAGE_CON) ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON;

    // Make sure, that the CONTENT_TYPE option will not be included in the response
    coap_option_filter_unset(opts_filter, COAP_OPTION_CONTENT_TYPE);

    // Initialize options iterator for the request PDU
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(request, &opt_iter, opts_filter);
    
    // Value used for calculating a new delta-storage codes of the options
    uint16_t opt_type = 0;

    // Estimate how much space is required for options to copy from the request
    coap_opt_t *option;
    while ((option = coap_option_next(&opt_iter))) {

        // Calculate space required for option code's delta encoding
        uint16_t delta = opt_iter.type - opt_type;
        if (delta < 13)
            size += 1;
        else if (delta < 269)
            size += 2;
        else
            size += 3;

        size += coap_opt_length(option);

        // Calculate space required for option's length encoding
        switch (*option & 0x0f) {
            case 0x0e:
                size += 2;
                break;
            case 0x0d:
                size += 1;
                break;
        }

        opt_type = opt_iter.type;
    }

    // Create the response and fill it with options and payload data
    coap_pdu_t *response = coap_pdu_init(type, code, request->tid, size);
    if (response) {
    
        // Copy token from the request
        if (!coap_add_token(response, request->token_length, request->token)) {
            coap_log(LOG_DEBUG, "cannot add token to error response\n");
            coap_delete_pdu(response);
            return NULL;
        }

        // Copy all options (after filtering)
        coap_option_iterator_init(request, &opt_iter, opts_filter);
        while ((option = coap_option_next(&opt_iter))) {
            coap_add_option(
                response, 
                opt_iter.type,
                coap_opt_length(option),
                coap_opt_value(option)
            );
        }

#if COAP_ERROR_PHRASE_LENGTH > 0
        // Add the diagnostick payload
        if (phrase)
            coap_add_data(response, (size_t)strlen(phrase), (const uint8_t *)phrase);
#endif

    }

    return response;
}


coap_pdu_t *coap_wellknown_response(
    coap_session_t *session,
    coap_pdu_t *request
) {

    // Create a response PDU
    coap_pdu_t *resp = coap_pdu_init(
        (request->type == COAP_MESSAGE_CON) ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON,
        COAP_RESPONSE_CODE(205),
        request->tid, 
        coap_session_max_pdu_size(session)
    );
    if (!resp) {
        coap_log(LOG_DEBUG, "coap_wellknown_response: cannot create PDU\n");
        return NULL;
    }

    // Add the token to the PDU
    if (!coap_add_token(resp, request->token_length, request->token)) {
        coap_log(LOG_DEBUG, "coap_wellknown_response: cannot add token\n");
        goto error;
    }

    // Check whether a query filter was attached with the request for /.well-known/core (so called 'wkc')
    coap_opt_iterator_t opt_iter;
    coap_opt_t *query_filter = coap_check_option(request, COAP_OPTION_URI_QUERY, &opt_iter);

    // Calculate wkc representation's length
    size_t wkc_len = get_wkc_len(session->context, query_filter);

    // As the value of some resources is undefined get_wkc_len() can return 0
    if (wkc_len == 0) {
        // Answer with error code 4.00 (Bad Request)
        resp->code = COAP_RESPONSE_BAD_REQUEST;
        resp->used_size = resp->token_length;
        coap_log(LOG_DEBUG, "coap_wellknown_response: undefined resource\n");
        return resp;
    }

    // Flag that is set to 1, when Block2 option is requested
    int need_block2 = 0;

    /**
     * If the wkc resource is requested with Block2 option, this
     * function will be called every time the next block is to be sent.
     * The @v offset will hold the byte-offset in the wkc representation's
     * buffer that the current Block2 response's payload should start at. 
     */
    size_t offset = 0;

    // Check whether the request contains the Block2 option
    coap_block_t block;
    if (coap_get_block(request, COAP_OPTION_BLOCK2, &block)) {
        
        coap_log(LOG_DEBUG, "coap_wellknown_response: create block\n");

        // Compute the offset of the requested wkc representation's block
        offset = block.num << (block.szx + 4);

        // Validate the SZX field of the option
        if (block.szx > 6) {
            resp->code = COAP_RESPONSE_BAD_OPTION;
            return resp;
        } 
        // If the SZX is valid, but bigger than the implemented one, cut the block's size
        else if (block.szx > COAP_MAX_BLOCK_SZX) {
            block.szx = COAP_MAX_BLOCK_SZX;
            // Update block's number according to the new block's size
            block.num = (unsigned int)(offset >> (block.szx + 4));
        }

        need_block2 = 1;
    }

    /**
     * Check if there is sufficient space to add Content-Format option
     * and data. We do this before adding the Content-Format option to
     * avoid sending error responses with that option but no actual
     * content. 
     */
    if (resp->max_size && resp->max_size <= resp->used_size + 3) {
        coap_log(LOG_DEBUG, "coap_wellknown_response: insufficient storage space\n");
        goto error;
    }

    // Add Content-Format option to the response
    uint8_t buf[2];
    coap_add_option(
        resp, 
        COAP_OPTION_CONTENT_FORMAT,
        coap_encode_var_safe(buf, sizeof(buf), COAP_MEDIATYPE_APPLICATION_LINK_FORMAT), 
        buf
    );

    // Check if Block2 option is required even if not requested 
    if (!need_block2 && resp->max_size && resp->max_size - resp->used_size < wkc_len + 1) {
        
        /**
         * @note: '+1' in the condition's check refers to the payload marker
         */

        // Compute a free space for the payload
        const size_t payload_len = resp->max_size - resp->used_size;

        // Initialize the block
        block.num = 0;
        block.m = 0;     
        block.szx = COAP_MAX_BLOCK_SZX;

        /**
         * @note: The M bit is set by coap_write_block_opt()
         */

        // Compute required block size
        while (payload_len < SZX_TO_BYTES(block.szx) + 6) {
            if (block.szx == 0) {
                coap_log(LOG_DEBUG, "coap_wellknown_response: message to small even for szx == 0\n");
                goto error;
            } else
                block.szx--;
        }

        need_block2 = 1;
    }

    // Write Block2 option, if necessary.
    if (need_block2) {
        if (coap_write_block_opt(&block, COAP_OPTION_BLOCK2, resp, wkc_len) < 0) {
            coap_log(LOG_DEBUG, "coap_wellknown_response: cannot add Block2 option\n");
            goto error;
        }
    }

    /* -------------- Compute payload's length -------------- */
    
    size_t payload_len = 0;

    // Block2 was requested and more block will be required
    if(need_block2 && block.m)
        payload_len = SZX_TO_BYTES(block.szx);
    // Block2 was requested and the last block is to be sent
    else if(need_block2 && !block.m)
        payload_len = wkc_len - offset;
    // Block2 was NOT requesed but the PDU cannot transport the whole wkc's representation
    else if(resp->max_size && resp->used_size + wkc_len + 1 > resp->max_size) 
        payload_len = resp->max_size - resp->used_size - 1;
    // Block2 wa NOT requested and the whole wkc's representation will be sent
    else
        payload_len = wkc_len;

    /**
     * @note: '-1' elements refer to payload's marker that will be added at coap_add_data_after()
     */
        
    // Add the payload marker to the PDU
    uint8_t *data = coap_add_data_after(resp, payload_len);
    if (!data) {
        coap_log(LOG_DEBUG, "coap_wellknown_response: coap_add_data failed\n" );
        goto error;
    }

    // Add the data itself
    int result = coap_print_wellknown(session->context, data, &payload_len, offset, query_filter);
    if ((result & COAP_PRINT_STATUS_ERROR) != 0) {
        coap_log(LOG_DEBUG, "coap_print_wellknown failed\n");
        goto error;
    }

    return resp;

error:
    // Set error code 5.03 (Service Unavailable) and remove all options and data from response
    resp->code = COAP_RESPONSE_SERVICE_UNAVAILABLE;
    resp->used_size = resp->token_length;
    return resp;
}


void coap_dispatch(
    coap_session_t *session,
    coap_pdu_t *pdu
) {

#ifndef NDEBUG
    // Log some debug infos about the received PDU
    if (LOG_DEBUG <= coap_get_log_level()) {

        #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 40
        #endif

        unsigned char addr[INET6_ADDRSTRLEN + 8], localaddr[INET6_ADDRSTRLEN + 8];

        // Format source and destination address to strings
        size_t remote_result = coap_print_addr(&(session->remote_addr), addr, INET6_ADDRSTRLEN + 8);
        size_t local_result = coap_print_addr(&(session->local_addr), localaddr, INET6_ADDRSTRLEN + 8);

        // Print the log
        if (remote_result && local_result)
            coap_log(LOG_DEBUG, "** received %d bytes from %s on interface %s:\n", (int) (pdu->used_size + COAP_HEADER_SIZE), addr, localaddr);

        // Print the PDU's description
        coap_show_pdu(LOG_DEBUG, pdu);
    }
#endif

    // Initialize options' filter (it's used to look for critical unknown options in the request)
    coap_opt_filter_t opt_filter;
    memset(opt_filter, 0, sizeof(coap_opt_filter_t));

    // Response PDU
    coap_pdu_t *response;
    // Holder for an entry of the @p context->sendqueue that will be removed if ACK/RST message was received
    coap_queue_t *sent = NULL;

    // Dispatch the message with respect to it's type
    switch (pdu->type) {
        case COAP_MESSAGE_ACK: // ACK Message

            // Find transaction in a sendqueue and remove it to stop retransmission
            coap_remove_from_queue(&session->context->sendqueue, session, pdu->tid, &sent);

            // Update the number of CON messages waiting for ACK
            if (session->con_active) {
                session->con_active--;
                // Flush out any entries on @p session->delayqueue
                if (session->state == COAP_SESSION_STATE_ESTABLISHED)
                    coap_session_connected(session);
            }

            // Skip an Empty message
            if (pdu->code == 0)
                goto cleanup;

            /**
             * If sent code was >= 64 (i.e. >= 2.00: a response code) the message might have
             * been a notification. If so, we must flag the observer to be alive by setting 
             * obs->fail_cnt = 0. 
             */
            if (sent && COAP_RESPONSE_CLASS(sent->pdu->code) == 2) {
                const coap_binary_t token =
                    { sent->pdu->token_length, sent->pdu->token };
                coap_touch_observer(sent->session, &token);
            }
            
            break;

        case COAP_MESSAGE_RST: // RST Message

            /**
             * @note: As we have sent something the receiver disliked, we need to remove
             * not only the transaction but also the subscriptions we might have. 
             */

            coap_log(LOG_ALERT, "got RST for message %d\n", pdu->tid);
            
            // Update the number of CON messages waiting for ACK
            if (session->con_active) {
                session->con_active--;
                // Flush out any entries on @p session->delayqueue
                if (session->state == COAP_SESSION_STATE_ESTABLISHED)
                    coap_session_connected(session);
            }

            // Find transaction in sendqueue and delete it to stop retransmission
            coap_remove_from_queue(&session->context->sendqueue, session, pdu->tid, &sent);

            // If a message was removed from the queue...
            if (sent) {
                
                // Cancel outstanding messages related to the sender. Remove any observation relationship for them.
                coap_cancel(session->context, sent);

                // Call a NACK handler, if present
                if(sent->pdu->type==COAP_MESSAGE_CON && session->context->nack_handler)
                    session->context->nack_handler(session->context, sent->session, sent->pdu, COAP_NACK_RST, sent->id);
            }
            
            goto cleanup;

        case COAP_MESSAGE_NON: // NON Message
        
            // Check for unknown critical options. If present, silently discard the message
            if (coap_option_check_critical(session->context, pdu, opt_filter) == 0)
                goto cleanup;
        
            break;

        case COAP_MESSAGE_CON: // CON Message
            
            // Check for unknown critical options. If present, create an appropriate response
            if (coap_option_check_critical(session->context, pdu, opt_filter) == 0) {

               // If we received the request, send an error response
               if(pdu->code < COAP_RESPONSE_200) {
                
                   // Create the response
                    response = coap_new_error_response(pdu, COAP_RESPONSE_CODE(402), opt_filter);
                    if (!response)
                        coap_log(LOG_WARNING, "coap_dispatch: cannot create error response\n");
                    else if (coap_send(session, response) == COAP_INVALID_TID)
                        coap_log(LOG_WARNING, "coap_dispatch: error sending response\n");
                }
                // If we received the response, send an RST
                else
                    if (coap_send_message_type(session, pdu, COAP_MESSAGE_RST) == COAP_INVALID_TID)
                        coap_log(LOG_WARNING, "coap_dispatch: error sending response\n");
                
                goto cleanup;
            }
            break;
    }

    // Pass message to upper layer if a specific handler was registered for a request that should be handled locally.
    if (COAP_PDU_IS_REQUEST(pdu))
        handle_request(session, pdu);
    else if (COAP_PDU_IS_RESPONSE(pdu))
        handle_response(session, sent ? sent->pdu : NULL, pdu);
    // Otherwise, the message is invalid or is of the empty type
    else {

        // If the message is empty, call the PING handler (if registered)
        if (COAP_PDU_IS_EMPTY(pdu)){
            if (session->context->ping_handler)
                session->context->ping_handler(session->context, session, pdu, pdu->tid);
        } else
            coap_log(LOG_DEBUG, "dropped message with invalid code (%d.%02d)\n", COAP_RESPONSE_CLASS(pdu->code), pdu->code & 0x1f);

        // For non-multi-cast message ...
        if (!coap_is_mcast(&session->local_addr)) {

            // If the message is empty, send the RST response only if the last RST sent earlier than some configured time span
            if (COAP_PDU_IS_EMPTY(pdu)) {
                
                coap_tick_t now;
                coap_ticks(&now);

                if (session->last_tx_rst + COAP_TICKS_PER_SECOND / MAX_RST_FREQ < now) {
                    coap_send_message_type(session, pdu, COAP_MESSAGE_RST);
                    session->last_tx_rst = now;
                }
            }
            // Otherwise, send RST response anyway
            else
                coap_send_message_type(session, pdu, COAP_MESSAGE_RST);
        }
    }

cleanup:
    coap_delete_node(sent);
}


int coap_can_exit(coap_context_t *context) {
    
    if (!context)
        return 1;
    if (context->sendqueue)
        return 0;

    coap_endpoint_t *endpoint;
    coap_session_t *session;

    // Check if any endpoint's session has packet's scheduled to be sent
    LL_FOREACH(context->endpoint, endpoint)
        LL_FOREACH(endpoint->sessions, session)
            if (session->delayqueue)
                return 0;

    // Check if any context's session has packet's scheduled to be sent
    LL_FOREACH(context->sessions, session)
        if (session->delayqueue)
            return 0;
            
    return 1;
}


void coap_startup(void) {

    static int coap_started = 0;

    // Check if libcoap has been initialized yet
    if (coap_started)
      return;

    // Denote library's initialization
    coap_started = 1;

    // Initialize the library-internal clock
    coap_clock_init();

    // Initialize RNG
    prng_init(0);
}

void coap_cleanup(void) {}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */


COAP_STATIC_INLINE coap_queue_t *coap_malloc_node(void) {
    return (coap_queue_t *) coap_malloc(sizeof(coap_queue_t));
}


COAP_STATIC_INLINE void coap_free_node(coap_queue_t *node) {
    coap_free(node);
}


/**
 * @brief: Tries to send the @p pdu using @p session. If a message cannot be sent,
 *    it is delayed. If @p node is not NULL, it has to point to the entry in the
 *    @p session->delayqueue that will be re-placed in the queue instead of creating
 *    a new node for the @p pdu (when delayed)
 * 
 * @param session:
 *    session to send with
 * @param pdu:
 *    pdu to be sent
 * @param node:
 *    (optional) entry in the @p session->delayqueue that will be re-paced in the
 *    queue when the @p pdu would be delayed
 * @return
 *    number of bytes dent on succedd
 *    @c COAP_PDU_DELAYED when @p pdu was delayed
 *    @c COAP_DROPPED_RESPONSE when tries to send a broadcast response
 *    @c COAP_INVALID_TID when @p pdu could not be delayed
 *    <= 0 when session is not connected
 *    
 */
static ssize_t coap_send_pdu(
    coap_session_t *session, 
    coap_pdu_t *pdu, 
    coap_queue_t *node
) {
    // Do not send error responses for requests that were received via IP multicast.
    if (coap_is_mcast(&session->local_addr) && COAP_RESPONSE_CLASS(pdu->code) > 2)
        return COAP_DROPPED_RESPONSE;

    /**
     * @todo: If No-Response option indicates interest, these responses must not be dropped. 
     */

    // Unconnected session cannoct be used to send
    if (session->state == COAP_SESSION_STATE_NONE)
        return -1;

    // If session cannot hold more CON messages open, delay the pdu for later send 
    if (pdu->type == COAP_MESSAGE_CON && session->con_active >= COAP_DEFAULT_NSTART)
        return coap_session_delay_pdu(session, pdu, node);

    // Increment counter of the open CON messages hold by the session
    if (pdu->type == COAP_MESSAGE_CON)
        session->con_active++;

    // Send the PDU
    return coap_session_send_pdu(session, pdu);
}


/**
 * @brief: Reads data from the socket associated with the @p session. Calls 
 *    coap_handle_dgram() if the reading was succesfull
 * 
 * @param session:
 *    session to read from
 * @param now:
 *    timestamp for the session's RX/TX
 */
static void coap_read_session(
    coap_session_t *session, 
    coap_tick_t now
) {
    assert(session->sock.flags & (COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST));
   
    coap_packet_t packet;

    // Make copies of session's addresses
    coap_packet_set_addr(&packet, &session->remote_addr, &session->local_addr);

    // Read data from the socket associated with the session
    ssize_t bytes_read = session->context->network_read(&session->sock, &packet);

    // If reading failed
    if (bytes_read < 0) {
        // If address is unreachable, disconnect the session
        if (bytes_read == -2)
            coap_session_disconnected(session, COAP_NACK_RST);
        // Else, log error
        else
            coap_log(LOG_WARNING, "*  %s: read error\n", coap_session_str(session));
    }
    // Else, if reading succeded
    else if (bytes_read > 0) {
        
        coap_log(LOG_DEBUG, "*  %s: received %lu bytes\n", coap_session_str(session), (unsigned long) bytes_read);

        // Update RX/TX timestamp
        session->last_rx_tx = now;

        // Reset the packet's address in case it was modified by network_read() 
        coap_packet_set_addr(&packet, &session->remote_addr, &session->local_addr);

        // Handle the received datagram
        coap_handle_dgram(session, packet.payload, packet.length);
    }
}


/**
 * @brief: This function should be called when the underleaying socket is ready to read.
 *    Function handles incoming datagram sending a response, if needed.
 * 
 * @param endpoint:
 *    endopint to read
 * @param now:
 *    timestamp for the session
 * @returns:
 *    0, if message was handle successfully
 *    <= 0, otherwise
 */
static int coap_read_endpoint(coap_endpoint_t *endpoint, coap_tick_t now) {

    assert(endpoint->sock.flags & COAP_SOCKET_BOUND);

    // Initialize the packet object to read to
    coap_packet_t packet;
    coap_address_init(&packet.src);
    coap_address_copy(&packet.dst, &endpoint->bind_addr);

    // perform the read reading
    ssize_t bytes_read = endpoint->context->network_read(&endpoint->sock, &packet);

    // The value to be returned 
    int result = -1;

    // If failed, print a log
    if (bytes_read < 0)
        coap_log(LOG_WARNING, "*  %s: read failed\n", coap_endpoint_str(endpoint));
    // Othwerwise, if succeeded, handle the message
    else if (bytes_read > 0) {

        // Get / Create a session for the message
        coap_session_t *session = coap_endpoint_get_session(endpoint, &packet, now);
        if (session) {
            coap_log(LOG_DEBUG, "*  %s: received %lu bytes\n", coap_session_str(session), (unsigned long) bytes_read);
            result = coap_handle_dgram(session, packet.payload, packet.length);
        }
    }

    return result;
}


COAP_STATIC_INLINE int token_match(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen) {
    return alen == blen && (alen == 0 || memcmp(a, b, alen) == 0);
}


/**
 * @brief: Quick hack to determine the size of the resource description for /.well-known/core.
 * 
 * @param context:
 *    context associated with the resource
 * @param query_filter:
 *    client's filters sent with the request
 * @returns:
 *    length of the representation on success
 *    0 on failure
 */
COAP_STATIC_INLINE size_t get_wkc_len(coap_context_t *context, coap_opt_t *query_filter) {
  
    size_t len = 0;
    unsigned char buf[1];

    // Call coap_print_wellknown() with UINT_MAX offset to skip printing the representation into the buffer
    if (coap_print_wellknown(context, buf, &len, UINT_MAX, query_filter) & COAP_PRINT_STATUS_ERROR) {
        coap_log(LOG_WARNING, "cannot determine length of /.well-known/core\n");
        return 0;
    }

    coap_log(LOG_DEBUG, "get_wkc_len: coap_print_wellknown() returned %lu\n", (unsigned long) len);

    return len;
}


/**
 * @brief: Cancels outstanding messages for the session and token specified in @p sent. Any
 *    observation relationship for @p sent->session and the token are removed. Calling this
 *    function is required when receiving an RST message (usually in response to a notification)
 *    or a GET request with the Observe option set to 1.
 *
 * @param context:
 *    context holding the @p sent node (or a session holding the node)
 * @param sent:
 *    entry in the queue that represents connection to be canceled
 * @returns:
 *    @c 0 when the token is unknown with this peer
 *    a value greater than zero otherwise
 */
static int coap_cancel(coap_context_t *context, const coap_queue_t *sent) {

    // The number of observers cancelled 
    int num_cancelled = 0;

    // Token identifying the message
    coap_binary_t token = { 0, NULL };
    COAP_SET_STR(&token, sent->pdu->token_length, sent->pdu->token);

    // Iterate over all resources registered in the context
    RESOURCES_ITER(context->resources, resource) {

        // Remove observers, if message matched
        num_cancelled += coap_delete_observer(resource, sent->session, &token);

        // Cancell all oustanding messages, if message matched
        coap_cancel_all_messages(sent->session, token.s, token.length);
    }

    return num_cancelled;
}


/**
 * @brief: Checks for No-Response option in given @p request and returns @c 1 if 
 *    @p response should be suppressed according to RFC 7967.
 *
 *    The value of the No-Response option is encoded as follows:
 *   
 *     +-------+-----------------------+-----------------------------------+
 *     | Value | Binary Representation |          Description              |
 *     +-------+-----------------------+-----------------------------------+
 *     |   0   |      <empty>          | Interested in all responses.      |
 *     +-------+-----------------------+-----------------------------------+
 *     |   2   |      00000010         | Not interested in 2.xx responses. |
 *     +-------+-----------------------+-----------------------------------+
 *     |   8   |      00001000         | Not interested in 4.xx responses. |
 *     +-------+-----------------------+-----------------------------------+
 *     |  16   |      00010000         | Not interested in 5.xx responses. |
 *     +-------+-----------------------+-----------------------------------+
 *
 * @param request:
 *    the CoAP request to check for the No-Response option; must not be NULL.
 * @param response:
 *    the response that is potentially suppressed; must not be NULL.
 * @returns:
 *    @c RESPONSE_DEFAULT when no special treatment is requested
 *    @c RESPONSE_DROP when the response must be discarded
 *    @c RESPONSE_SEND when the response must be sent
 */
static enum respond_t no_response(
    coap_pdu_t *request, 
    coap_pdu_t *response
) {
    assert(request);
    assert(response);

    // If response's code is valid
    if (COAP_RESPONSE_CLASS(response->code) > 0) {

        // Check if @p request contains a No-Response option
        coap_opt_iterator_t opt_iter;
        coap_opt_t *nores = coap_check_option(request, COAP_OPTION_NORESPONSE, &opt_iter);

        // If contains ...
        if (nores) {

            // Decode the option's value from bytes-vector into the integer number
            unsigned int val = coap_decode_var_bytes(coap_opt_value(nores), coap_opt_length(nores));

            /**
             * The response should be dropped when the bit corresponding to the 
             * response class is set (cf. table in function documentation).
             * When a No-Response option is present and the bit is not set,
             * the sender explicitly indicates interest in this response. 
             */
            if (((1 << (COAP_RESPONSE_CLASS(response->code) - 1)) & val) > 0)
                return RESPONSE_DROP;
            else
                return RESPONSE_SEND;
        }
    }

    /** 
     * Default behavior applies when we are not dealing with a response 
     * (class == 0) or the request did not contain a No-Response option. 
     */
    return RESPONSE_DEFAULT;
}


/**
 * @brief: Complex handler of the incoming request
 * 
 * @param context:
 *    context holding the resources
 * @param session:
 *    session that the @p pdu was received with
 * @param pdu:
 *    the request
 */
static void handle_request(
    coap_session_t *session, 
    coap_pdu_t *pdu
) {
    /**
     * The respond field indicates whether a response must be treated
     * specially due to a No-Response option that declares disinterest
     * or interest in a specific response class. DEFAULT indicates that
     * No-Response has not been specified. 
     */
    enum respond_t respond = RESPONSE_DEFAULT;

    // Initialize option's filter used fot pdu's options parsing
    coap_opt_filter_t opt_filter;
    coap_option_filter_clear(opt_filter);

    // Try to find the resource from the request URI 
    coap_string_t *uri_path = coap_get_uri_path(pdu);
    if (!uri_path)
        return;
    
    // Get the requested resource
    coap_str_const_t uri_path_c = { uri_path->length, uri_path->s };
    coap_resource_t *resource = coap_get_resource_from_uri_path(session->context, &uri_path_c);

    coap_pdu_t *response = NULL;
    
    // Handle an unknown resource
    if ((resource == NULL) || (resource->is_unknown == 1)) {

        /**
         * The resource was not found or there is an unexpected match against the resource defined
         * for handling unknown URIs. Check if the request URI happens to be the well-known URI,
         * if the unknown resource handler is defined, a PUT or optionally other methods, if configured,
         * for the unknown handler.
         *
         * --> If well-known URI generate a default response
         *
         * --> Else, if unknown URI handler defined, call the unknown URI handler (to allow for
         *     potential generation of resource [RFC7272 5.8.3]) if the appropriate method is defined.
         *
         * --> Else if DELETE, return 2.02 (RFC7252: 5.8.4.  DELETE)
         *
         * --> Else, return 4.04 
         */

        // Check whether the URI fits /.well-known/core (wkc)
        if (coap_string_equal(uri_path, &coap_default_uri_wellknown)) {
            // Get the wkc
            if (pdu->code == COAP_REQUEST_GET) {
                coap_log(LOG_INFO, "create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
                response = coap_wellknown_response(session, pdu);
            } 
            // Another methods are not allowed on the wkc
            else {
                coap_log(LOG_DEBUG, "handle_request: method not allowed for .well-known/core\n");
                response = coap_new_error_response(pdu, COAP_RESPONSE_CODE(405), opt_filter);
            }
        } 
        // The unknown resource was requested
        else if (( session->context->unknown_resource != NULL ) && 
                 ( (size_t)pdu->code - 1 < ( sizeof(resource->handler) / sizeof(coap_method_handler_t)) ) &&
                 ( session->context->unknown_resource->handler[pdu->code - 1] )
        ) {
            /**
             * The unknown_resource can be used to handle undefined resources for a PUT request
             * and can support any other registered handler defined for it. Example set up code:
             * 
             * @code
             *   r = coap_resource_unknown_init(hnd_put_unknown);
             *   coap_register_handler(r, COAP_REQUEST_POST, hnd_post_unknown);
             *   coap_register_handler(r, COAP_REQUEST_GET, hnd_get_unknown);
             *   coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_unknown);
             *   coap_add_resource(ctx, r);
             * @endcode
             * 
             * @note: It is not possible to observe the unknown_resource, a separate resource must
             *    be created (by PUT or POST) which has a GET handler to be observed
             */
            resource = session->context->unknown_resource;
        } 
        // Request for DELETE on non-existant resource (RFC7252: 5.8.4. DELETE) 
        else if (pdu->code == COAP_REQUEST_DELETE) {

            coap_log(LOG_DEBUG, "handle_request: request for unknown resource '%*.*s', return 2.02 \n",
                (int)uri_path->length, (int)uri_path->length, uri_path->s);
            response = coap_new_error_response(pdu, COAP_RESPONSE_DELETED, opt_filter);
        }
        // For request for any another resource, return 4.04 (Not Found)
        else {
            coap_log(LOG_DEBUG, "request for unknown resource '%*.*s', return 4.04\n",
                (int)uri_path->length, (int)uri_path->length, uri_path->s);
            response = coap_new_error_response(pdu, COAP_RESPONSE_NOT_FOUND, opt_filter);
        }

        // If an unknown resource was found (i.e. was created with unknown handler)
        if (!resource){
            // Send the response to the request
            if (response && (no_response(pdu, response) != RESPONSE_DROP))
                if (coap_send(session, response) == COAP_INVALID_TID)
                    coap_log(LOG_WARNING, "handle_request: cannot send response for transaction %u\n", pdu->tid);
        }
        else
            coap_delete_pdu(response);

        response = NULL;

        // Free the allocated string
        coap_delete_string(uri_path);

        return;
    
    }

    /* ------------------------ The resource was found ------------------------ */

    // Check if the handler was registered
    coap_method_handler_t handler = NULL;
    if ((size_t)pdu->code - 1 < sizeof(resource->handler) / sizeof(coap_method_handler_t))
        handler = resource->handler[pdu->code - 1];

    // If handler was registered ...
    if (handler) {
        
        // Parse the query
        coap_string_t *query = coap_get_query(pdu);
        // Mark that the query string was not taken over by the subscriber's object
        int owns_query = 1;

        coap_log(LOG_DEBUG, "handle_request: call custom handler for resource '%*.*s'\n",
            (int)resource->uri_path->length, (int)resource->uri_path->length, resource->uri_path->s);

        // Create the response PDU
        response = coap_pdu_init(
            pdu->type == COAP_MESSAGE_CON ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON,
            0, 
            pdu->tid, 
            coap_session_max_pdu_size(session)
        );

        /** 
         * @note: Implementation detail: coap_add_token() immediately returns 0
         *    if response == NULL 
         */

        // If PDU's initialization succeeded 
        if (coap_add_token(response, pdu->token_length, pdu->token)) {

            // Request's token used to identify the potentia subscription
            coap_binary_t token = { pdu->token_length, pdu->token };
            // 'Observe' option, if present in the request
            coap_opt_t *observe = NULL;
            // Type of the 'Observe' action
            int observe_action = COAP_OBSERVE_CANCEL;

            // Check for Observe option
            if (resource->observable) {

                // Check if the request contains 'Observe'
                coap_opt_iterator_t opt_iter;
                observe = coap_check_option(pdu, COAP_OPTION_OBSERVE, &opt_iter);

                // If 'Observe' is present
                if (observe) {

                    // Get the type of the 'Observer' option
                    observe_action = coap_decode_var_bytes(coap_opt_value(observe), coap_opt_length(observe));

                    // If the requested action was not a CANCEL
                    if ((observe_action & COAP_OBSERVE_CANCEL) == 0) {

                        coap_block_t block2;
                        int has_block2 = 0;

                        /**
                         * Try to parse the Block2 option from the request to establish the type
                         * of the observation's notifications.
                         */
                        if (coap_get_block(pdu, COAP_OPTION_BLOCK2, &block2))
                            has_block2 = 1;
                        
                        // Add the observator to the resource
                        coap_subscription_t *subscription = coap_add_observer(resource, session, &token, query, has_block2, block2);

                        // Note, that observer's object captured the query string
                        owns_query = 0;

                        // Reset observer's notification failure counter
                        if (subscription)
                           coap_touch_observer(session, &token);
                        
                    } 
                    // If a requested action was CANCEL, delete the subscription (i.e. observator)
                    else
                        coap_delete_observer(resource, session, &token);
                    
                }
            }

            // Call the request's handler
            handler(resource, session, pdu, &token, query, response);

            // Delete query string, if observer was not created
            if (query && owns_query)
                coap_delete_string(query);

            // Check the No-Response option
            respond = no_response(pdu, response);
            //  If the response must be discarded ...
            if (respond != RESPONSE_DROP) {

                // Delete the subscription, if Error response would be sent
                if (observe && (COAP_RESPONSE_CLASS(response->code) > 2))
                    coap_delete_observer(resource, session, &token);

                /**
                 * @note: If original request contained a token, and the registered application 
                 *    handler made no changes to the response, then this is an empty ACK with 
                 *    a token, which is  a malformed PDU .
                 */

                // Remove token from otherwise-empty acknowledgment PDU 
                if ((response->type == COAP_MESSAGE_ACK) && (response->code == 0)) {
                    response->token_length = 0;
                    response->used_size = 0;
                }

                /* RESPOND_DEFAULT */
                if (( respond == RESPONSE_SEND                 ) || 
                    ( response->type != COAP_MESSAGE_NON       ) ||  
                    ( response->code >= COAP_RESPONSE_CODE(200)) ){
                    if (coap_send(session, response) == COAP_INVALID_TID)
                        coap_log(LOG_DEBUG, "handle_request: cannot send response for message %d\n", pdu->tid);
                }
                else
                    coap_delete_pdu(response);

            } 
            // If the response must be discared
            else
                // Destroy the response
                coap_delete_pdu(response);
            
            response = NULL;
        } 
        // Response PDU could not be initialized
        else 
            coap_log(LOG_WARNING, "handle_request: cannot generate response\r\n");
    } 
    // If handler was not registered
    else {
        // Check if /.well.known/core was requesed
        if (coap_string_equal(uri_path, &coap_default_uri_wellknown)) {
            coap_log(LOG_DEBUG, "create default response for %s\n", COAP_DEFAULT_URI_WELLKNOWN);
            response = coap_wellknown_response(session, pdu);  
            coap_log(LOG_DEBUG, "have wellknown response %p\n", (void *)response);
        } 
        // Response with error
        else
            response = coap_new_error_response(pdu, COAP_RESPONSE_CODE(405), opt_filter);

        // Send the rsponse
        if (response && (no_response(pdu, response) != RESPONSE_DROP)){
            if (coap_send(session, response) == COAP_INVALID_TID)
                coap_log(LOG_DEBUG, "cannot send response for transaction %d\n", pdu->tid);
        } 
        // Or delete it, if cannot be sent
        else
            coap_delete_pdu(response);
        response = NULL;
    }

    assert(response == NULL);

    // Free the allocated string
    coap_delete_string(uri_path);
}


/**
 * @brief: Complex handler for the response messages.
 *
 * @param session:
 *    session that received the response
 * @param sent: 
 *    message that has been sent from the local machine
 * @param rcvd:
 *    peer's response
 */
static void handle_response(
    coap_session_t *session,
    coap_pdu_t *sent, 
    coap_pdu_t *received
) {

    // Send an ACK message to the peer
    coap_send_ack(session, received);

    /**
     * @note: In a lossy context, the ACK of a separate response may have
     *    been lost, so we need to stop retransmitting requests with the
     *    same token.
     */
    coap_cancel_all_messages(session, received->token, received->token_length);

    // Call application-specific response handler when available
    if (session->context->response_handler)
        session->context->response_handler(session->context, session, sent, received, received->tid);
}
