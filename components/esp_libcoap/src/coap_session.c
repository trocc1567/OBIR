/* ============================================================================================================
 *  File:
 *  Author: Jean-Claue Michelou
 *  Source: https://github.com/obgm/libcoap
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 04:02:56
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

/* session.c -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/* ------------------------------------------------------------------------------------------------------------ */

#include "coap_config.h"
#include "coap_io.h"
#include "coap_session.h"
#include "net.h"
#include "coap_debug.h"
#include "mem.h"
#include "resource.h"
#include "utlist.h"
#include "encode.h"
#include <stdio.h>

static coap_session_t *coap_session_create_client(coap_context_t *ctx, const coap_address_t *local_if, const coap_address_t *server);
static coap_session_t *coap_make_session(coap_session_type_t type, const coap_address_t *local_addr, const coap_address_t *remote_addr, coap_context_t *context, coap_endpoint_t *endpoint );

/* ----------------------------------------------- [Functions] ------------------------------------------------ */

void coap_session_set_max_retransmit(coap_session_t *session, unsigned int value){

    // Set value (if valid given)
    if(value > 0)
        session->max_retransmit = value;

    // Log in debug case
    coap_log(LOG_DEBUG, "***%s: session max_retransmit set to %d\n",
        coap_session_str(session), session->max_retransmit);

    return;
}


void coap_session_set_ack_timeout (coap_session_t *session, coap_fixed_point_t value){

    // Set the value (if valid given)
    if(value.integer_part > 0 && value.fractional_part < 1000)
        session->ack_timeout = value;

    // Log in debug case
    coap_log(LOG_DEBUG, "***%s: session ack_timeout set to %d.%03d\n",
        coap_session_str(session), session->ack_timeout.integer_part,
            session->ack_timeout.fractional_part);

    return;
}

void coap_session_set_ack_random_factor(
    coap_session_t *session,
    coap_fixed_point_t value
){
    // Set the value (if valid given)
    if(value.integer_part > 0 && value.fractional_part < 1000)
        session->ack_random_factor = value;

    // Log in debug case
    coap_log(LOG_DEBUG, "***%s: session ack_random_factor set to %d.%03d\n",
        coap_session_str(session), session->ack_random_factor.integer_part,
            session->ack_random_factor.fractional_part);

    return;
}


unsigned int coap_session_get_max_transmit (coap_session_t *session) {
    return session->max_retransmit;
}


coap_fixed_point_t coap_session_get_ack_timeout (coap_session_t *session) {
    return session->ack_timeout;
}


coap_fixed_point_t coap_session_get_ack_random_factor (coap_session_t *session) {
    return session->ack_random_factor;
}

coap_session_t *coap_session_reference(coap_session_t *session) {
    ++(session->ref);
    return session;
}

void coap_session_release(coap_session_t *session){

    if(session) {
        assert(session->ref > 0);
        if(session->ref > 0)
            --session->ref;
        if(session->ref == 0 && session->type == COAP_SESSION_TYPE_CLIENT)
            coap_session_free(session);
    }
}

void coap_session_set_app_data(coap_session_t *session, void *app_data) {
    assert(session);
    session->app = app_data;
}

void *coap_session_get_app_data(const coap_session_t *session){
    assert(session);
    return session->app;
}


void coap_session_mfree(coap_session_t *session){

    coap_queue_t *q, *tmp;

    // Close used socket
    if (session->sock.flags != COAP_SOCKET_EMPTY)
        coap_socket_close(&session->sock);

    // If some packets was delayed, send NACK responses now
    LL_FOREACH_SAFE(session->delayqueue, q, tmp) {
        if (q->pdu->type==COAP_MESSAGE_CON && session->context && session->context->nack_handler)
            session->context->nack_handler(session->context, session, q->pdu, COAP_NACK_NOT_DELIVERABLE, q->id);
        coap_delete_node(q);
    }
}


void coap_session_free(coap_session_t *session) {

    if (!session)
        return;

    // If session is not referred by any object, it doesn't need to be freed
    assert(session->ref == 0);
    if(session->ref)
        return;

    // If we free endpoint's session, delete it from the endpoint's list
    if (session->endpoint) {
        if (session->endpoint->sessions)
            LL_DELETE(session->endpoint->sessions, session);
    } 
    // If we free context's session, delete it from the context's list
    else if (session->context) {
        if (session->context->sessions)
            LL_DELETE(session->context->sessions, session);
    }

    // Free session's internals
    coap_session_mfree(session);

    // Log debuf info
    coap_log(LOG_DEBUG, "***%s: session closed\n", coap_session_str(session));

    // Free session itself
    coap_free(session);
}


size_t coap_session_max_pdu_size(const coap_session_t *session){
    return ((size_t) session->mtu > COAP_HEADER_SIZE) ?
        ((size_t) session->mtu - COAP_HEADER_SIZE) : 0;
}


void coap_session_set_mtu(coap_session_t *session, unsigned mtu) {
    session->mtu = mtu;
}

ssize_t coap_session_send(
    coap_session_t *session, 
    const uint8_t *data, 
    size_t datalen
){
    coap_socket_t *sock = &session->sock;

    // If session has no socket assigned, use socket of the endpoint that session is assigned to
    if (sock->flags == COAP_SOCKET_EMPTY) {
        assert(session->endpoint != NULL);
        sock = &session->endpoint->sock;
    }

    // Send actual data using session 
    ssize_t bytes_written = coap_socket_send(sock, session, data, datalen);

    // Log informations about session's transaction
    if (bytes_written == (ssize_t)datalen){
        coap_ticks(&session->last_rx_tx);
        coap_log(LOG_DEBUG, "*  %s: sent %lu bytes\n", coap_session_str(session), (unsigned long) datalen);
    } else
        coap_log(LOG_DEBUG, "*  %s: failed to send %lu bytes\n", coap_session_str(session), (unsigned long) datalen);

    return bytes_written;
}


ssize_t coap_session_delay_pdu(
    coap_session_t *session, 
    coap_pdu_t *pdu,
    coap_queue_t *node
){
    // If node has to be deleted from the delayequeue ...
    if(node) {
        
        // Remove pdu from the context's sendqueue
        coap_queue_t *removed = NULL;
        coap_remove_from_queue(&session->context->sendqueue, session, node->id, &removed);
        assert(removed == node);

        // Release reference to the session that was hold by the node
        coap_session_release(node->session);
        node->session = NULL;
        // Clear packet's time stamp
        node->t = 0;
    } 
    // If node has to be created ...
    else {

        assert(pdu);

        // Check if the same tid is not getting re-used (it would be violation of RFC7252)
        coap_queue_t *q = NULL;
        LL_FOREACH(session->delayqueue, q) {
            if (q->id == pdu->tid) {
                coap_log(LOG_ERR, "**  %s: tid=%d: already in-use - dropped\n", coap_session_str(session), pdu->tid);
                return COAP_INVALID_TID;
            }
        }

        // Create a new packet node
        node = coap_new_node();
        if (node == NULL)
            return COAP_INVALID_TID;

        // Initialize node    
        node->id = pdu->tid;
        node->pdu = pdu;

        // If PDU is a CON message, set a random timeout for the ACK
        if (pdu->type == COAP_MESSAGE_CON) {
            uint8_t r;
            prng(&r, sizeof(r));
            node->timeout = coap_calc_timeout(session, r);
        }
    }

    // Append node to the delayqueue
    LL_APPEND(session->delayqueue, node);
    coap_log(LOG_DEBUG, "** %s: tid=%d: delayed\n", coap_session_str(session), node->id);

    return COAP_PDU_DELAYED;
}


coap_tid_t coap_session_send_ping(coap_session_t *session){
    
    // If session's state was not established, PING cannot be sent
    if (session->state != COAP_SESSION_STATE_ESTABLISHED)
        return 0;

    // Create PING packet
    coap_pdu_t *ping = coap_pdu_init(COAP_MESSAGE_CON, COAP_RESPONSE_EMPTY, 0, 1);
    if (!ping)
        return COAP_INVALID_TID;

    // Set packet
    return coap_send(session, ping);
}


void coap_session_connected(coap_session_t *session){

    // Mark session as connected
    session->state = COAP_SESSION_STATE_ESTABLISHED;

    while(session->delayqueue && session->state == COAP_SESSION_STATE_ESTABLISHED){

        // Get head of the queue of delayed packets
        coap_queue_t *q = session->delayqueue;
        // If it's a CON message (i.e. the one, that has to wait for an ACK message)...
        if (q->pdu->type == COAP_MESSAGE_CON){
            // If no more active connections can be handled, break the send loop
            if(session->con_active >= COAP_DEFAULT_NSTART)
                break;
            // Else, increment counter of simultaneously hold CON connections
            session->con_active++;
        }

        // Detach head of the delayqueue
        session->delayqueue = q->next;
        q->next = NULL;

        coap_log(LOG_DEBUG, "** %s: tid=%d: transmitted after delay\n",
            coap_session_str(session), (int)q->pdu->tid);

        // Send a detached packet
        ssize_t bytes_written = coap_session_send_pdu(session, q->pdu);
        if (bytes_written < 0)
            break;

        // If the sent message was of the CON type (waits for ACK), put it's node into context's sendqueue
        if (q->pdu->type == COAP_MESSAGE_CON){
            if (coap_wait_ack(session, q) >= 0)
                q = NULL;
            // If invalid TID was set to the PDU, delete it
            else
                coap_delete_node(q);
        }
    }
}


void coap_session_disconnected(
    coap_session_t *session, 
    coap_nack_reason_t reason
){
    
    // Log reson of the disconnection
    coap_log(LOG_DEBUG, "***%s: session disconnected (reason %d)\n",
            coap_session_str(session), reason);

    // Every Obervation relationship has a dedicated active sesion; delate it in such case
    coap_delete_observers(session);

    // Mark session's state
    session->state = COAP_SESSION_STATE_NONE;

    // Iterate over all delayed messages
    while (session->delayqueue) {

        // Detach head of the delayqueue
        coap_queue_t *q = session->delayqueue;
        session->delayqueue = q->next;
        q->next = NULL;

        // Log warning about discarded message
        coap_log(LOG_DEBUG, "** %s: tid=%d: not transmitted after delay\n",
            coap_session_str(session), q->id);

        // If peer didn't sent RST message and detached message was of the typ CON, put the message
        // to the queue of messages waiting for ACK 
        if(q->pdu->type == COAP_MESSAGE_CON && reason != COAP_NACK_RST)
            if (coap_wait_ack(session, q) >= 0)
                q = NULL;
        // If message could not be added to the ACK-waiting queue ...
        if(q != NULL){
            // Call nack_handler (if present)
            if(q->pdu->type == COAP_MESSAGE_CON && session->context->nack_handler)
                session->context->nack_handler(session->context, session, q->pdu, reason, q->id);
            // Delete the message
            coap_delete_node(q);
        }
    }
}

coap_session_t *coap_endpoint_get_session(
    coap_endpoint_t *endpoint,
    const coap_packet_t *packet, 
    coap_tick_t now
){

    /**
     * @brief: At the beggining make an overwiev of sessions already hold be the endpoint
     */

    // Number of IDLE sessions hold by the endpoint
    unsigned int num_idle = 0;
    // Pointer to the session with the oldest last_rx_tx timestamp
    coap_session_t *oldest = NULL;

    // Iterate over all sessions hold by the endpoint
    coap_session_t *session = NULL;
    LL_FOREACH(endpoint->sessions, session){

        // If @p packet can be unambiguously associated with a session, refresh session's time stamp
        if (coap_address_equals(&session->local_addr, &packet->dst) &&
            coap_address_equals(&session->remote_addr, &packet->src)
        ){
            session->last_rx_tx = now;
            return session;
        }

        // If session of the 'server' type is unreferred and has no messages to send in the delayqueue mark it as IDLE
        if (session->ref == 0 && session->delayqueue == NULL && session->type == COAP_SESSION_TYPE_SERVER){

            ++num_idle;

            // Update the oldest session (with respect to last_rx_tx timestamp)
            if (oldest == NULL || session->last_rx_tx < oldest->last_rx_tx)
                oldest = session;
        }
    }

    // Check if maximum number of IDLE sessions doen't cross the limit
    if (endpoint->context->max_idle_sessions > 0 && num_idle >= endpoint->context->max_idle_sessions) {
        coap_session_free(oldest);
    }

    /**
     * @brief: After the review, if no session associated with the packe was found,
     *    create a new session
     */

    // Create a new session for the endpoint
    session = coap_make_session(
        COAP_SESSION_TYPE_SERVER,
        &packet->dst, &packet->src, 
        endpoint->context,
        endpoint
    );

    // Initialize rest of the session's parameters
    if (session) {
        session->last_rx_tx = now;
        session->state = COAP_SESSION_STATE_ESTABLISHED;
        LL_PREPEND(endpoint->sessions, session);
        coap_log(LOG_DEBUG, "***%s: new incoming session\n",
            coap_session_str(session));
    }

    return session;
}


coap_session_t *coap_new_client_session(
    struct coap_context_t *context,
    const coap_address_t *local_if,
    const coap_address_t *server
){
    assert(context);
    
    // Create a new session, connect it to the @p server and bound with the @p local_if
    coap_session_t *session = coap_session_create_client(context, local_if, server);
    if (session)
        coap_log(LOG_DEBUG, "***%s: new outgoing session\n", coap_session_str(session));
    
    return session;
}


coap_endpoint_t *coap_new_endpoint(
    coap_context_t *context,
    const coap_address_t *listen_addr
){  
    assert(context);
    assert(listen_addr);

    // Allocate memory for the new endpoint
    struct coap_endpoint_t *ep = NULL;
    ep = coap_malloc_endpoint();
    if (!ep) {
        coap_log(LOG_WARNING, "coap_new_endpoint: malloc");
        goto error;
    }

    // Cleanup memory of the endpoint
    memset(ep, 0, sizeof(struct coap_endpoint_t));

    ep->context = context;

    // Try to bind endpoin's socket to the @p listen_addr
    if (!coap_socket_bind_udp(&ep->sock, listen_addr, &ep->bind_addr))
        goto error;
    ep->sock.flags |= COAP_SOCKET_WANT_READ;

    // Conditionally log some info 
    #ifndef NDEBUG
    if (LOG_DEBUG <= coap_get_log_level()) {

        #ifndef INET6_ADDRSTRLEN
        #define INET6_ADDRSTRLEN 40
        #endif

        unsigned char addr_str[INET6_ADDRSTRLEN + 8];
        if (coap_print_addr(&ep->bind_addr, addr_str, INET6_ADDRSTRLEN + 8)) {
            coap_log(LOG_DEBUG, "created an endpoint %s\n", addr_str);
        }
    }
    #endif /* NDEBUG */

    // Set endpoint's socket's library-specific flags & MTU
    ep->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_BOUND;
    ep->default_mtu = COAP_DEFAULT_MTU;

    // Add the endpoint to the @p context
    LL_PREPEND(context->endpoint, ep);

    return ep;

error:
    coap_free_endpoint(ep);
    return NULL;
}


void coap_endpoint_set_default_mtu(coap_endpoint_t *ep, unsigned mtu){
    ep->default_mtu = (uint16_t)mtu;
}


void coap_free_endpoint(coap_endpoint_t *ep){
    
    if (ep){

        // Close the endpoint's socket
        if (ep->sock.flags != COAP_SOCKET_EMPTY)
            coap_socket_close(&ep->sock);

        // Close all sessions hold by the endpoint
        coap_session_t *session, *tmp;
        LL_FOREACH_SAFE(ep->sessions, session, tmp) {
            assert(session->ref == 0);
            if (session->ref == 0) {
                session->endpoint = NULL;
                session->context = NULL;
                coap_session_free(session);
            }
        }

        coap_mfree_endpoint(ep);
    }
}


const char *coap_session_str(const coap_session_t *session) {
    
    static char szSession[256];
    char *start = szSession, *end = szSession + sizeof(szSession);

    // Write session's local address
    if (coap_print_addr(&session->local_addr, (unsigned char*) start, end - start) > 0)
        start += strlen(start);

    // Write delimiter between local address and the remote address
    if (start + 6 < end) {
        strcpy(start, " <-> ");
        start += 5;
    }

    // Write delimiter between local address and the remote address
    if (start < end - 1) {
        if (coap_print_addr(&session->remote_addr, (unsigned char*)start, end - start) > 0)
            start += strlen(start);
    }
    
    // Write name of the transport layter protocol 
    if (start + 6 < end) {
        strcpy(start, " UDP ");
        start += 4;
    }

    return szSession;
}


const char *coap_endpoint_str(const coap_endpoint_t *endpoint) {

    static char szEndpoint[128];
    char *p = szEndpoint, *end = szEndpoint + sizeof(szEndpoint);

    // Write the local address that the endpoint listens on
    if (coap_print_addr(&endpoint->bind_addr, (unsigned char*)p, end - p) > 0)
        p += strlen(p);

    // Write name of the transport layter protocol 
    if (p + 6 < end) {
        strcpy(p, " UDP");
        p += 4;
    }

    return szEndpoint;
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */


/**
 * @brief: Creates a clear @t coap_session_t object with given parameters
 * 
 * @param type:
 *    session's type
 * @param local_addr:
 *    local address the session will be receiving on
 * @param remote_addr:
 *    remote address the session will be send to
 * @param context:
 *    context the session belongs to
 * @param endpoint:
 *    edpoint the session belongs to 
 * @return:
 *    a new @t coap_session_t object
 */
static coap_session_t *coap_make_session(
    coap_session_type_t type,
    const coap_address_t *local_addr,
    const coap_address_t *remote_addr, 
    coap_context_t *context,
    coap_endpoint_t *endpoint
){
    assert(context);

    // Allocate memory for the session
    coap_session_t *session = (coap_session_t*) coap_malloc(sizeof(coap_session_t));
    if(!session)
        return NULL;

    // Clear session's memory
    memset(session, 0, sizeof(*session));

    // Fill basic fields of the session
    session->type = type;
    session->context = context;
    session->endpoint = endpoint;
    session->max_retransmit = COAP_DEFAULT_MAX_RETRANSMIT;
    session->ack_timeout = COAP_DEFAULT_ACK_TIMEOUT;
    session->ack_random_factor = COAP_DEFAULT_ACK_RANDOM_FACTOR;
    // Set session's addresses,if given
    if(local_addr)
        coap_address_copy(&session->local_addr, local_addr);
    else
        coap_address_init(&session->local_addr);
    if(remote_addr)
        coap_address_copy(&session->remote_addr, remote_addr);
    else
        coap_address_init(&session->remote_addr);
    // Initialize MTU
    if (endpoint)
        session->mtu = endpoint->default_mtu;
    else
        session->mtu = COAP_DEFAULT_MTU;

    // Initialize ID's of the sent message with a random value
    prng((unsigned char *)&session->tx_mid, sizeof(session->tx_mid));

    return session;
}

/**
 * @brief: Creates client-type session in the given context. Connects the session
 *    with the @p server address. If @p local_if is not NULL, the session's socket
 *    is bound to this address
 * 
 * @param ctx:
 *    context of the created session
 * @param local_if:
 *    local address to be bound with the session
 * @param server:
 *    remote server that the session will connect with
 * @returns:
 *    created session on success
 *    NULL on error
 */
static coap_session_t *coap_session_create_client(
    coap_context_t *context,
    const coap_address_t *local_if,
    const coap_address_t *server
){
    assert(context);
    assert(server);

    // Create a new session of the client type
    coap_session_t *session = coap_make_session(
        COAP_SESSION_TYPE_CLIENT, 
        local_if, server,
        context, NULL
    );
    if (!session)
        goto error;

    // Increment references counter on the session
    coap_session_reference(session);

    // Connect the session to the remote endpoint
    int ret = coap_socket_connect(
        &session->sock, 
        &session->local_addr, 
        server,
        COAP_DEFAULT_PORT, 
        &session->local_addr, 
        &session->remote_addr
    );
    if (!ret)
        goto error;

    // Set flags for the session's socket
    session->sock.flags |= COAP_SOCKET_NOT_EMPTY | COAP_SOCKET_WANT_READ;    
    if (local_if)
        session->sock.flags |= COAP_SOCKET_BOUND;
    session->state = COAP_SESSION_STATE_ESTABLISHED;
    
    // Set the timestamp on the session
    coap_ticks(&session->last_rx_tx);

    // Append session to the context's sessions list
    LL_PREPEND(context->sessions, session);

    return session;

error:
    // On fail, free the alocated session
    coap_session_release(session);
    return NULL;
}
