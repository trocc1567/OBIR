/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 00:20:38
 *  Description:
 * 
 *      File contains header associated with CoAP session abstraction.
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

/* coap_session.h -- Session management for libcoap
*
* Copyright (C) 2017 Jean-Claue Michelou <jcm@spinetix.com>
*
* This file is part of the CoAP library libcoap. Please see
* README for terms of use.
*/

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_SESSION_H_
#define COAP_SESSION_H_


#include "coap_io.h"
#include "coap_time.h"
#include "pdu.h"

struct coap_endpoint_t;
struct coap_context_t;
struct coap_queue_t;

typedef struct coap_fixed_point_t coap_fixed_point_t;


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: Basic parameters of the CoAP session
 */
#define COAP_DEFAULT_SESSION_TIMEOUT 300
#define COAP_PARTIAL_SESSION_TIMEOUT_TICKS (30 * COAP_TICKS_PER_SECOND)

/**
 * @brief: possible values of @t coap_session_type_t type
 */
#define COAP_SESSION_TYPE_CLIENT 1  // Client-side session
#define COAP_SESSION_TYPE_SERVER 2  // Server-side session


/**
 * @brief: possible values of @t coap_session_state_t type
 */
#define COAP_SESSION_STATE_NONE        0
#define COAP_SESSION_STATE_ESTABLISHED 1

/**
 * @brief: Number of seconds when to expect an ACK or a response to an outstanding
 *    CON message RFC 7252, Section 4.8 Default value of ACK_TIMEOUT is 2.
 */
#define COAP_DEFAULT_ACK_TIMEOUT ((coap_fixed_point_t){2,0})

/**
* @brief:A factor that is used to randomize the wait time before a message is retransmitted
     to prevent synchronization effects. RFC 7252, Section 4.8 Default value of ACK_RANDOM_FACTOR 
     is 1.5
*/
#define COAP_DEFAULT_ACK_RANDOM_FACTOR ((coap_fixed_point_t){1,500})

/**
 * @brief: Number of message retransmissions before message sending is stopped RFC 7252, Section
 *    4.8 Default value of MAX_RETRANSMIT is 4
 */
#define COAP_DEFAULT_MAX_RETRANSMIT  4

/**
 * @brief: The number of simultaneous outstanding interactions that a client maintains to a given
 *    server RFC 7252, Section 4.8 Default value of NSTART is 1
 */
#define COAP_DEFAULT_NSTART 1

/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Abstraction of a fixed point number that can be used where necessary instead
 *    of a float. 1'000 fractional bits equals one integer
 */
struct coap_fixed_point_t {

    // Integer part
    uint16_t integer_part;
    // Fractional part (1/1000 precision)
    uint16_t fractional_part;
  
};

/**
 * @brief: Type of the CoAP session
 */
typedef uint8_t coap_session_type_t;

/**
 * @brief: State of the CoAP session (type of the realtionship with current peer)
 */
typedef uint8_t coap_session_state_t;


/**
 * @brief: Structure describing abstraction of the CoAP-level client-server session
 */
typedef struct coap_session_t {
  
    // Value used for storing sessions as a forward list
    struct coap_session_t *next;

    // Session's context
    struct coap_context_t *context;

    // Application-specific data
    void *app;                        

    /* ------------------------ Basic session info ------------------------------- */

    // Session's type ( @see @t coap_session_type_t)
    coap_session_type_t type;
    // Session's state (@see coap_session_state_t)
    coap_session_state_t state;
    // Count of refferences to the session from message queues
    unsigned ref;

    /* ----------------------- Session's parameters ------------------------------ */

    // Current MTU (i.e. maximum transimssion unit)
    unsigned mtu;
    // Maximum re-transmit count (default 4)
    unsigned int max_retransmit;      
    // Timeout for waiting for ack (default 2 secs)
    coap_fixed_point_t ack_timeout;   
    // ACK random factor backoff (default 1.5)
    coap_fixed_point_t ack_random_factor;

    /* ------------------------- Endpoints' info --------------------------------- */

    // Remote address and port
    coap_address_t remote_addr;
    // Local address and port
    coap_address_t local_addr;
    // Socket object for the session (if any)
    coap_socket_t sock;
    // Session's endpoint [?]
    struct coap_endpoint_t *endpoint;

    /* -------------------------- Messages' info --------------------------------- */

    // The last message id that was used in this session
    uint16_t tx_mid;
    // Counter of active CON request sent (waiting for the ACK message)
    uint8_t con_active;

    // List of delayed messages waiting to be sent (only the CON messages can be delayed)
    struct coap_queue_t *delayqueue;

    // Session's timestamps
    coap_tick_t last_rx_tx;
    coap_tick_t last_tx_rst;
    
} coap_session_t;

/**
 * @brief: Abstraction of a virtual endpoint that can be attached to @t coap_context_t. The
 *    tuple (handle, addr) must uniquely identify this endpoint. It is structure describing
 *    higher abstraction of the local, integrated (all-in-one) CoAP's interface used for 
 *    communication with peers.
 * 
 *    An endpoint is an entity directly possessed by the CoAP context and it's representation
 *    of the single CoAP client/server instance. In one @t coap_context_t many instances
 *    of the @t coap_endpoint_t can be registered and so many clients/servers can work 
 *    paralelly.    
 * 
 *    Single endpoint CAN be used for double-type communication, i.e. it can function as
 *    server and client enpoint simultaneously, although only one system socket can be
 *    associated with it.
 */
typedef struct coap_endpoint_t {

    // Value used for storing sessions as a forward list
    struct coap_endpoint_t *next;

    // Endpoint's context
    struct coap_context_t *context; 

    // Default mtu for this interface
    uint16_t default_mtu;
    
    // Socket object for the interface (if any)
    coap_socket_t sock;
    // Local interface address
    coap_address_t bind_addr;

    // list of active sessions
    coap_session_t *sessions;

} coap_endpoint_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Increment reference counter on a session.
 *
 * @param:
 *    session The CoAP session.
 * @returns: 
 *    same as @p session
 */
coap_session_t *coap_session_reference(coap_session_t *session);

/**
 * @brief: Decrement reference counter on a session
 *
 * @param session:
 *    the CoAP session.
 * 
 * @note: the session may be deleted as a result and should not be used after this call.
 */
void coap_session_release(coap_session_t *session);

/**
 * @brief: Stores data within the given session. This function overwrites any value
 *    that has previously been stored with @p session->app.
 * 
 * @param session:
 *    session to be modified
 * @param data:
 *    data to be assigned to the @p session
 */
void coap_session_set_app_data(coap_session_t *session, void *data);

/**
 * @param session:
 *    session to be inspected
 * @returns:
 *    any application-specific data that has been stored with @p session->app using the 
 *    function @f coap_session_set_app_data(). This function will return NULL if no data
 *    has been stored.
 */
void *coap_session_get_app_data(const coap_session_t *session);

/**
 * @brief: Changes state of the session to COAP_SESSION_STATE_NONE. Cleans partial
 *    PDU. Deletes observers associated with the session. Clears the delayqueue.
 *    Delayed CON messages are put to the context's retransmittion queue if @p reason
 *    is not COAP_NACK_RST.
 *
 * @param session:
 *    the CoAP session
 * @param reason:
 *    the reason why the session was disconnected
 */
void coap_session_disconnected(coap_session_t *session, coap_nack_reason_t reason);

/**
 * @brief: Changes state of the session to COAP_SESSION_STATE_ESTABLISHED. Flushes
 *    (i.e. tries to send) all of the packets put into the @p session->delayqueue.
 *
 * @param session:
 *    the CoAP session.
 */
void coap_session_connected(coap_session_t *session);

/**
 * @brief: Sets the session MTU. This is the maximum message size that can be sent,
 *    excluding IP and UDP overhead.
 *
 * @param session:
 *    the CoAP session.
 * @param mtu:
 *    maximum message size
 */
void coap_session_set_mtu(coap_session_t *session, unsigned mtu);

/**
 * @brief: Get maximum acceptable PDU size
 *
 * @param session:
 *    the CoAP session.
 * @return maximum:
 *    PDU size, not including header (but including token).
 */
size_t coap_session_max_pdu_size(const coap_session_t *session);

/**
 * @brief: Creates a new client session to the designated server.
 *
 * @param ctx:
 *    the CoAP context.
 * @param local_if:
 *    address of local interface. It is recommended to use NULL to let the operating 
 *    system choose a suitable local interface. If an address is specified, the port
 *    number should be zero, which means that a free port is automatically selected.
 * @param server:
 *    the server's address. If the port number is zero, the default port will be used.
 * @returns:
 *    a new CoAP session or NULL if failed. Call coap_session_release to free.
 */
coap_session_t *coap_new_client_session(
    struct coap_context_t *ctx,
    const coap_address_t *local_if,
    const coap_address_t *server
);

/**
 * @brief: Function interface for datagram data transmission. This function returns the
 *    number of bytes that have been transmitted, or a value less than zero on error.
 *
 * @param session:
 *    session to send data on.
 * @param data:
 *    the data to send.
 * @param datalen:
 *    the actual length of @p data.
 * @returns:
 *    the number of bytes written on success, or a value less than zero on error.
 */
ssize_t coap_session_send(
    coap_session_t *session,
    const uint8_t *data,
    size_t datalen
);

/**
 * @brief: Send a pdu
 * 
 * @param session:
 *    session to send pdu on.
 * @param pdu:
 *    the pdu to send.
 * @returns:
 *    the number of bytes written on success
 *    value less than zero on error.
 */
ssize_t coap_session_send_pdu(
    coap_session_t *session,
    coap_pdu_t *pdu
);

/**
 * @brief: Get session description.
 *
 * @param session:
 *   the CoAP session.
 * @returns:
 *   description string.
 */
const char *coap_session_str(const coap_session_t *session);

/**
 * @brief: Appends @p pdu to the end of the @p session's delayqueue or re-places the
 *    @p node of the delayqueue.
 * 
 * @param session:
 *    session to delay PDU with
 * @param pdu:
 *    if not NULL, PDU to be delayed
 * @param node [in/out]:
 *    if not NULL points to the entity in the @t coap_context_t->sendqueue to be removed 
 *    before delaying
 *    if NULL and @p pdu is not NULL will point to the created entity in the @p session->delayqueue
 * @return ssize_t:
 *    @c COAP_PDU_DELAYED on success
 *    @c COAP_INVALID_TID when @p pdu->tid is already in the in the delayqueue
 *    @c COAP_INVALID_TID if new entity in the delayqueue cannot be created
 */
ssize_t
coap_session_delay_pdu(
    coap_session_t *session,
    coap_pdu_t *pdu,
    struct coap_queue_t *node
);

/**
 * @brief: Create a new endpoint for communicating with peers.
 * 
 * @param context:
 *    the coap context that will own the new endpoint
 * @param listen_addr:
 *    address the endpoint will listen for incoming requests on or originate outgoing
 *    requests from. Use NULL to specify that no incoming request will be accepted and 
 *    use a random endpoint.
 * @returns:
 *    created endpoint on success
 *    NULL on failure
 */
coap_endpoint_t *coap_new_endpoint(
    struct coap_context_t *context,
    const coap_address_t *listen_addr
);

/**
 * @brief: Set the endpoint's default MTU. This is the maximum message size that can be
 *    sent, excluding IP and UDP overhead.
 *
 * @param endpoint:
 *    the CoAP endpoint.
 * @param mtu:
 *    maximum message size
 */
void coap_endpoint_set_default_mtu(
    coap_endpoint_t *endpoint,
    unsigned mtu
);

/**
 * @brief: Frees resources dynamicly allocated by the library on @p ep's behalf
 * 
 * @param ep:
 *    endpoint to be freed     
 */
void coap_free_endpoint(coap_endpoint_t *ep);


/**
 * @brief: Get endpoint's human-readable description.
 *
 * @param endpoint:
 *    the CoAP endpoint.
 * @returns:
 *    description string.
 */
const char *coap_endpoint_str(const coap_endpoint_t *endpoint);

/**
 * @brief: Lookup the enpoint's (i.e. server's) session for the packet received, or
 *    creates a new one session for incoming packet.
 *
 * @param endpoint:
 *    active endpoint the packet was received on.
 * @param packet:
 *    received packet.
 * @param now:
 *    the current time in ticks.
 * @returns:
 *    the CoAP session.
 */
coap_session_t *coap_endpoint_get_session(
    coap_endpoint_t *endpoint,
    const struct coap_packet_t *packet,
    coap_tick_t now
);

/**
 * @brief: Releases resources allocated by the library fo the session
 * 
 * @param session:
 *    session to be freed
 */
void coap_session_free(coap_session_t *session);

/**
 * @brief: Releases resources allocated by the library fo the session
 *    Part of the @f coap_session_free's inner implementation.
 * 
 * @param session:
 *    session to be freed
 */
void coap_session_mfree(coap_session_t *session);

/**
 * @brief: Set the CoAP maximum retransmit count before failure. Number 
 *    of message retransmissions before message sending is held.
 *
 * @param session:
 *    the CoAP session.
 * @param value:
 *    the value to set to. The default is 4 and should not normally get changed.
 */
void coap_session_set_max_retransmit(
    coap_session_t *session,
    unsigned int value
);

/**
 * @brief: Set the CoAP initial ack response timeout before the next re-transmit,
 *    i.e. number of seconds when to expect an ACK or a response to an outstanding 
 *    CON message.
 *
 * @param session:
 *    the CoAP session.
 * @param value:
 *    the value to set to. The default is 2 and should not normally get changed.
 */
void coap_session_set_ack_timeout(
    coap_session_t *session,
    coap_fixed_point_t value
);

/**
 * @brief: Set the CoAP ack randomize factor. A factor that is used to randomize the
 *    wait time before a message is retransmitted to prevent synchronization effects.
 *
 * @param session:
 *    the CoAP session.
 * @param value:
 *    the value to set to. The default is 1.5 and should not normally get changed.
 */
void coap_session_set_ack_random_factor(
    coap_session_t *session,
    coap_fixed_point_t value
);

/**
 * @brief: Get the CoAP maximum retransmit before failure. Number of message retransmissions 
 *    before message sending is stopped
 *
 * @param session:
 *    the CoAP session.
 * @returns:
 *    current maximum retransmit value
 */
unsigned int coap_session_get_max_transmit(coap_session_t *session);

/**
 * @brief: Get the CoAP initial ack response timeout before the next re-transmit. Number of
 *    seconds when to expect an ACK or a response to an outstanding CON message.
 *
 * @param session:
 *    the CoAP session.
 * @returns:
 *    current ack response timeout value
 */
coap_fixed_point_t coap_session_get_ack_timeout(coap_session_t *session);

/**
 * @brief: Get the CoAP ack randomize factor. A factor that is used to randomize the wait time
 *    before a message is retransmitted to prevent synchronization effects.
 *
 * @param session:
 *    the CoAP session.
 * @returns:
 *    current ack randomize value
 */
coap_fixed_point_t coap_session_get_ack_random_factor(coap_session_t *session);

/**
 * @brief: Sends a ping message for the session.
 * 
 * @param session:
 *    the CoAP session
 * @returns:
 *    @c COAP_INVALID_TID if there is an error
 */
coap_tid_t coap_session_send_ping(coap_session_t *session);

#endif  /* COAP_SESSION_H */
