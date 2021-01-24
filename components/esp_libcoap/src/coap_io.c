/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 01:25:19
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

/* coap_io.c -- Default network I/O functions for libcoap
 *
 * Copyright (C) 2012,2014,2016-2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>

#include "coap_config.h"
#include "coap_debug.h"
#include "coap_io.h"
#include "mem.h"
#include "net.h"
#include "pdu.h"
#include "libcoap.h"
#include "utlist.h"
#include "resource.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

#define OPTVAL_T(t)         (t)
#define OPTVAL_GT(t)        (t)

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif


/* ----------------------------------------------- [Functions] ------------------------------------------------ */


struct coap_endpoint_t *coap_malloc_endpoint(void){
    return (struct coap_endpoint_t *) coap_malloc(sizeof(struct coap_endpoint_t));
}


void coap_mfree_endpoint(struct coap_endpoint_t *ep){
    coap_free(ep);
}


int coap_socket_bind_udp(
    coap_socket_t *sock,
    const coap_address_t *listen_addr,
    coap_address_t *bound_addr
){

    // Define options for @f setsockopt()
    int on = 1, off = 0;

    // Create system socket
    sock->fd = socket(listen_addr->addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sock->fd == COAP_INVALID_SOCKET) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp: socket: %s\n", coap_socket_strerror());
        goto error;
    }

#ifdef NOBLOCK
    // Set socket to non-blocking mode
    if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp: ioctl FIONBIO: %s\n", coap_socket_strerror());
    }
#endif

    // Set socket to have reusable address
    if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR){
        coap_log(LOG_WARNING, "coap_socket_bind_udp: setsockopt SO_REUSEADDR: %s\n",
            coap_socket_strerror());
    }

    // Set IP-gen-dependent options
    switch (listen_addr->addr.sa.sa_family){
        case AF_INET: // IPv4
            
            // Set IP_PKTINFO on the socket
            if (setsockopt(sock->fd, IPPROTO_IP, IP_PKTINFO, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR){
                coap_log(LOG_ALERT, "coap_socket_bind_udp: setsockopt IP_PKTINFO: %s\n",
                    coap_socket_strerror());
            }
            break;

        case AF_INET6: // IPv6

            // Configure the socket as dual-stacked
            if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR){
                coap_log(LOG_ALERT, "coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                    coap_socket_strerror());
            }

            // Set IP_PKTINFO on the socket
            if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR){
                coap_log(LOG_ALERT, "coap_socket_bind_udp: setsockopt IPV6_V6ONLY: %s\n",
                    coap_socket_strerror());
            }
            // Set IP_PKTINFO on the socket
            setsockopt(sock->fd, IPPROTO_IP, IP_PKTINFO, OPTVAL_T(&on), sizeof(on));

            break;

        default: // Unknown protocol

            coap_log(LOG_ALERT, "coap_socket_bind_udp: unsupported sa_family\n");
            break;
    }

    // Bind socket to the @p listen_addr
    if (bind(sock->fd, &listen_addr->addr.sa, listen_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp: bind: %s\n", coap_socket_strerror());
        goto error;
    }

    // Get local address bound with the socket by the system
    bound_addr->size = (socklen_t)sizeof(*bound_addr);
    if (getsockname(sock->fd, &bound_addr->addr.sa, &bound_addr->size) < 0) {
        coap_log(LOG_WARNING, "coap_socket_bind_udp: getsockname: %s\n", coap_socket_strerror());
        goto error;
    }

    return 1;

error:
    // On error, close the socket
    coap_socket_close(sock);
    return 0;
}


int coap_socket_connect(
    coap_socket_t *sock,
    const coap_address_t *local_if,
    const coap_address_t *server,
    int default_port,
    coap_address_t *local_addr,
    coap_address_t *remote_addr
){
    // Define options for @f setsockopt()
    int on = 1, off = 0;

    // Check whether address is in multicast group
    int is_mcast = coap_is_mcast(server);

    // Make local copy of the address
    coap_address_t connect_addr;
    coap_address_copy(&connect_addr, server);

    // Reset socket's flags and associate it with a new system socket
    sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);
    sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sock->fd == COAP_INVALID_SOCKET) {
        coap_log(LOG_WARNING, "coap_socket_connect: socket: %s\n", coap_socket_strerror());
        goto error;
    }

#ifdef NOBLOCK
    // Try to set socket in the non-blocking mode
    if (ioctl(sock->fd, FIONBIO, &on) == COAP_SOCKET_ERROR)
        coap_log(LOG_WARNING, "coap_socket_connect: ioctl FIONBIO: %s\n", coap_socket_strerror());
#endif

    // Set IP-gen-dependent options
    switch (connect_addr.addr.sa.sa_family) {
        case AF_INET: // IPv4

            // Set port, if'ts not set yet
            if (connect_addr.addr.sin.sin_port == 0)
                connect_addr.addr.sin.sin_port = htons(default_port);
            break;

        case AF_INET6: // IPv6

            // Set port, if'ts not set yet
            if (connect_addr.addr.sin6.sin6_port == 0)
                connect_addr.addr.sin6.sin6_port = htons(default_port);
            
            // Configure the socket as dual-stacked
            if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_V6ONLY, OPTVAL_T(&off), sizeof(off)) == COAP_SOCKET_ERROR)
                coap_log(LOG_WARNING, "coap_socket_connect: setsockopt IPV6_V6ONLY: %s\n",
                    coap_socket_strerror());
            break;

        default: // Unknown protocol

            coap_log(LOG_ALERT, "coap_socket_connect: unsupported sa_family\n");
            break;
    }

    // Check if local interface was passed to the function
    if (local_if && local_if->addr.sa.sa_family) {

        // Set address as reusable
        if (setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, OPTVAL_T(&on), sizeof(on)) == COAP_SOCKET_ERROR)
            coap_log(LOG_WARNING, "coap_socket_connect: setsockopt SO_REUSEADDR: %s\n",
                coap_socket_strerror());

        // Bind socket with the local interface
        if (bind(sock->fd, &local_if->addr.sa, local_if->size) == COAP_SOCKET_ERROR) {
            coap_log(LOG_WARNING, "coap_socket_connect: bind: %s\n",
                coap_socket_strerror());

        goto error;
        }
    }

    // Multicast addresses don't require connection step special treatment for sockets that are used for multicast communication */
    if (is_mcast) {

        // Get the address actually bound to the socket (local interface)
        if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR)
            coap_log(LOG_WARNING, "coap_socket_connect: getsockname for multicast socket: %s\n",
                coap_socket_strerror());

        // If multicast address is given, it is returned to the caller in the @p remote_addr
        coap_address_copy(remote_addr, &connect_addr);
        sock->flags |= COAP_SOCKET_MULTICAST;

        return 1;
    }

    // A regular addresses are configured via connect
    if (connect(sock->fd, &connect_addr.addr.sa, connect_addr.size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect: connect: %s\n",
                coap_socket_strerror());
        goto error;
    }

    /**
     * @note: in fact, connecting is not required for UDP sockets as it's conectionless protocol,
     *    but this calls sets internal library's structure so that writting to it in the future
     *    does not require passing a destination address.
     */

    // Get the address actually bound to the socket (local interface)
    if (getsockname(sock->fd, &local_addr->addr.sa, &local_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect: getsockname: %s\n",
                coap_socket_strerror());
    }

    // Get the address that socket actually connected to (remote interface)
    if (getpeername(sock->fd, &remote_addr->addr.sa, &remote_addr->size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect: getpeername: %s\n",
                coap_socket_strerror());
    }

    // Mark socket as connected
    sock->flags |= COAP_SOCKET_CONNECTED;

    return 1;

error:
    // On error, close the socket
    coap_socket_close(sock);
    return 0;
}


void coap_socket_close(coap_socket_t *sock){

    // Close the socket and mark it with an invalid file descriptor
    if (sock->fd != COAP_INVALID_SOCKET) {
        coap_closesocket(sock->fd);
        sock->fd = COAP_INVALID_SOCKET;
    }

    // Mark the socket as empty
    sock->flags = COAP_SOCKET_EMPTY;
}


ssize_t coap_socket_send(
    coap_socket_t *sock,
    coap_session_t *session,
    const uint8_t *data, 
    size_t data_len
){
    return session->context->network_send(sock, session, data, data_len);
}


ssize_t coap_network_send(
    coap_socket_t *sock, 
    const coap_session_t *session, 
    const uint8_t *data, 
    size_t datalen
){

    ssize_t bytes_written = 0;

    // Check @f coap_debug_send_packet's return value to establish if library should simulate this packet to belost
    if (!coap_debug_send_packet())
        bytes_written = (ssize_t) datalen;
    // If packet should be sent, check if a given socket was connected 
    else if (sock->flags & COAP_SOCKET_CONNECTED)
        bytes_written = send(sock->fd, data, datalen, 0);
    // If not, use 'sendto' metod and establish destination address basing on the @p session
    else
        bytes_written = sendto(sock->fd, data, datalen, 0, &session->remote_addr.addr.sa, session->remote_addr.size);

    // If ocurred, log an error type
    if (bytes_written < 0)
        coap_log(LOG_CRIT, "coap_network_send: %s\n", coap_socket_strerror());

    return bytes_written;
}


void coap_packet_set_addr(coap_packet_t *packet, const coap_address_t *src, const coap_address_t *dst) {
    coap_address_copy(&packet->src, src);
    coap_address_copy(&packet->dst, dst);
}

ssize_t coap_network_read(
    coap_socket_t *sock, 
    coap_packet_t *packet
){
    assert(sock);
    assert(packet);

    // Check if socket is readable
    if ((sock->flags & COAP_SOCKET_CAN_READ) == 0) {
        return -1;
    } 
    // If it is, mark it as unreadable at the moment (as it will be read in a moment)
    else {
        /* clear has-data flag */
        sock->flags &= ~COAP_SOCKET_CAN_READ;
    }

    ssize_t len = -1;

    // If socket was connected ... (i.e. 'bound' when it comes to receiving)
    if (sock->flags & COAP_SOCKET_CONNECTED) {

        // Receive from the socket
        len = recv(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0);

        // On error ...
        if (len < 0) {

            // If client-side ICMP destination unreachable ...
            if (errno == ECONNREFUSED) {
                coap_log(LOG_WARNING, "coap_network_read: unreachable\n");
                return -2;
            }

            // Otherwise, log a regualr error
            coap_log(LOG_WARNING, "coap_network_read: %s\n", coap_socket_strerror());
            return -1;
        }
        // On success, mark received data's length 
        else if (len > 0)
            packet->length = (size_t)len;
    } 
    // If socket was not connected (i.e. bound) previously, use @p packet to establish source address
    else {

        // Receive from the address encoded in the @p packet
        len = recvfrom(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0, &packet->src.addr.sa, &packet->src.size);

        // On error ...
        if (len < 0) {

            // Unconnected source address is unreachable, ignore it
            if (errno == ECONNREFUSED)
                return 0;

            // Log other errors
            coap_log(LOG_WARNING, "coap_network_read: %s\n", coap_socket_strerror());

            return -1;
        } 
        // Data was successfully received
        else {
            
            // Save a length of the received data
            packet->length = (size_t)len;

            // Save destination (i.e. local) address of the packet
            if (getsockname(sock->fd, &packet->dst.addr.sa, &packet->dst.size) < 0){
                coap_log(LOG_DEBUG, "Cannot determine local port\n");
                return -1;
            }
        }
    }

    return len;
}


int coap_run_once(coap_context_t *context, unsigned timeout_ms) {

    // Get time stamp of the routine's start
    coap_tick_t before;
    coap_ticks(&before);

    // Prepare array of sockets that potentially need to read data 
    coap_socket_t *sockets[COAP_MAX_SOCKET_OBSERVED];
    unsigned int num_sockets = 0;

    // Perform all operations required to establish what sessions should send messages
    unsigned int timeout = coap_write(context, sockets, (unsigned int)(sizeof(sockets) / sizeof(sockets[0])), &num_sockets, before);

    // Set timeout as a minimum of timeout returned by the coap_write and the one determined by the user
    if (timeout == 0 || timeout_ms < timeout)
        timeout = timeout_ms;

    // Define three sets of file descriptors (sockets) 
    fd_set readfds, writefds, exceptfds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);

    // Highest file descriptors (sockets) that needs to perform an action (plus 1) [@see select(2) man]
    coap_fd_t nfds = 0;

    // Iterate over all sockets marked by the @f coap_write() to lt select() observe them
    for(unsigned int i = 0; i < num_sockets; i++) {
        nfds = max(sockets[i]->fd + 1, nfds);
        FD_SET(sockets[i]->fd, &readfds);
    }

    // Convert actual timeout to the timeval
    struct timeval tv = {0, 0};
    if (timeout > 0) {
        tv.tv_usec = (timeout % 1000) * 1000;
        tv.tv_sec = (long)(timeout / 1000);
    }

    // Wait for the one of the sockets checked by coap_write() to be ready
    int result = select(nfds, &readfds, &writefds, &exceptfds, timeout > 0 ? &tv : NULL);

    /**
     * @note: before passing fd_sets to the select() the read/write-wanting sockets are set inside them.
     *    It means that select() will observer if they are ready and return either when the @v timeout
     *    is reached or some of the are ready. Before returning it will clear all fd_sets and set them
     *    to those descriptors that have become ready.
     */

    // On select's error ...
    if (result < 0) {
        // Ignore EINTR error
        if (errno != EINTR) {
            coap_log(LOG_DEBUG, "%s", coap_socket_strerror());
            return -1;
        }
    }

    // When seom descriptors are ready to perform an action ...
    if (result > 0) {

        // Iterate over all sockets that possibly want to perform an action
        for (int i = 0; i < num_sockets; i++) {
            // If socket is ready to be read, mark it as read-able
            if (FD_ISSET(sockets[i]->fd, &readfds))
                sockets[i]->flags |= COAP_SOCKET_CAN_READ;
        }
    }

    // Get time stamp of the routine's end
    coap_tick_t now;
    coap_ticks(&now);

    // Handle incoming data
    coap_read(context, now);

    // Return number of miliseconds that passed during the procedure call
    return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}


const char *coap_socket_strerror(void) {
      return strerror(errno);
}

