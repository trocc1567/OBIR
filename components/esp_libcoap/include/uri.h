/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-22 23:48:20
 *  Description:
 * 
 *      File defines basic API related to CoAP's URIs.
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
 * uri.h -- helper functions for URI treatment
 *
 * Copyright (C) 2010-2011,2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#ifndef COAP_URI_H_
#define COAP_URI_H_

#include <stdint.h>
#include "str.h"

struct coap_pdu_t;

/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/** This mask can be used to check if a parsed URI scheme is secure. */
#define COAP_URI_SCHEME_SECURE_MASK 0x01


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: The scheme specifiers. Secure schemes have an odd numeric value, others are even.
 */
enum coap_uri_scheme_t {
    COAP_URI_SCHEME_COAP=0,
    COAP_URI_SCHEME_COAPS=1,
};

/**
 * @brief: Representation of parsed URI. Components may be filled from a string with
 *    @f coap_split_uri() and can be used as input for option-creation functions.
 */
typedef struct {

  // Host part of the URI
  coap_str_const_t host;  
  // The port in host byte order
  uint16_t port;          
  // Beginning of the first path segment.
  coap_str_const_t path;  
  // The query part if present
  coap_str_const_t query; 

  // The parsed scheme specifier.
  enum coap_uri_scheme_t scheme;
  
} coap_uri_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Creates a new coap_uri_t object from the specified URI. Returns the new
 *    object or NULL on error. The memory allocated by the new coap_uri_t must be released
 *    using coap_free().
 *
 * @param uri:
 *    the URI path to copy.
 * @param length:
 *    the length of uri.
 * @returns:
 *    new URI object or NULL on error.
 */
coap_uri_t *coap_new_uri(const uint8_t *uri, unsigned int length);

/**
 * @brief: Clones the specified @t coap_uri_t object. Thie function allocates sufficient
 *    memory to hold the coap_uri_t structure and its contents. The object must
 *    be released with coap_free(). 
 *
 * @param uri:
 *    URI to be cloned 
 * @returns:
 *    cloned URI
 */
coap_uri_t *coap_clone_uri(const coap_uri_t *uri);

/**
 * @brief: Parses a given string into URI components. The identified syntactic
 *    components are stored in the result parameter @p uri. Optional URI
 *    components that are not specified will be set to { 0, 0 }, except for the
 *    port which is set to @c COAP_DEFAULT_PORT. This function returns @p 0 if
 *    parsing succeeded, a value less than zero otherwise.
 *
 * @param str:
 *    the string to split up.
 * @param len:
 *    the actual length of @p str_var
 * @param uri:
 *    the coap_uri_t object to store the result.
 * @returns:
 *    0 on success, or < 0 on error.
 *
 */
int coap_split_uri(const uint8_t *str, size_t len, coap_uri_t *uri);

/**
 * @brief: Splits the given URI path into segments. Each segment is preceded
 *    by an option pseudo-header with delta-value 0 and the actual length
 *    of the respective segment after percent-decoding.
 *
 * @param path:
 *    the path string to split.
 * @param length:
 *    the actual length of @p path.
 * @param buf:
 *    result buffer for parsed segments.
 * @param buflen:
 *    maximum length of @p buf. Will be set to the actual number of bytes written
 *    into buf on success.
 * @returns:
 *    the number of segments created or @c -1 on error.
 */
int coap_split_path(
    const uint8_t *path,
    size_t length,
    unsigned char *buf,
    size_t *buflen
  );

/**
 * @brief: Splits the given URI query into segments. Each segment is preceded
 *    by an option pseudo-header with delta-value 0 and the actual length
 *    of the respective query term.
 *
 * @param s:
 *    the query string to split.
 * @param length:
 *    the actual length of @p s.
 * @param buf:
 *    result buffer for parsed segments.
 * @param buflen:
 *    maximum length of @p buf. Will be set to the actual number of bytes written
 *    into buf on success.
 *
 * @returns:
 *    the number of segments created or @c -1 on error.
 *
 * @bug This function does not reserve additional space for delta > 12.
 */
int coap_split_query(
    const uint8_t *query,
    size_t length,
    unsigned char *buf,
    size_t *buflen
);

/**
 * @brief: Extract query string from request PDU according to escape rules
 *    in RFC 8252: Chapter 6.5 (point 8)
 * 
 * @param request:
 *    request PDU.
 * @returns:
 *    reconstructed and escaped query string part.
 */
coap_string_t *coap_get_query(const struct coap_pdu_t *request);

/**
 * @brief: Extract uri_path string from request PDU
 * 
 * @param request:
 *    request PDU.
 * @returns:
 *    reconstructed and escaped uri path string part.
 */
coap_string_t *coap_get_uri_path(const struct coap_pdu_t *request);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Checks whether URI scheme is secure
 * 
 * @param uri:
 *    URI to be checked
 * @return int:
 *    0 if URI is not secure, != 0 otherwise
 */
static inline int
coap_uri_scheme_is_secure(const coap_uri_t *uri) {
  return uri && ((uri->scheme & COAP_URI_SCHEME_SECURE_MASK) != 0);
}

#endif /* COAP_URI_H_ */
