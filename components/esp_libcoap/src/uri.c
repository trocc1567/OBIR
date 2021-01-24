/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-28 15:08:23
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

/* uri.c -- helper functions for URI treatment
 *
 * Copyright (C) 2010--2012,2015-2016 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */


#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "coap_config.h"
#include "coap_debug.h"
#include "libcoap.h"
#include "option.h"
#include "pdu.h"
#include "mem.h"
#include "uri.h"

struct cnt_str;
typedef void (*segment_handler_t)(const uint8_t *, size_t, struct cnt_str *);

COAP_STATIC_INLINE const uint8_t *strnchr(const uint8_t *s, size_t len, unsigned char c);
static void decode_segment(const uint8_t *seg, size_t length, unsigned char *buf);
static int check_segment(const uint8_t *seg, size_t length, size_t *segment_size);
static int make_decoded_option(const uint8_t *seg, size_t length, unsigned char *buf, size_t buflen, size_t* optionsize);
static void write_option(const uint8_t *seg, size_t len, struct cnt_str *data);
COAP_STATIC_INLINE int dots(const uint8_t *seg, size_t len);
static size_t coap_split_path_impl(const uint8_t *str, size_t length, segment_handler_t handler, void *data);
COAP_STATIC_INLINE int is_unescaped_in_path(const uint8_t c);
COAP_STATIC_INLINE int is_unescaped_in_query(const uint8_t c);
static coap_string_t *coap_get_seg_impl(const coap_pdu_t *request, unsigned int filter_type);


/* -------------------------------------------- [Macrofeinitions] --------------------------------------------- */

#define ISEQUAL_CI(a,b) \
  ((a) == (b) || (islower(b) && ((a) == ((b) - 0x20))))

/**
 * @brief: Calculates decimal value from hexadecimal ASCII character given in
 *    @p c. The caller must ensure that @p c actually represents a valid
 *    heaxdecimal character, e.g. with isxdigit(3).
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief: Helper macro used, when data related with the coap_uri_t object is
 *    storect directly after the structure itself.
 */
#define URI_DATA(uriobj) ((unsigned char *)(uriobj) + sizeof(coap_uri_t))


/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Helper structure used to produce a sequence of Uri-Path
 *    options. @a buf is the buffer for the options sequence itself,
 *    when @a n is a number of options.
 */
struct cnt_str {
    coap_string_t buf;
    int n;
};


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

int coap_split_uri(const uint8_t *str, size_t len, coap_uri_t *uri){

    int retval = 0;

    // Assure non-empty arguments
    if (!str || !uri)
        return -1;

    // Initialize @p uri structure
    memset(uri, 0, sizeof(coap_uri_t));
    uri->port = COAP_DEFAULT_PORT;

    /* ------------------------- search for scheme ------------------------- */

    const uint8_t *q;
    const uint8_t *p = str;

    // If the string start with '/' it means that no scheme, address and port are given
    if (*p == '/') {
        q = p;
        goto path;
    }

    // Compare subsequent bytes of the schema with the default scheme
    q = (const uint8_t *) COAP_DEFAULT_SCHEME;
    for(; len > 0 && *q != '\0' && ISEQUAL_CI(*p, *q); --len){
        ++p; ++q;
    }

    // If q does not point to the string end marker '\0', the schema identifier is wrong.
    if(*q != '\0'){
        retval = -1;
        goto error;
    } else 
        uri->scheme = COAP_URI_SCHEME_COAP;
    
    // Check characters after the scheme
    q = (const uint8_t *)"://";
    for(; len > 0 && *q != '\0' && ISEQUAL_CI(*p, *q); --len){
        ++p; ++q;
    }

    // If q does not point to the string end marker '\0', there are wrong characters after schema
    if (*q) {
        retval = -2;
        goto error;
    }

    /* -------------------- search for the host address -------------------- */

    /**
     * @note: At this point 'p' points to the beggining of the host address in the URI
     */
    q = p;

    if(len == 0){
        retval = -3;
        goto error;
    }

    // If host is given with the leading '[', it is an IPv6 address
    if (*p == '['){

        // Find end position of the address
        for(; len != 0 && *q != ']'; --len)
            ++q;

        /**
         * If:
         *   - len is equal 0 (i.e. there are no more characters after address)
         *   - q does not point to finishing bracket ']'
         *   - q points to the position after the p
         * the URI string is invalid
         */
        if (!len || *q != ']' || ++p == q) {
            retval = -3;
            goto error;
        }

        // Set host address in the uri structure
        COAP_SET_STR(&uri->host, q - p, p);

        // Set q to the first character after the address
        ++q; --len;
    } 
    // Otherwise, it is an IPv4 address
    else {

        // Look for the end of the address
        for(; len && *q != ':' && *q != '/' && *q != '?'; --len)
            ++q;

        // q still point to the same byte as q, there is no address in fact - report an error
        if (p == q) {
            retval = -3;
            goto error;
        }

        // Set host address in the uri structure
        COAP_SET_STR(&uri->host, q - p, p);
    }


    /* ------------------------ search for the port ------------------------ */


    if (len && *q == ':') {
        
        // Set p and q to the next character after the ':'
        p = ++q; --len;
        
        // Look for the first non-digit character (end of the port)
        for(; len != 0 && isdigit(*q); --len)
            ++q;

        // If q moved forward, the port is given explicitly
        if (p < q){

            // Convert port string into the number
                        int uri_port = 0;
            while (p < q)
                uri_port = uri_port * 10 + (*p++ - '0');

            // Check if a port number is in the allowed range
            if (uri_port > 65535) {
                retval = -4;
                goto error;
            }

            uri->port = (uint16_t)uri_port;
        }
    }

path: 
    /* ------------------- search for the resource path -------------------- */

    // No resource in the path
    if (len == 0)
        goto end;

    // Parse the resource path
    if (*q == '/') {

        // Set p and q to point the next character after '/' 
        p = ++q; --len;

        // Search for the first character after the path
        for(; len != 0 && *q != '?'; --len)
            ++q;

        // If q moved forward, there is a resource path in the string 
        if (p < q) {
            COAP_SET_STR(&uri->path, q - p, p);
            p = q;
        }
    }

    // If there is a '?' character after the resource path, all left characters constitute a query
    if (len && *p == '?') {
        ++p; --len;
        COAP_SET_STR(&uri->query, len, p);
        len = 0;
    }

end:
    return len ? -1 : 0;

error:
    return retval;
}


int coap_split_path(
    const uint8_t *path, 
    size_t length,
    unsigned char *buf, 
    size_t *buflen
){
    struct cnt_str tmp = {
        .buf = { .length =  *buflen, .s = buf },
        .n   = 0 
    };

    // Split a path into segment. Each of them write to the tmp.buf as an option using write_option() callback
    coap_split_path_impl(path, length, write_option, &tmp);

    // Set @p buflen to the size of the remaining space
    *buflen = *buflen - tmp.buf.length;

    // Return number of segment created
    return tmp.n;
}


int coap_split_query(
    const uint8_t *query, 
    size_t length,
    unsigned char *buf,
    size_t *buflen
){
    struct cnt_str tmp = {
        .buf = { .length =  *buflen, .s = buf },
        .n   = 0 
    };

    const uint8_t *query_start = query;

    // Iterate over the query string
    unsigned int i;
    for(i = 0; i < length && query[i] != '#'; ++i, --length){
        
        // Start new query element
        if (*query == '&') {
            // Write a query option into the buffer
            write_option(query_start, (query + i) - query_start, &tmp);
            query_start = query + i + 1;
        }
    }

    // Write the last query element
    write_option(query_start, (query + i) - query_start, &tmp);

    // Set @p buflen to the size of the remaining space
    *buflen = *buflen - tmp.buf.length;
    
    return tmp.n;
}


coap_uri_t *coap_new_uri(const uint8_t *uri, unsigned int length) {
  
    // Allocate memory for the result structure and the @p uri's copy (+1 byte for terminating '\0')
    unsigned char *result = 
        (unsigned char*) coap_malloc(length + 1 + sizeof(coap_uri_t));
    if (result == NULL)
        return NULL;

    // Make a local copy of the @uri in the allocated block; terminate it with '\0'
    memcpy(URI_DATA(result), uri, length);
    URI_DATA(result)[length] = '\0';

    // Try to split URI into the structure
    if (coap_split_uri(URI_DATA(result), length, (coap_uri_t *)result) < 0) {
        coap_free(result);
        return NULL;
    }

    return (coap_uri_t *)result;
}


coap_uri_t *coap_clone_uri(const coap_uri_t *uri){
  
    if(uri == NULL)
        return NULL;

    // Allocate memory for @p uri structure and it's internal buffers
    coap_uri_t *result = 
        (coap_uri_t *) coap_malloc( 
            sizeof(coap_uri_t) +
            uri->host.length   +
            uri->path.length   + 
            uri->query.length
        );
    if (result == NULL)
        return NULL;

    // Clear allocated memory
    memset( result, 0, sizeof(coap_uri_t));

    // Clone port value
    result->port = uri->port;

    // Clone host address as the first element after the @t coap_uri_t structure
    if ( uri->host.length != 0) {
        result->host.s  = URI_DATA(result);
        result->host.length = uri->host.length;
        memcpy((uint8_t *) result->host.s, uri->host.s, uri->host.length);
    }

    // Clone resource path as the second element after the @t coap_uri_t structure
    if (uri->path.length != 0){
        result->path.s = URI_DATA(result) + uri->host.length;
        result->path.length = uri->path.length;
        memcpy((uint8_t *) result->path.s, uri->path.s, uri->path.length);
    }

    // Clone query path as the first third after the @t coap_uri_t structure
    if (uri->query.length != 0) {
        result->query.s = URI_DATA(result) + uri->host.length + uri->path.length;
        result->query.length = uri->query.length;
        memcpy((uint8_t *) result->query.s, uri->query.s, uri->query.length);
    }

    return result;
}


coap_string_t *coap_get_query(const coap_pdu_t *request) {
    return coap_get_seg_impl(request, COAP_OPTION_URI_QUERY);
}


coap_string_t *coap_get_uri_path(const coap_pdu_t *request) {
    return coap_get_seg_impl(request, COAP_OPTION_URI_PATH);
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */

/**
 * @brief: A length-safe version of strchr().
 *
 * @param s:
 *    the string to search for @p c
 * @param len:
 *    the length of @p s
 * @param c:
 *    the character to search
 *
 * @returns:
 *    a pointer to the first occurence of @p c if found
 *    @c NULL if not found
 */
COAP_STATIC_INLINE const uint8_t *
strnchr(const uint8_t *s, size_t len, unsigned char c){
    while (len && *s++ != c)
        --len;
    return len ? s : NULL;
}


/**
 * @brief: Decodes percent-encoded characters while copying the string @p seg
 *    of size @p length to @p buf. The caller of this function must ensure that
 *    the percent-encodings are correct (i.e. the character '%' is always followed
 *    by two hex digits. and that @p buf provides sufficient space to hold the result.
 *    This function is supposed to be called by make_decoded_option() only.
 *
 * @param seg:
 *    the segment to decode and copy
 * @param length:
 *    length of @p seg
 * @param buf:
 *    the result buffer
 */
static void decode_segment(const uint8_t *seg, size_t length, unsigned char *buf){

    // Iterate over all characters in the @seg 
    for(unsigned int i = 0; i < length; ++i, ++buf){
        if(seg[i] == '%'){
            *buf = (hexchar_to_dec(seg[i + 1]) << 4) + hexchar_to_dec(seg[i + 2]); 
            i += 2;
        }
        else
            *buf = seg[i];
    }
}


/**
 * @brief: Runs through the given path (or query) segment and checks if
 *    percent-encodings are correct
 * 
 * @param seg:
 *    segment to check  
 * @param length:
 *     @p segment's length
 * @param segment_size [out]:
 *     number of characters in the segments ('%'-encoded-3-byte characters 
 *     are trated as one)
 * @returns:
 *    0 on success
 *   -1 on error
 */
static int check_segment(const uint8_t *seg, size_t length, size_t *segment_size) {
    
    // Size of the segment (will be assigned to the @p segment_size)
    size_t s_size = 0;

    for(unsigned int i = 0; i < length; ++i){
        
        // Check if special character is properly encoded
        if(seg[i] == '%'){
            if(length - i < 2 || !(isxdigit(seg[i + 1]) && isxdigit(seg[i + 2])))
                return -1;
            i += 2;
        }

        ++s_size;
    }

  *segment_size = s_size;

  return 0;
}

/**
 * @brief: Writes a CoAP option from given string @p seg to @p buf. @p seg should
 *    point to a (percent-encoded) path or query segment of a coap_uri_t object.
 *    The created option will have type (delta) @c 0, and the length parameter will be set
 *    according to the size of the decoded string. On success, and sets @p optionsize
 *    to the option's size.
 * 
 *    This function is designed to be called from write_option() only.
 *
 * @param seg:
 *    the string to decode
 * @param length:
 *    the size of the percent-encoded string @p seg
 * @param buf [out]:
 *    the buffer to store the new coap option
 * @param buflen:
 *    the maximum size of @p buf
 * @param optionsize [out]:
 *    the option's size
 * @returns:
 *    0 on success and 
 *   -1 on error
 *
 */
static int make_decoded_option(
    const uint8_t *seg, 
    size_t length,
    unsigned char *buf, 
    size_t buflen, 
    size_t* optionsize
){
    // Check whether output buffer is writeable
    if (!buflen) {
        coap_log(LOG_DEBUG, "make_decoded_option(): buflen is 0!\n");
        return -1;
    }

    // Validate segment's content
    size_t segmentlen;
    if( check_segment(seg, length, &segmentlen) < 0)
        return -1;

    // Write option header using delta=0 and length=segmentlen
    size_t header_size = coap_opt_setheader(buf, buflen, 0, segmentlen);
    assert(header_size <= buflen);
    if (!header_size)
        return -1;    

    // Set buf to point the first byte of the option's value
    buf += header_size;

    // Check if output buffer
    if (buflen < header_size + segmentlen) {
        coap_log(LOG_DEBUG, "buffer too small for option\n");
        return -1;
    }

    // Write option's value
    decode_segment(seg, length, buf);

    // Compute total option's length
    *optionsize = header_size + segmentlen;

    return 0;
}


/**
 * @brief: Writes a CoAP option from given string @p seg to @p data->buf.s . @p seg 
 *    should point to a (percent-encoded) path or query segment of a coap_uri_t object.
 *    The created option will have type (delta) @c 0, and the length parameter will be
 *    set according to the size of the decoded string.
 * 
 *    This function is wrapper around make_decoded_option().
 * 
 * @param seg:
 *    the segment to crate option from 
 * @param len:
 *    the length of the @p seg
 * @param data:
 *    the output buffer structure
 */
static void write_option(const uint8_t *seg, size_t len, struct cnt_str *data) {

    assert(data);

    // Encode a new option to the buffer
    size_t optionsize;
    int res = make_decoded_option(seg, len, data->buf.s, data->buf.length, &optionsize);
    if (res == 0) {
        // Set buffer's pointer to point to the next byte after the encoded option
        data->buf.s += optionsize;
        data->buf.length -= optionsize;
        // Increment number of options written in the buffer
        data->n++;
    }
}


/**
 * @brief: Checks if path segment @p seg consists of one or two dots.
 * 
 * @param seg:
 *    segment to check
 * @param len:
 *    segment's length
 * @returns:
 *    non-zero 
 */
COAP_STATIC_INLINE
int dots(const uint8_t *seg, size_t len) {
    return (len && *seg == '.' && (len == 1 || (len == 2 && *(seg + 1) == '.') ) );
}

/**
 * @brief: Splits the given string into segments. The function is designed
 *    as an internal implementation of the @f coap_split_path().
 *
 * @param str:
 *    the URI string to be tokenized.
 * @param length:
 *    the length of @p str.
 * @param handler:
 *    a handler that is called with every token (i.e with segment that is not '.' or '..')
 * @param data:
 *    opaque data that is passed as the third argument to @p handler when called
 * @returns:
 *    yhe number of characters that have been parsed from @p str
 */
static 
size_t coap_split_path_impl(
    const uint8_t *str, 
    size_t length,
    segment_handler_t handler, 
    void *data
){
    const uint8_t *segment_start = str;

    // Iterate over the @p str path up to the '?' or '#' character
    unsigned int i;
    for(i = 0; i < length && !strnchr((const uint8_t *) "?#", 2, str[i]); ++i){
        
        // A new segment
        if(str[i] == '/'){
            // Call a handler if path's segment is not a '.' or '..'
            if (!dots(segment_start, (str + i) - segment_start))
                handler(segment_start, (str + i) - segment_start, data);
            // Set pto the first byte after '/'
            segment_start = str + i + 1;
        }
    }

    // Handle the final segment
    if (!dots(segment_start, (str + i) - segment_start))
        handler(segment_start, (str + i) - segment_start, data);

    return i;
}


/**
 * @returns:
 *    non-zero value if character is an unescaped character (considering the path string)
 *    zero otherwise
 */
COAP_STATIC_INLINE int
is_unescaped_in_path(const uint8_t c) {

  return ( c >= 'A'  && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) || ( c >= '0' && c <= '9' ) ||
           c == '-'  || c == '.'   ||   c == '_' || c == '~'   ||   c == '!' || c == '$'   || 
           c == '\'' || c == '('   ||   c == ')' || c == '*'   ||   c == '+' || c == ','   ||
           c == ';'  || c == '='   ||   c == ':' || c == '@'   || c == '&';
}

/**
 * @returns:
 *    non-zero value if character is an unescaped character (considering the query string)
 *    zero otherwise
 */
COAP_STATIC_INLINE int
is_unescaped_in_query(const uint8_t c) {
    return is_unescaped_in_path(c) || c == '/' || c == '?';
}

/**
 * @brief: Extracts query / path string from request PDU according to the rules
 *    in RFC 8252: Chapter 6.5. It function is an internal implementation of
 *    @f coap_get_query() and @f coap_get_path()
 * 
 * @param request:
 *      request PDU.
 * @param filter_type:
 *      options filter type used to parse segments; either COAP_OPTION_URI_QUERY
 *      or COAP_OPTION_URI_PATH
 * @returns:
 *    reconstructed and escaped query / path string
 * 
 */
static
coap_string_t *coap_get_seg_impl(const coap_pdu_t *request, unsigned int filter_type){

    static const uint8_t hex[] = "0123456789ABCDEF";

    // Create an option filter for Uri-Query options
    coap_opt_filter_t filter;
    coap_option_filter_clear(filter);
    coap_option_filter_set(filter, filter_type);

    // Create filtering options iterator
    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(request, &opt_iter, filter);

    coap_opt_t *opt_tmp;
    size_t length = 0;

    // Iterate over all Uri-Query options to establish number of bytes required to store the whole query
    while ((opt_tmp = coap_option_next(&opt_iter))) {

        // Get option's value and length
        uint16_t seg_len = coap_opt_length(opt_tmp);
        const uint8_t *seg = coap_opt_value(opt_tmp);
        
        // Iterate over the segment
        for (uint16_t i = 0; i < seg_len; i++) {
            // If character is unescaped, it will be directly encoded (on 1 byte) 
            if ((COAP_OPTION_URI_QUERY && is_unescaped_in_query(seg[i])) ||
                (COAP_OPTION_URI_PATH  && is_unescaped_in_path(seg[i])))
                length += 1;
            // Otherwise, it will be encoded indirectly (on 3 bytes) 
            else
                length += 3;
        }

        // Count byte for the leading '&' / '/'
        length += 1;
    }

    // There is no the leading '&' / '/' of the first segment
    if (length > 0)
        length -= 1;

    coap_string_t *string = NULL;

    // If there were some Uri-Query among options or if we deal with Uri-Path
    if (length > 0 || filter_type == COAP_OPTION_URI_PATH) {

        // Allocate a new string for the whole query
        if ((string = coap_new_string(length))) {

            // Initialize the string
            string->length = length;
            unsigned char *segment_str = string->s;
            
            // Iterate over all options one more time to concatenate queries into the segment_str
            coap_option_iterator_init(request, &opt_iter, filter);
            while ((opt_tmp = coap_option_next(&opt_iter))) {

                // Put an '&' / '/' between subsequent segments of the query
                if (segment_str != string->s){
                    if (filter_type == COAP_OPTION_URI_QUERY)
                        *segment_str++ =  '&';
                    else if(filter_type == COAP_OPTION_URI_PATH)
                        *segment_str++ =  '/';
                }

                // Get option's value and length
                uint16_t seg_len = coap_opt_length(opt_tmp);
                const uint8_t *seg= coap_opt_value(opt_tmp);

                // Iterate over the query's segment to encode it into the final string
                for (unsigned i = 0; i < seg_len; i++) {

                    // Unescaped characters are encoded directly
                    if (is_unescaped_in_query(seg[i]))
                        *segment_str++ = seg[i];
                    // Escaped characters are encoded in 3-bytes '%' notation
                    else {
                        *segment_str++ = '%';
                        *segment_str++ = hex[seg[i] >> 4];
                        *segment_str++ = hex[seg[i] & 0x0F];
                    }
                }
            }
        }
    }

    return string;
}
