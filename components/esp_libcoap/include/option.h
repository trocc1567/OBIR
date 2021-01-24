/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-30 22:10:58
 *  Description:
 * 
 *      File contains main API for CoAP's options creation, parsing and manipulation.
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
 * option.h -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file option.h
 * @brief Helpers for handling options in CoAP PDUs
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_OPTION_H_
#define COAP_OPTION_H_

#include "bits.h"
#include "pdu.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/**
 * @brief: The number of option types (codes below 256) that can be stored in an option filter.
 * 
 *    Each @t coap_option_filter_t object reserves COAP_OPT_FILTER_SHORT (rounded up to the
 *    closest even value) bytes for short options.
 * 
 * @note: COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be at most 16
 */
#define COAP_OPT_FILTER_SHORT 6

/**
 * @brief: The number of option types (codes grater or equal to 256) that can be stored in an
 *    option filter.
 * 
 *    Each coap_option_filter_t object reserves COAP_OPT_FILTER_LONG * 2 bytes for short options.
 * 
 * @note: COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be at most 16
 */
#define COAP_OPT_FILTER_LONG  2

/**
 * @brief: Ensure that COAP_OPT_FILTER_SHORT and COAP_OPT_FILTER_LONG are set correctly. 
 */
#if (COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG > 16)
#error COAP_OPT_FILTER_SHORT + COAP_OPT_FILTER_LONG must be less or equal 16
#endif

/** 
 * @brief: The number of elements in @t coap_opt_filter_t.
 */
#define COAP_OPT_FILTER_SIZE \
  (((COAP_OPT_FILTER_SHORT + 1) >> 1) + COAP_OPT_FILTER_LONG) +1

/** 
 * @brief: Pre-defined filter that includes all options. 
 */
#define COAP_OPT_ALL NULL


// The highest option number 
#define COAP_MAX_OPT 65535 

/*
 * @brief: CoAP option types 
 * 
 * @note: Be sure to update coap_option_check_critical() when adding options
 */
#define COAP_OPTION_IF_MATCH        1 /* C,     opaque,     0-8 B, (none)                         */
#define COAP_OPTION_URI_HOST        3 /* C,     String,   1-255 B,  destination address           */
#define COAP_OPTION_ETAG            4 /* E,     opaque,     1-8 B, (none)                         */
#define COAP_OPTION_IF_NONE_MATCH   5 /* -,      empty,       0 B, (none)                         */
#define COAP_OPTION_URI_PORT        7 /* C,       uint,     0-2 B,  destination port              */
#define COAP_OPTION_LOCATION_PATH   8 /* E,     String,   0-255 B,  -                             */
#define COAP_OPTION_URI_PATH       11 /* C,     String,   0-255 B, (none)                         */
#define COAP_OPTION_CONTENT_FORMAT 12 /* E,       uint,     0-2 B, (none)                         */
#define COAP_OPTION_MAXAGE         14 /* E,       uint,    0--4 B,  60 Seconds                    */
#define COAP_OPTION_URI_QUERY      15 /* C,     String,   1-255 B, (none)                         */
#define COAP_OPTION_ACCEPT         17 /* C,       uint,     0-2 B, (none)                         */
#define COAP_OPTION_LOCATION_QUERY 20 /* E,     String,   0-255 B, (none)                         */
#define COAP_OPTION_SIZE2          28 /* E,       uint,     0-4 B, (none)                         */
#define COAP_OPTION_PROXY_URI      35 /* C,     String,  1-1034 B, (none)                         */
#define COAP_OPTION_PROXY_SCHEME   39 /* C,     String,   1-255 B, (none)                         */
#define COAP_OPTION_SIZE1          60 /* E,       uint,     0-4 B, (none)                         */
#define COAP_OPTION_OBSERVE         6 /* E, empty/uint, 0 B/0-3 B, (none)              (RFC 7641) */
#define COAP_OPTION_BLOCK2         23 /* C,       uint,    0--3 B, (none)              (RFC 7959) */
#define COAP_OPTION_BLOCK1         27 /* C,       uint,    0--3 B, (none)              (RFC 7959) */
#define COAP_OPTION_NORESPONSE    258 /* N,       uint,    0--1 B,  0                  (RFC 7967) */
// Synonymous options
#define COAP_OPTION_CONTENT_TYPE \
    COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_SUBSCRIPTION \
    COAP_OPTION_OBSERVE

/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Basic CoAP option identifier.
 * 
 * @note: Use byte-oriented access methods here because sliding a complex struct
 *    @t coap_opt_t over the data buffer may cause bus error on certain platforms.
 */
typedef uint8_t coap_opt_t;

/**
 * @brief: Representation of CoAP options.
 */
typedef struct {

    /**
     * @note: Options in the header are always sorted so that they can be unambiguously
     *    identified not by their code but by the increment in the code number between
     *    subsequent options.
     */

    // Increment from the previousoption ID to the current
    uint16_t delta;
    // Option's value field length
    size_t length;
    // Option value field
    const uint8_t *value;
    
} coap_option_t;

/**
 * @brief: Fixed-size vector used for option filtering. It is large enough to hold
 *    COAP_OPT_FILTER_SHORT entries with an option number between 0 and 255, and
 *    COAP_OPT_FILTER_LONG entries with an option number between 256 and 65535.
 *    Its internal structure is:
 *
 * @code
 * 
 *    struct {
 *    uint16_t mask;
 *    uint16_t long_opts[COAP_OPT_FILTER_LONG];
 *    uint8_t short_opts[COAP_OPT_FILTER_SHORT];
 *    }
 * 
 * @endcode
 *
 * @attr mask:
 *    a bit vector that indicates which fields in the remaining array are used. The first
 *    COAP_OPT_FILTER_LONG bits correspond to the long option types that are stored in the
 *    elements from index 1 to COAP_OPT_FILTER_LONG. The next COAP_OPT_FILTER_SHORT bits
 *    correspond to the short option types that are stored in the elements from index
 *    COAP_OPT_FILTER_LONG + 1 to COAP_OPT_FILTER_LONG + COAP_OPT_FILTER_SHORT
 * @attr long_opts:
 *    long options
 * @attr short_opts:
 *    short options
 */
typedef uint16_t coap_opt_filter_t[COAP_OPT_FILTER_SIZE];

/**
 * @brief: Iterator to run through PDU options. This object must be initialized with 
 *    coap_option_iterator_init(). Call coap_option_next() to walk through the list of
 *    options until coap_option_next() returns @c NULL.
 *
 * @code
 * 
 *    coap_opt_t *option;
 *    coap_opt_iterator_t opt_iter;
 *    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
 *   
 *    while ((option = coap_option_next(&opt_iter))) {
 *      ... do something with option ...
 *    }
 * 
 * @endcode
 * 
 */
typedef struct {
  
    // Pointer to the unparsed next option
    coap_opt_t *next_option;

    // Remaining length of PDU
    size_t length;
    // Decoded option type
    uint16_t type;

    // Iterator object is ok if not set
    unsigned int bad:1;
    // Denotes whether or not filter is used
    unsigned int filtered:1;
    // Option filter
    coap_opt_filter_t filter;

} coap_opt_iterator_t;


/**
 * @brief: Representation of the list of CoAP options to install
 *
 * @code
 * 
 *    coap_optlist_t *optlist = NULL;
 *    coap_pdu_t *pdu = coap_new_pdu(session);
 *   
 *    ... other set up code ...
 * 
 *    coap_insert_optlist(
 *        &optlist_chain,
 *        coap_new_optlist(
 *            COAP_OPTION_OBSERVE,
 *            COAP_OBSERVE_ESTABLISH,
 *            NULL
 *        )
 *    );
 * 
 *    coap_add_optlist_pdu(pdu, &optlist_chain);
 * 
 *    ... other code ...
 * 
 *    coap_delete_optlist(optlist_chain);
 * 
 * @endcode
 */
typedef struct coap_optlist_t {

  // Next entry in the optlist chain
  struct coap_optlist_t *next;

  // The option number (no delta coding)
  uint16_t number;
  // The option's value field's length
  size_t length;
  // The option's value field
  uint8_t *data;

} coap_optlist_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Parses the option pointed to by @p opt into @p result. An error is
 *    signaled when illegal delta or length values are encountered or when option
 *    parsing would result in reading past the option (i.e. beyond opt + length).
 *
 * @param opt:
 *    the beginning of the option to parse
 * @param length:
 *    the maximum length of @p opt
 * @param result:
 *    a pointer to the @t coap_option_t structure that is filled with actual values
 *    if coap_opt_parse() > 0
 * @returns:
 *    the number of bytes parsed on success
 *    0 on error
 */
size_t coap_opt_parse(
    const coap_opt_t *opt,
    size_t length,
    coap_option_t *result
);

/**
 * @brief: Returns the size of the given option, taking into account a possible option jump.
 *
 * @param opt:
 *    an option jump or the beginning of the option
 * @returns:
 *    the number of bytes between @p opt and the end of the option starting at @p opt 
 *    0 in case of an error, as options need at least one byte storage space.
 */
size_t coap_opt_size(const coap_opt_t *opt);

/**
 * @brief: Sets the corresponding entry for @p type in @p filter. 
 *
 * @param filter:
 *    the filter object to change
 * @param type:
 *    the type for which the bit should be set
 * @returns:
 *    1 if bit was set
 *    0 on error (i.e. when the given type does not fit in the filter)
 */
int coap_option_filter_set(coap_opt_filter_t filter, uint16_t type);

/**
 * @brief: Clears the corresponding entry for @p type in @p filter.
 *
 * @param filter:
 *    the filter object to change
 * @param type:
 *    the type that should be cleared from the filter
 *
 * @returns:
 *    1 if bit was set
 *    0 on error (i.e. when the given type does not fit in the filter)
 */
int coap_option_filter_unset(coap_opt_filter_t filter, uint16_t type);

/**
 * @brief: Checks if @p type is contained in @p filter. 
 *
 * @param filter:
 *    the filter object to search
 * @param type:
 *    the type to search for
 * @returns:
 *    1 if @p type was found
 *    0 if not
 *   -1 on error (i.e. when the given type does not fit in the filter)
 */
int coap_option_filter_get(coap_opt_filter_t filter, uint16_t type);

/**
 * @brief: Initializes the given option iterator @p opt_iter to point to the beginning of the
 *    @p pdu's option list.
 *
 * @param pdu:
 *    the PDU the options of which should be walked through
 * @param opt_iter:
 *    an iterator object that will be initilized
 * @param filter:
 *    an optional option type filter. With @p type != @c COAP_OPT_ALL, coap_option_next()
 *    will return only options matching this bitmask. Fence-post options 14, 28, 42, ...
 *    are always skipped.
 * @returns:
 *    the iterator object @p opt_iter on success
 *    NULL on error (i.e. when no options exist)
 * 
 * @note: A length check on the option list must be performed before coap_option_iterator_init()
 *    is called.
 */
coap_opt_iterator_t *coap_option_iterator_init(
    const coap_pdu_t *pdu,
    coap_opt_iterator_t *opt_iter,
    const coap_opt_filter_t filter
);

/**
 * @brief: Updates the iterator @p opt_iter to point to the next option. The contents of @p opt_iter will be
 *    updated. In particular, @c opt_iter->n specifies the current option's ordinal number (counted from
 *    1), @p opt_iter->type is the option's type code, and @p opt_iter->option points to the beginning of the
 *    current option itself. When advanced past the last option, @p opt_iter->option will be NULL.
 *
 * @param opt_iter:
 *    the option iterator to update
 * @returns:
 *    the next option on success
 *    NULL if no more options exist
 * 
 * @note: Note that options are skipped whose corresponding bits in the filter specified with
 *    coap_option_iterator_init() are 0. Options with type codes that do not fit in this filter
 *    hence will always be returned.
 */
coap_opt_t *coap_option_next(coap_opt_iterator_t *opt_iter);

/**
 * @brief: Retrieves the first option of type @p type from @p pdu. @p opt_iter must point to a
 *    @t coap_opt_iterator_t object that will be initialized by this function to a filter only options
 *    with code @p type.
 *
 * @param pdu:
 *    the PDU to parse for options
 * @param type:
 *    the option type code to search for
 * @param opt_iter:
 *    an iterator object to use
 * @returns:
 *    a pointer to the first option of type @p type
 *    NULL if not found
 */
coap_opt_t *coap_check_option(
    coap_pdu_t *pdu,
    uint16_t type,
    coap_opt_iterator_t *opt_iter
);

/**
 * @brief: Encodes the given delta and length values into @p opt.
 *
 * @param opt [out]:
 *    the option buffer space where @p delta and @p length are written
 * @param maxlen:
 *    the maximum length of @p opt buffer
 * @param delta:
 *    the actual delta value to encode
 * @param length:
 *    the actual length value to encode
 * @returns:
 *    the number of bytes used on success
 *    0 on error
 * 
 * @note: The result indicates by how many bytes @p opt must be advanced to 
 *    encode the option value.
 */
size_t coap_opt_setheader(
    coap_opt_t *opt,
    size_t maxlen,
    uint16_t delta,
    size_t length
);

/**
 * @brief: Compute storage bytes needed for an option with given @p delta and
 *    @p length.
 *
 * @param delta:
 *    the option delta
 * @param length:
 *    the option length
 * @returns:
 *    the number of bytes required to encode this option
 */
size_t coap_opt_encode_size(uint16_t delta, size_t length);

/**
 * @brief: Encodes option with given @p delta into @p opt. 
 *
 * @param opt [out]:
 *    the option buffer space where @p val is written
 * @param opt_len:
 *    maximum length of @p opt
 * @param delta:
 *    the option delta
 * @param val:
 *    the option value to copy into @p opt
 * @param length:
 *    actual length of @p val
 * @returns:
 *    the number of bytes that have been written to @p opt on success
 *    0 on error. 
 * 
 *    The return value will always be less than @p opt_len.
 * 
 * @note: Error happens especially often when @p opt does not provide sufficient 
 *    space to store the option value, delta, and option jumps when required.
 */
size_t coap_opt_encode(
    coap_opt_t *opt,
    size_t opt_len,
    uint16_t delta,
    size_t length,
    const uint8_t *val    
);

/**
 * @brief: Decodes the delta value of the next option. The caller of this function must ensure
 *    that it does not read over the boundaries of @p opt (e.g. by calling coap_opt_check_delta()).
 *
 * @param opt:
 *    the option to examine
 * @returns:
 *    the number of bytes read
 *    0 on error
 */
uint16_t coap_opt_delta(const coap_opt_t *opt);

/**
 * @param opt:
 *    the option whose length should be returned
 * @returns:
 *    the option's length on success
 *    0 on error
 *
 * @note: The rationale for using 0 in case of an error is that in most contexts, the result of this
 *    function is used to skip the next coap_opt_length() bytes.
 * @note: @p opt must point to an option jump or the beginning of the optisize_t lengthon.
 */
uint16_t coap_opt_length(const coap_opt_t *opt);

/**
 * @param opt:
 *    the option whose value should be returned
 * @returns:
 *    pointer to the option value on success
 *    NULL if @p opt is not a valid option
 * 
 * @note: @p opt must point to an option jump or the beginning of the option.
 */
const uint8_t *coap_opt_value(const coap_opt_t *opt);

/**
 * @brief: Create a new optlist entry.
 *
 * @param number:
 *    the option number (COAP_OPTION_*)
 * @param length:
 *    the option length
 * @param data:
 *    the option value data
 * @returns:
 *    a pointer to the new optlist entry on success
 *    NULL on error
 */
coap_optlist_t *coap_new_optlist(
    uint16_t number,
    size_t length,
    const uint8_t *data
);

/**
 * @brief: Sorts the current optlist of @p optlist (as per RFC7272 ordering requirements)
 *    and then adds it to the @p pdu.
 *
 * @param pdu:
 *    the pdu to add the options to from the list
 * @param optlist:
 *    head node of the options' list to be inserted into @p pdu
 * @returns:
 *    1 if succesful
 *    0 if failure
 */
int coap_add_optlist_pdu(
    coap_pdu_t *pdu,
    coap_optlist_t** optlist
);

/**
 * @brief: Adds @p optlist to the given @p optlist. The @p optlist variable is
 *    set to NULL before the initial call to coap_insert_optlist(). 
 *
 * @param optlist:
 *    the chain to add optlist to
 * @param optlist_node:
 *    the optlist's element to add to the queue
 * @returns:
 *    1 on success
 *    0 on failure
 * 
 * @note: The @p optlist will need to be deleted using coap_delete_optlist() when no 
 *    longer required.
 */
int coap_insert_optlist(
    coap_optlist_t **optlist,
    coap_optlist_t *optlist_node
);

/**
 * @brief: Removes all entries from the @p optlist_chain, freeing off their memory usage.
 *
 * @param optlist_chain:
 *     the optlist chain to remove all the entries from
 */
void coap_delete_optlist(coap_optlist_t *optlist_chain);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Clears @p filter.
 *
 * @param f:
 *    the filter to clear
 */
COAP_STATIC_INLINE void
coap_option_filter_clear(coap_opt_filter_t filter){
    memset(filter, 0, sizeof(coap_opt_filter_t));
}

#endif /* COAP_OPTION_H_ */
