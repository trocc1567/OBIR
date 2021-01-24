/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 05:03:03
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

/*
 * option.c -- helpers for handling options in CoAP PDUs
 *
 * Copyright (C) 2010-2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

# include <assert.h>
#include <stdio.h>
#include <string.h>

#include "libcoap.h"
#include "option.h"
#include "encode.h"
#include "coap_config.h"
#include "coap_debug.h"
#include "mem.h"
#include "utlist.h"

COAP_STATIC_INLINE int is_long_option(uint16_t type);
COAP_STATIC_INLINE int opt_finished(coap_opt_iterator_t *opt_iter);
static int coap_option_filter_op(coap_opt_filter_t filter, uint16_t type, int filter_op); 
static int order_opts(void *a, void *b);
static void coap_internal_delete(coap_optlist_t *node);


/* -------------------------------------------- [Macrofeinitions] --------------------------------------------- */

/**
 * @brief: Helper macro used to safely move @p option pointer forward 
 *    and update value of the remaining option buffer's length
 * 
 * @param option:
 *    option pointer to move forward
 * @param length:
 *    length of the option buffer that @p option points to 
 * @param step:
 *    number of steps by which @p option should be moved
 */
#define ADVANCE_OPT(option,length,step)                        \
    if ((length) < (step)) {                                   \
        coap_log(LOG_DEBUG, "cannot advance opt past end\n");  \
        return 0;                                              \
    } else {                                                   \
        (length) -= (step);                                    \
        (option) = (option) + (step);                          \
    }

/**
 * @brief: Helper macro used to sequentially forward the option's pointer and return
 *    from the function using the macro when @p option pointer was moved beyond the last
 *    element of the buffer.
 */
#define ADVANCE_OPT_CHECK(option,length,step) \
    do {                                      \
        ADVANCE_OPT(option,length,step);      \
        if ((length) < 1)                     \
            return 0;                         \
    } while (0)


/**
 * @brief: Masks used to lift out an option's type from the option filter
 *    @t opt_filter 
 */
#define LONG_MASK ((1 << COAP_OPT_FILTER_LONG) - 1)
#define SHORT_MASK \
  (~LONG_MASK & ((1 << (COAP_OPT_FILTER_LONG + COAP_OPT_FILTER_SHORT)) - 1))


/**
 * @brief: Operation specifiers for @fcoap_filter_op()
 */
enum filter_op_t { FILTER_SET, FILTER_CLEAR, FILTER_GET };


/* ---------------------------------------- [Global and static data] ------------------------------------------ */

/**
 * @brief: Local structure used for options filtering. This is in fact a named
 *    mapping of the data stored in the @t coap_opt_filter_t.
 */
typedef struct {

    /**
     * @brief: Bit-wise mask used to denote what filters (of types described by the @a long_opts and
     *    @a short_opts) are active. When Nth bit in this mask is set:
     * 
     *       - if N < COAP_OPT_FILTER_LONG, the Nth element in @a long_opts describes
     *         type of the filtered option
     *       - if N >= COAP_OPT_FILTER_LONG, the (N - COAP_OPT_FILTER_LONG)th  element
     *         in @a short_ops describes type of the filtered option
     */
    uint16_t mask;

    // Filtered options
    uint16_t long_opts[COAP_OPT_FILTER_LONG];
    uint8_t short_opts[COAP_OPT_FILTER_SHORT];
    
} opt_filter;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

size_t coap_opt_parse(
    const coap_opt_t *opt, 
    size_t length, 
    coap_option_t *result
) {
    assert(opt); 
    assert(result);

    if (length < 1)
        return 0;

    result->delta = (*opt & 0xf0) >> 4;
    result->length = *opt & 0x0f;

    //  Pointer to the option's buffer start (@p opt will be forwareded within the function)
    const coap_opt_t *opt_start = opt;

    // Compute option's delta and set @p opt to the first byt after delta's encoding
    result->delta = coap_opt_delta(opt_start);
    if(result->delta == 0 && (*opt & 0xf0) != 0){
        result->delta = (*opt & 0xf0) >> 4;
        if(*opt != COAP_PAYLOAD_START)
            coap_log(LOG_DEBUG, "coap_opt_parse: ignored reserved option delta 15\n");
        return 0;
    }
    else if(result->delta >= 269)
        ADVANCE_OPT_CHECK(opt, length, 2);
    else if(result->delta >= 13)
        ADVANCE_OPT_CHECK(opt, length, 1);
        
    // Compute option's length and set @p opt to the first byt after length's encoding
    result->length = coap_opt_length(opt_start);
    if(result->length == 0 && (*opt & 0x0f) != 0){
        result->length = *opt & 0x0f;
        return 0;
    }
    else if(result->length >= 269)
        ADVANCE_OPT_CHECK(opt, length, 2);
    else if(result->length >= 13)
        ADVANCE_OPT_CHECK(opt, length, 1);

    // Move @p opt to the first byte of data (if any) and set option's value pointer to it
    ADVANCE_OPT(opt, length, 1);
    result->value = opt;

    // Check if the length encoded is correct
    if (length < result->length) {
        coap_log(LOG_DEBUG, "invalid option length\n");
        return 0;
    }

    return (opt + result->length) - opt_start;
}


coap_opt_iterator_t *coap_option_iterator_init(
    const coap_pdu_t *pdu, 
    coap_opt_iterator_t *opt_iter,
    const coap_opt_filter_t filter
) {
    assert(pdu);
    assert(pdu->token);
    assert(opt_iter);

    // Clear the iterator
    memset(opt_iter, 0, sizeof(coap_opt_iterator_t));

    //Initialize iterator to the first option in the PDU (if present)
    opt_iter->next_option = pdu->token + pdu->token_length;
    // Check whether options might be allocated to the PDU
    if (pdu->token + pdu->used_size <= opt_iter->next_option) {
        opt_iter->bad = 1;
        return NULL;
    }

    // Set maximum length of the option's are (possibly this region holds also payload)
    opt_iter->length = pdu->used_size - pdu->token_length;

    // Apply a filter to the iterator (if present)
    if (filter) {
        memcpy(opt_iter->filter, filter, sizeof(coap_opt_filter_t));
        opt_iter->filtered = 1;
    }

    return opt_iter;
}


coap_opt_t *coap_option_next(coap_opt_iterator_t *opt_iter) {

    assert(opt_iter);
    if (opt_finished(opt_iter))
        return NULL;

    // Next option (the one to be returned)
    coap_opt_t *current_opt = NULL;

    // Iterate over subsequent options and break when the first non-filtered-out one appears
    while (true) {

        /** 
         * @note: @p opt_iter->option always points to the next option to be delivered;
         *    when opt_finished() filters out any bad state of the iterator, we can assume
         *    that @p opt_iter->option is valid. 
         */

        // Get the next option
        current_opt = opt_iter->next_option;

        // Parse an option from byte-vector to the dedicated structure
        coap_option_t option;
        size_t optsize = coap_opt_parse(opt_iter->next_option, opt_iter->length, &option);

        // Advance internal pointer to next option, if parsing succeeded
        if (optsize) {
            opt_iter->next_option += optsize;
            opt_iter->length -= optsize;
            opt_iter->type += option.delta;
        } else {
            opt_iter->bad = 1;
            return NULL;
        }

        /**
         * @brief: Exit the while loop when:
         *   - no filtering is done at all
         *   - the filter matches for the current option
         *   - the filter is too small for the current option number
         */

        int filter_found = 0;

        // Filterring off
        if (!opt_iter->filtered)
            break;
        // Filter matched
        else if((filter_found = coap_option_filter_get(opt_iter->filter, opt_iter->type) > 0))
            break;
        // Filtering error
        else if (filter_found < 0) {
            opt_iter->bad = 1;
            return NULL;
        }
    }

    return current_opt;
}


coap_opt_t *coap_check_option(
    coap_pdu_t *pdu, 
    uint16_t type,
    coap_opt_iterator_t *opt_iter
) {
    coap_opt_filter_t opt_filter;

    // Reset the filter to the given @p type
    coap_option_filter_clear(opt_filter);
    coap_option_filter_set(opt_filter, type);

    // Bind the iterator to the @p pdu's options
    coap_option_iterator_init(pdu, opt_iter, opt_filter);

    // Try to parse the first option in the @p pdu
    return coap_option_next(opt_iter);
}


uint16_t coap_opt_delta(const coap_opt_t *opt) {
  
    // Shortes options have their delta encoded onto higher 4 bits of the 1st byte
    uint16_t delta = (*opt++ & 0xf0) >> 4;

    switch (delta) {
        case 15: 
            return 0;
        // If delta = 14, it's notation will be extended by 2 bytes
        case 14:
            delta = (opt[0] << 8) + opt[1] + 269;
            if (delta < 269) {
                coap_log(LOG_DEBUG, "coap_opt_delta: delta too large\n");
                return 0;
            }
            break;
        // If delta = 13, it's notation will be extended by 1 bytes
        case 13:
            delta += opt[0];
            break;
    }

    return delta;
}


uint16_t coap_opt_length(const coap_opt_t *opt) {

    // Shortes options have their length encoded onto lower 4 bits of the 1st byte
    uint16_t length = *opt & 0x0f;

    // Inspect "Option Delta" field to check if delta notation is extended
    switch (*opt++ & 0xf0) {
    case 0xf0:
        return 0;
    // If delta = 14, it's notation will be extended by 2 bytes
    // (i.e potential length's extension will start at 3rd byte)
    case 0xe0:
        opt += 2;
        break;
    // If delta = 13, it's notation will be extended by 1 byte
    // (i.e potential length's extension will start at 2nd byte)
    case 0xd0:
        opt += 1;
        break;
    }

    // Inspect "Option Length" field to check if length notation is extended
    switch (length) {
        case 0x0f:
            coap_log(LOG_DEBUG, "illegal option length\n");
            return 0;
        // If length notation is extended by 2 bytes; these bytes are equal to option's
        // value length substracted by 269
        case 0x0e:
            length = (opt[0] << 8) + opt[1] + 269;
            break;
        // If length notation is extended by 1 bytes; this bytes is equal to option's
        // value length substracted by 13 (i.e 0x0d)
        case 0x0d:
            length += opt[0];
            break;
    }

    return length;
}


const uint8_t *coap_opt_value(const coap_opt_t *opt){

    // Default offset of value in the option's field is 1 byte
    size_t data_offsset = 1;

    // Inspect "Option Delta" part of the option's header
    switch (*opt & 0xf0) {
        case 0xf0:
            coap_log(LOG_DEBUG, "illegal option delta\n");
            return 0;
        // If delta = 14, it's notation will be extended by 2 bytes
        case 0xe0:
            data_offsset += 2;
            break;
        // If delta = 13, it's notation will be extended by 1 byte
        case 0xd0:
            data_offsset += 1;
            break;
    }

    // Inspect "Option Length" part of the option's ehader
    switch (*opt & 0x0f) {
        case 0x0f:
            coap_log(LOG_DEBUG, "illegal option length\n");
            return 0;
        // If length = 14, it's notation will be extended by 2 bytes
        case 0x0e:
            data_offsset += 2;
            break;
        // If length = 13, it's notation will be extended by 1 byte
        case 0x0d:
            data_offsset += 1;
            break;

    }

    return (const uint8_t *)opt + data_offsset;
}


size_t coap_opt_size(const coap_opt_t *opt) {

    /**
     * @note: Here, we assume that @p opt is encoded correctly and
     *   pass a (technically) unlimited size of the option's buffer
     *  to the @f coap_opt_parse function.
     */

    coap_option_t option;
    return coap_opt_parse(opt, (size_t) UINT_MAX, &option);
}


size_t coap_opt_setheader(
    coap_opt_t *opt,
    size_t maxlen,
    uint16_t delta, 
    size_t length
) {
    assert(opt);
    if (maxlen == 0)
        return 0;

    // Number of bytes from @p opt to the first byte of option's value
    size_t data_offset = 0;

    /* ---------------------- Delta encoding ---------------------- */

    // No extesion
    if (delta < 13)
        opt[0] = (coap_opt_t) (delta << 4);
    // One-byte extension
    else if (delta < 269) {

        // Verify buffer's length
        if (maxlen < 2) {
            coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n", delta);
            return 0;
        }
        opt[0] = 0xd0;
        opt[++data_offset] = (coap_opt_t)(delta - 13);
    } 
    // Two-bytes extension
    else {

        // Verify buffer's length
        if (maxlen < 3) {
            coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n", delta);
            return 0;
        }

        opt[0] = 0xe0;
        opt[++data_offset] = ((delta - 269) >> 8) & 0xff;
        opt[++data_offset] = (delta - 269) & 0xff;
    }


    /* --------------------- Length encoding ---------------------- */
    
    // No extesion
    if (length < 13)
        opt[0] |= length & 0x0f;
    // One-byte extension
    else if (length < 269) {
        
        // Verify buffer's length
        if (maxlen < data_offset + 2) {
            coap_log(LOG_DEBUG, "insufficient space to encode option length %lu\n", (unsigned long) length);
            return 0;
        }

        opt[0] |= 0x0d;
        opt[++data_offset] = (coap_opt_t)(length - 13);
    } 
    // Two-bytes extension
    else {

        // Verify buffer's length
        if (maxlen < data_offset + 3) {
            coap_log(LOG_DEBUG, "insufficient space to encode option delta %d\n", delta);
            return 0;
        }

        opt[0] |= 0x0e;
        opt[++data_offset] = ((length - 269) >> 8) & 0xff;
        opt[++data_offset] = (length - 269) & 0xff;
    }

    return data_offset + 1;
}


size_t coap_opt_encode_size(
    uint16_t delta, 
    size_t length
) {
    // Option consist of at least 1-byte header
    size_t size = 1;

    // Option's code encoding can be extended by 1 or 2 bytes
    if (delta >= 13) {
        if (delta < 269)
            size += 1;
        else
            size += 2;
    }

    // Option's length encoding can be extended by 1 or 2 bytes
    if (length >= 13) {
        if (length < 269)
            size += 1;
        else
            size += 2;
    }

    return size + length;
}


size_t coap_opt_encode(
    coap_opt_t *opt, 
    size_t maxlen, 
    uint16_t delta,
    size_t length,
    const uint8_t *val    
) {
    // Compute required size for storing the option and check if it fits the buffer
    size_t size = coap_opt_encode_size(delta, length);
    if (size > maxlen) {
        coap_log(LOG_DEBUG, "coap_opt_encode: option's buffer too small\n");
        return 0;
    }

    // Encode the header
    size_t opt_offset = coap_opt_setheader(opt, maxlen, delta, length);
    if (opt_offset == 0) {
        coap_log(LOG_DEBUG, "coap_opt_encode: cannot set option header\n");
        return 0;
    }

    // Copy option's value, if given
    if (val){
        opt += opt_offset;
        memcpy(opt, val, length);
    }

    return size;
}


int coap_option_filter_set(coap_opt_filter_t filter, uint16_t type) {
    return coap_option_filter_op(filter, type, FILTER_SET);
}


int coap_option_filter_unset(coap_opt_filter_t filter, uint16_t type) {
    return coap_option_filter_op(filter, type, FILTER_CLEAR);
}


/**
 * @note: [?] For some reson here was an ugly cast: 
 * 
 * @code
 *    return coap_option_filter_op((uint16_t *)filter, type, FILTER_GET);
 * @endcode
 * 
 *   In the author's opinion: "FILTER_GET wont change filter but as *_set and *_unset do,
 *   the function does not take a const". The cast was removed. Everything works fin by now.
 * 
 */
int coap_option_filter_get(coap_opt_filter_t filter, uint16_t type) {
    return coap_option_filter_op(filter, type, FILTER_GET);
}


coap_optlist_t *coap_new_optlist(
    uint16_t number,
    size_t length,
    const uint8_t *data
) {
    // Allocate memory for the list's node and the option's value field
    coap_optlist_t *node = 
        (coap_optlist_t*) coap_malloc(sizeof(coap_optlist_t) + length);

    // Initialize the node, if allocation suceeded
    if (node) {
        memset(node, 0, (sizeof(coap_optlist_t) + length));
        node->number = number;
        node->length = length;
        node->data = (uint8_t *)&node[1];
        memcpy(node->data, data, length);

    } else
        coap_log(LOG_WARNING, "coap_new_optlist: malloc failure\n");

    return node;
}


int coap_add_optlist_pdu(coap_pdu_t *pdu, coap_optlist_t** options) {

    if (options && *options) {

        // Sort options for delta encoding */
        LL_SORT((*options), order_opts);

        // Add options to the @p pdu
        coap_optlist_t *opt;
        LL_FOREACH((*options), opt)
            coap_add_option(pdu, opt->number, opt->length, opt->data);

        return 1;
    }
    return 0;
}


int coap_insert_optlist(coap_optlist_t **head, coap_optlist_t *node) {

    if (node)
        LL_APPEND((*head), node);
    else
        coap_log(LOG_DEBUG, "optlist not provided\n");

    return node != NULL;
}


void coap_delete_optlist(coap_optlist_t *optlist) {
    if (!optlist)
        return;
    coap_optlist_t *node, *tmp_node;
    LL_FOREACH_SAFE(optlist, node, tmp_node)
        coap_internal_delete(node);
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */

/**
 * @param type:
 *    option's type (i.e. code)
 * @returns:
 *    true if @p type denotes an option type larger than 255 bytes
 *    false otherwise
 */
COAP_STATIC_INLINE int is_long_option(uint16_t type) { return type > 255; }


/**
 * @brief: Checks whether the @p opt_iter iterator can be forwarded to the next option
 * 
 * @param opt_iter:
 *    option iterator to check
 * @return:
 *    != 0, when operator can be forwarded
 *    0, otherwise
 */
COAP_STATIC_INLINE int opt_finished(coap_opt_iterator_t *opt_iter) {

    assert(opt_iter);

    if (opt_iter->length == 0 || opt_iter->next_option == NULL || *(opt_iter->next_option) == COAP_PAYLOAD_START)
        opt_iter->bad = 1;

    return opt_iter->bad;
}


/**
 * @brief: Applies @p filter_op on @p filter with respect to @p type. The following
 *   operations are defined:
 *
 *   FILTER_SET: Store @p type into an empty slot in @p filter. Returns
 *   @c 1 on success, or @c 0 if no spare slot was available.
 *  
 *   FILTER_CLEAR: Remove @p type from filter if it exists.
 *  
 *   FILTER_GET: Search for @p type in @p filter. Returns @c 1 if found,
 *   or @c 0 if not found.
 *
 * @param filter:
 *    the filter object
 * @param type:
 *    the option type to set, get or clear in @p filter
 * @param filter_op:
 *    the operation to apply to @p filter and @p type
 *
 * @returns
 *    1 on success
 *    0 when FILTER_GET yields no hit or no free slot is available to store @p type 
 *    with FILTER_SET
 */
static int coap_option_filter_op(
    coap_opt_filter_t filter,
    uint16_t type,
    int filter_op
) {
    
    uint16_t mask = 0;

    opt_filter *filter_map = (opt_filter *)filter;

    // If @p type represents a long option ...
    if (is_long_option(type)) {

        // Save a mask for the option's type
        mask = LONG_MASK;

        // Iterate over all possible long options held by the filter
        size_t filter_num = 0;
        for (uint16_t filter_mask = 1; filter_num < COAP_OPT_FILTER_LONG; filter_mask <<= 1, filter_num++) {

            // If the filter is active and filter's code matches ...
            if (filter_map->long_opts[filter_num] == type && filter_map->mask & filter_mask) {

                // Deactivate the filter, if asked
                if (filter_op == FILTER_CLEAR) 
                    filter_map->mask &= ~filter_mask;

                // Return 1, no matter the @p filter_op was
                return 1;
            }
        }
    }
    // Else, @p type represents a short option ...
    else {

        // Save a mask for the option's type
        mask = SHORT_MASK;

        // Iterate over all possible long options held by the filter
        size_t filter_num = 0;
        for (uint16_t filter_mask = 1 << COAP_OPT_FILTER_LONG; filter_num < COAP_OPT_FILTER_SHORT; filter_mask <<= 1, filter_num++) {

            // If the filter is active and filter's code matches ...
            if (((filter_map->mask & filter_mask) > 0) && (filter_map->short_opts[filter_num] == (type & 0xff))) {
                
                // Deactivate the filter, if asked
                if (filter_op == FILTER_CLEAR)
                    filter_map->mask &= ~filter_mask;

                // Return 1, no matter the @p filter_op was
                return 1;
            }
        }
    }

    // If type was not found,there is nothing to do on CLEAR or GET
    if ((filter_op == FILTER_CLEAR) || (filter_op == FILTER_GET))
        return 0;

    /* -- We get here only on FILTER_SET -- */

    // Get number (i.e. index) of the first filter (of LONG/SHORT type, according to the case) that is free to be set
    size_t filter_num  = coap_fls(~filter_map->mask & mask);
    if (!filter_num)
        return 0;

    // Set @p type for the requested filter
    if (is_long_option(type))
        filter_map->long_opts[filter_num - 1] = type;
    else
        filter_map->short_opts[filter_num - COAP_OPT_FILTER_LONG - 1] = (uint8_t)type;

    // Activate the filter
    filter_map->mask |= 1 << (filter_num - 1);

    return 1;
}


/**
 * @brief: Helper function used to sort the options' list using LL_SORT in
 *    an ascending option's code order
 * 
 * @param a:
 *    first option to be compared
 * @param b:
 *    first option to be compared
 * @return:
 *    > 0 if a > b
 *    0 if a == b
 *    < 0 if a < b 
 */
static int order_opts(void *a, void *b) {

    if (!a || !b)
        return a < b ? -1 : 1;

    coap_optlist_t *opt_a = (coap_optlist_t *)a;
    coap_optlist_t *opt_b = (coap_optlist_t *)b;

    return (int) (opt_a->number - opt_b->number);
}


/**
 * @brief: Helper function used to free resources allocated by the @t coap_optlist_t's nodes
 * 
 * @param node:
 *    node whose resources will be freed
 */
static void coap_internal_delete(coap_optlist_t *node) {
    if (node)
        coap_free(node);
}
