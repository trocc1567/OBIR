/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-12-01 04:42:32
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

/* resource.c -- generic resource handling
 *
 * Copyright (C) 2010--2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

/* ------------------------------------------------------------------------------------------------------------ */

#include <stdio.h>
#include <stdbool.h>
#include "coap_config.h"
#include "coap.h"
#include "coap_debug.h"
#include "mem.h"
#include "net.h"
#include "resource.h"
#include "subscribe.h"
#include "utlist.h"

static int match(const coap_str_const_t *text, const coap_str_const_t *pattern, int match_prefix,int match_substring);
static void coap_free_resource(coap_resource_t *resource);
static coap_subscription_t *coap_find_observer_query(coap_resource_t *resource, coap_session_t *session, const coap_string_t *query);
static void coap_notify_observers(coap_context_t *context, coap_resource_t *resource);
static void coap_remove_failed_observer(coap_context_t *context, coap_resource_t *resource, coap_session_t *session, const coap_binary_t *token);


/* -------------------------------------------- [Macrofeinitions] --------------------------------------------- */

#define COAP_PRINT_STATUS_MAX (~COAP_PRINT_STATUS_MASK)

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief: Helper macro; adds Char to Buf if Offset is zero. Otherwise, Char is not written
 *    and Offset is decremented. If this macro is called in the loop, it makes it easy to 
 *    copy data from one buffer to another skipping first N (N is put as offset Offset)
 *    elements. When element is copied @p Buf poiter is incremented.
 * 
 * @param Buf:
 *    buffer to write @p Char into
 * @param Offset:
 *    number of elements to skip when copying data from one buffer to another. If > 0,
 *    element's copy will be skipped and @p Offset will be decremented.
 * @param Char:
 *    character (element of the source buffer) to be copied into the @p Buf
 */
#define PRINT_WITH_OFFSET(Buf,Offset,Char)    \
    if ((Offset) == 0) {                      \
        (*(Buf)++) = (Char);                  \
    } else {                                  \
        (Offset)--;                           \
    }                                         \

/**
 * @brief: Helper macro; wrapper around PRINT_WITH_OFFSET(). Adds two features to it:
 *    - checks whether destination @p Buf pointer does not point to the end of the buffer
 *      @p Bufend
 *    - Increments @p Written without considering whether @p Char was copied to the
 *      @p Buf or not. Initializing @p Written as 0 before the loop makes it possible
 *      to automatically count how many elements of the source buffer (whose elements
 *      are @p char ) WOULD be copied to the @p Buf destination buffer if it had
 *      enough space.
 */
#define PRINT_COND_WITH_OFFSET(Buf,Bufend,Offset,Char,Written) { \
        if ((Buf) < (Bufend)) {                                  \
            PRINT_WITH_OFFSET(Buf,Offset,Char);                  \
        }                                                        \
        (Written)++;                                             \
    }

/**
 * @brief: Copies at most @p Length characters of @p Str to @p Buf. The first @p Offset
 *   characters are skipped. Output may be truncated to ( @p Bufend - @p Buf ) characters.
 */
#define COPY_COND_WITH_OFFSET(Buf,Bufend,Offset,Str,Length,Written)             \
    for (size_t i = 0; i < (Length); i++) {                                     \
        PRINT_COND_WITH_OFFSET((Buf), (Bufend), (Offset), (Str)[i], (Written)); \
    }

#define MATCH_URI       0x01
#define MATCH_PREFIX    0x02
#define MATCH_ATTRIBUTE 0x04


/* ---------------------------------------- [Global and static data] ------------------------------------------ */

static coap_str_const_t *null_path = coap_make_str_const("");

static const uint8_t coap_unknown_resource_uri[] = "- Unknown -";


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

coap_print_status_t coap_print_wellknown(
    coap_context_t *context, 
    unsigned char *buf, 
    size_t *buflen,
    size_t offset, 
    coap_opt_t *query_filter
) {

    // String holding name of the query name-key pair
    coap_str_const_t resource_param = { 0, NULL };
    // String holding value of the query name-key pair
    coap_str_const_t  query_pattern = { 0, NULL };

    int flags = 0;

    // Analyse the given filter (if any)
    if (query_filter) {

        uint16_t query_length = coap_opt_length(query_filter);

        if(query_length < 3){
            coap_log(LOG_ERR, "coap_print_wellknown: Query is shorter than 3 bytes (cannot store 'x=y' expression) \n");            
            return COAP_PRINT_STATUS_ERROR;
        }

        // Set resource_param to the 'name' of the name-key pair of the query hold by query_filter option's value
        resource_param.s = coap_opt_value(query_filter);
        while (resource_param.length < query_length && resource_param.s[resource_param.length] != '=')
            resource_param.length++;

        /**
         * @brief: Validate the query. Check whether:
         *    - query's name is not empty
         *    - '=' character is present in the query
         *    - query's value is not empty
         * 
         * @note: Taking into account that our query's name's parsing stops when we reach end
         *    of the option or meet '=' character, alle these error scenarios happen when
         *    resource_param.length + 2 < query_length.
         */

        if(resource_param.length + 2 < query_length){

            // Query's name is empty
            if(resource_param.length == 0) {
                coap_log(LOG_ERR, "coap_print_wellknown: Query's name is empty \n");            
                return COAP_PRINT_STATUS_ERROR;
            }

            // No '=' after query's name
            if(resource_param.length == query_length){
                coap_log(LOG_ERR, "coap_print_wellknown: No '=' after query's name \n");            
                return COAP_PRINT_STATUS_ERROR;
            }
            
            // Query's value is empty
            coap_log(LOG_ERR, "coap_print_wellknown: Query's value is empty \n");            
            return COAP_PRINT_STATUS_ERROR;
        }

        /**
         * @note: According to RFC 6690, name of the name-key pair in the query can be
         *    either "href", a link-param name defined in this specification, or any
         *    other link-extension name.
         * 
         * @note: request for /.well-known/core can hold only one query name-key pair
         *    according to the RFC 6690
         */
        
        // Check if query's name is a "href" (if so, denote that URI will have to be matched)
        if (resource_param.length == 4 && memcmp(resource_param.s, "href", 4) == 0)
            flags |= MATCH_URI;
        // Else, denote that the target attribute filter was requested 
        else
            flags |= MATCH_ATTRIBUTE;
        
        // Set query_pattern to the 'value' of the name-key pair of the query hold by query_filter option's value
        query_pattern.s = coap_opt_value(query_filter) + resource_param.length + 1;
        query_pattern.length = coap_opt_length(query_filter) - (resource_param.length + 1);

        // Check whether the 'href' query's value starts with '/' character. If so, trim it
        // (resource's URIs are stored without the leading '/').
        if (query_pattern.length > 0 && (query_pattern.s[0] == '/') && flags & MATCH_URI) {
            query_pattern.s++;
            query_pattern.length--;
        }

        // Check if query's value is a complete or a prefix filter (i.e. if ends with '*' wildcard)
        if (query_pattern.length > 0 && query_pattern.s[query_pattern.length - 1] == '*') {
            query_pattern.length--;
            flags |= MATCH_PREFIX;
        }
    }

    /**
     * @brief: Here we know what kind of query (i.e href, core attribute or 
     *    non-standard attribute) was requested (if any).
     */

    // Pointer to the first empty byte in the @p buf. It will advance when the buffer will be getting written.
    unsigned char *p_buf = buf;
    // End of the @p buf
    const uint8_t *bufend = buf + *buflen;
    // Summary length of the /.well-known/core's representation
    size_t wkc_len = 0;
    // Number of empty writes that left to met the offset requirement
    size_t current_offset = offset;
    // Flag used for printint ',' between subsequent resources' representations
    bool first_resource = true;
    
    // Iterate over all resources registered in the context
    RESOURCES_ITER(context->resources, resource){

        // If there is a query in the request ...
        if (resource_param.length) {

            // If query contains URI-filter (i.e. '...?href=...')
            if (flags & MATCH_URI){
                // Try to match URI
                if ( ! match(resource->uri_path, &query_pattern, flags & MATCH_PREFIX, flags & MATCH_URI) )
                    continue;
            }
            // Else, query containt attribute's filter
            else {
                // Find an attribute in the resource's list. Check if the attribute has not an empty value
                coap_attr_t *attr = coap_find_attr(resource, &resource_param);                
                if (!attr || !attr->value)
                    continue;

                // Remove surrounding quote, if present
                coap_str_const_t unquoted_val = *attr->value;
                if (attr->value->s[0] == '"') {          /* if attribute has a quoted value, remove double quotes */
                    unquoted_val.length -= 2;
                    unquoted_val.s += 1;
                }

                // Try to match attribute
                if ( ! match(&unquoted_val, &query_pattern, flags & MATCH_PREFIX, flags & MATCH_ATTRIBUTE ))
                    continue;
            }
        }

        /**
         * @brief: If we reach this point, the resource met the constraint
         *    given in the query (or no query was requested).
         */

        // Before all, but not the first, resource's representation's print put a comma
        if (first_resource)
            first_resource = false;
        else
            PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, ',', wkc_len);

        /**
         * @note: @p current_offset is decremented at every single operation that tries to 
         *   write data to the @p buf. In such way program can establish wen the actual 
         *   copying should start.
         * 
         * @note: @p p_buf is incremented at every single operation that tries to write
         *   data into it. In such a way, this pointer always points to the first empty
         *   byte in the @p buf.
         */

        // Compute space available after printing a comma
        size_t left = bufend - p_buf;

        // Print resource's representation's (or at least it's part, when the @p buf is too small).
        // Skip first @v  current_offset characters when copying (as they was printed in the previous
        // callc of the @f coap_print_wellknown() )
        coap_print_status_t written = 
            coap_print_link(resource, p_buf, &left, &current_offset);
        if (written & COAP_PRINT_STATUS_ERROR)
            return COAP_PRINT_STATUS_ERROR;

        // If printing a link succeded, advance p_buf to the first empty byt in the @p buf
        p_buf += COAP_PRINT_OUTPUT_LENGTH(written);

        // Update summary length of the /.well-known/core representation
        wkc_len += left;

        /**
         * @note: In fact we could check COAP_PRINT_STATUS_TRUNC mask on this point
         *    and if data was truncated (i.e. @p buf is full), break the loop. 
         *    The function has to return summary size of the /.well-known/core 
         *    representation in the @p buflen though and so we need to proceed the
         *    loop even if the @p buf cannot be further written
         */
    }

    // Compute number of btyes actually written to the buf
    size_t written = p_buf - buf;

    // As number of bytes written is passed to the caller as 28 lower bits of the result,
    // we have to check if this value doesn't overflow.
    if (written > COAP_PRINT_STATUS_MAX)
        return COAP_PRINT_STATUS_ERROR;

    // Return length of the /.well-known/core representation
    *buflen = wkc_len;

    // Construct the return value
    coap_print_status_t result = 
        (coap_print_status_t) written;
    if (offset - current_offset + written < wkc_len)
        result |= COAP_PRINT_STATUS_TRUNC;

    return result;
}


coap_resource_t *coap_resource_init(coap_str_const_t *uri_path, int flags){

    // Allocate memory for the resource
    coap_resource_t *resource =
        (coap_resource_t *) coap_malloc(sizeof(coap_resource_t));

    // If allocation succeeded ...
    if (resource) {

        // Clear resource's memory
        memset(resource, 0, sizeof(coap_resource_t));

        // Take name's copy if caller is not providing a release request
        if ( !(flags & COAP_RESOURCE_FLAGS_RELEASE_URI) ) {
            if (uri_path)
                uri_path = coap_new_str_const(uri_path->s, uri_path->length);
            else
                uri_path = coap_new_str_const(null_path->s, null_path->length);
        }
        // User should not provide the flag and an empty string simultaneously, but in case ...
        else if (!uri_path)
            uri_path = coap_new_str_const(null_path->s, null_path->length);

        // Fill the allocated resource
        if (uri_path)
            resource->uri_path = uri_path;
        resource->flags = flags;
    } 
    // If allocation failed
    else
        coap_log(LOG_DEBUG, "coap_resource_init: allocation failed\n");

    return resource;
}


coap_resource_t *coap_resource_unknown_init(coap_method_handler_t put_handler) {
    
    // Allocate memory for the resource
    coap_resource_t *resource = 
        (coap_resource_t *)coap_malloc(sizeof(coap_resource_t));

    // If allocation succeeded
    if (resource) {

        // Clean it's memory
        memset(resource, 0, sizeof(coap_resource_t));

        // Mark as unknown
        resource->is_unknown = 1;
        // Give the default name to the resource
        resource->uri_path = 
            coap_new_str_const(coap_unknown_resource_uri, sizeof(coap_unknown_resource_uri) - 1);

        // Register the given PUT handler
        coap_register_handler(resource, COAP_REQUEST_PUT, put_handler);
    } 
    // If allocation failed
    else
        coap_log(LOG_DEBUG, "coap_resource_unknown_init: no memory left\n");

    return resource;
}

coap_attr_t *coap_add_attr(
    coap_resource_t *resource,
    coap_str_const_t *name,
    coap_str_const_t *val,
    int flags
){
    if (resource == NULL || name == NULL)
        return NULL;

    // Allocate memory for the attribute
    coap_attr_t *attr = 
        (coap_attr_t *) coap_malloc(sizeof(coap_attr_t));

    // If allocation succeeded
    if (attr) {

        // Take name's copy if caller is not providing a release request
        if (!(flags & COAP_ATTR_FLAGS_RELEASE_NAME))
            name = coap_new_str_const(name->s, name->length);
        attr->name = name;

        // Take values's copy if caller is not providing a release request
        if (val && !(flags & COAP_ATTR_FLAGS_RELEASE_VALUE))
            val = coap_new_str_const(val->s, val->length);
        attr->value = val;

        // Rewrite flags
        attr->flags = flags;

        // Add attribute to @p resource's list
        LL_PREPEND(resource->link_attr, attr);
    } 
    // Otherwise, if allocation failed
    else
        coap_log(LOG_DEBUG, "coap_add_attr: no memory left\n");
        
    return attr;
}


coap_attr_t *coap_find_attr(
    coap_resource_t *resource,
    coap_str_const_t *name
){
    if (resource == NULL || name == NULL)
        return NULL;

    coap_attr_t *attr;

    // Iterate over all resource's attrobutes to find the requested one
    LL_FOREACH(resource->link_attr, attr)
        if (attr->name->length == name->length && memcmp(attr->name->s, name->s, name->length) == 0)
            return attr;

    return NULL;
}


void coap_delete_attr(coap_attr_t *attr) {

    if (!attr)
        return;
    
    // Free attribute's memory
    coap_delete_str_const(attr->name);
    if (attr->value)
        coap_delete_str_const(attr->value);

    coap_free(attr);
}


void coap_add_resource(
    coap_context_t *context, 
    coap_resource_t *resource
){

    // Add an unknown (unnamed) resource
    if (resource->is_unknown) {
        if (context->unknown_resource)
            coap_free_resource(context->unknown_resource);
        context->unknown_resource = resource;
    }
    // Add a regular (named) resource
    else {

        coap_resource_t *resource_found = 
            coap_get_resource_from_uri_path(context, resource->uri_path);

        // Check if resource with the given URI-Path has been already registered. If so, delete it.
        if (resource_found) {
            coap_log(LOG_WARNING,"coap_add_resource: Duplicate uri_path '%*.*s', old resource deleted\n",
                    (int)resource_found->uri_path->length, (int)resource_found->uri_path->length, resource_found->uri_path->s);
            coap_delete_resource(context, resource_found);
        }

        // Register the resource in the context
        RESOURCES_ADD(context->resources, resource);
    }
}


int coap_delete_resource(
    coap_context_t *context, 
    coap_resource_t *resource
) {
    if (context == NULL || resource == NULL)
        return 0;

    // Remove unknown (unnamed) resource
    if (resource->is_unknown && (context->unknown_resource == resource)) {
        coap_free_resource(context->unknown_resource);
        context->unknown_resource = NULL;
        return 1;
    }

    // Remove regular (named) resource
    RESOURCES_DELETE(context->resources, resource);

    // Free resource's memory
    coap_free_resource(resource);

    return 1;
}


void coap_delete_all_resources(coap_context_t *context) {
  
    /**
     * @note: We cannot use RESOURCES_ITER, because coap_free_resource() releases
     *    the allocated storage. 
     */

    coap_resource_t *res;
    coap_resource_t *rtmp;

    // Release all resources
    HASH_ITER(hh, context->resources, res, rtmp) {
        HASH_DELETE(hh, context->resources, res);
        coap_free_resource(res);
    }

    // Reste context's resource list
    context->resources = NULL;

    // Release a context's unknown resource, if present
    if (context->unknown_resource) {
        coap_free_resource(context->unknown_resource);
        context->unknown_resource = NULL;
    }
}


coap_resource_t *coap_get_resource_from_uri_path(
    coap_context_t *context, 
    coap_str_const_t *uri_path
) {
    coap_resource_t *result;
    RESOURCES_FIND(context->resources, uri_path, result);
    return result;
}


coap_print_status_t coap_print_link(
    const coap_resource_t *resource,
    unsigned char *buf, 
    size_t *len, 
    size_t *offset
){
    // Pointer to the first empty byte in the @p buf. It will advance when the buffer will be getting written.
    unsigned char *p_buf = buf;
    // End of the @p buf
    const uint8_t *bufend = buf + *len;

    // Length of the link's representation
    size_t link_len = 0;
    // Number of empty writes that left to met the offset requirement
    size_t current_offset = *offset;

    // Print resource's uri path betwee '</' and '>'
    PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, '<', link_len);
    PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, '/', link_len);
    COPY_COND_WITH_OFFSET(p_buf, bufend, current_offset, resource->uri_path->s, resource->uri_path->length, link_len);
    PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, '>', link_len);

    // Print all of the resource's attributes
    coap_attr_t *attr;
    LL_FOREACH(resource->link_attr, attr) {

        // Print attribute's name
        PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, ';', link_len);
        COPY_COND_WITH_OFFSET(p_buf, bufend, current_offset, attr->name->s, attr->name->length, link_len);

        // Print attribute's value
        if (attr->value && attr->value->s) {
            PRINT_COND_WITH_OFFSET(p_buf, bufend, current_offset, '=', link_len);
            COPY_COND_WITH_OFFSET(p_buf, bufend, current_offset, attr->value->s, attr->value->length, link_len);
        }

    }

    // Print additional info if the resource is observable
    if (resource->observable)
        COPY_COND_WITH_OFFSET(p_buf, bufend, current_offset, ";obs", 4, link_len);

    // Compute number of btyes actually written to the buf    
    size_t written = p_buf - buf;
    
    // As number of bytes written is passed to the caller as 28 lower bits of the result,
    // we have to check if this value doesn't overflow.
    if (written > COAP_PRINT_STATUS_MAX)
        return COAP_PRINT_STATUS_ERROR;

     // Update summary length of the /.well-known/core representation
    *len = link_len;

    // Construct the return value
    coap_print_status_t result = 
        (coap_print_status_t) written;
    if (*offset - current_offset + written < link_len)
        result |= COAP_PRINT_STATUS_TRUNC;

    // This function should modify @p offset when writes to the @p buf. Do it now
    *offset = current_offset;

    return result;
}


void coap_register_handler(
    coap_resource_t *resource,
    unsigned char method,
    coap_method_handler_t handler
) {
    assert(resource);
    assert(method > 0 && (size_t)(method - 1) < sizeof(resource->handler) / sizeof(coap_method_handler_t));
    resource->handler[method-1] = handler;
}


coap_subscription_t *coap_find_observer(
    coap_resource_t *resource, 
    coap_session_t *session,
    const coap_binary_t *token
) {
    assert(resource);
    assert(session);

    coap_subscription_t *s;
    LL_FOREACH(resource->subscribers, s) {

        bool session_match = s->session == session;
        bool token_match = !token || 
            (token->length == s->token_length && memcmp(token->s, s->token, token->length) == 0);

        if (session_match && token_match)
            return s;
    }

    return NULL;
}


coap_subscription_t *coap_add_observer(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token,
    coap_string_t *query,
    int has_block2,
    coap_block_t block2
) {
    assert( session );

    // Check if there is already a subscription for this peer
    coap_subscription_t *observer =
        coap_find_observer(resource, session, token);

    // If subscription was found, just update the query
    if (observer) {
        if (observer->query)
            coap_delete_string(observer->query);
        observer->query = query;
        return observer;
    }

    // If no subscription was not found by the Token, try to find by the query
    if (!observer) {

        /**
        * @note: Function cannot allow a duplicate to be created for the same query
        *    (for a single subscriber, ofcourse) as application may not be cleaning up
        *    duplicates.  If duplicate found, then original observer is deleted and
        *    a new one created with the new token.
        */
        
        observer = coap_find_observer_query(resource, session, query);

        // If observer was found by the query, delete the old subscription
        if (observer) {
            coap_binary_t tmp_token = { observer->token_length, observer->token };
            coap_delete_observer(resource, session, &tmp_token);
            observer = NULL;
        }
    }

    // Allocate memory for a new subscriber
    observer = (coap_subscription_t*) coap_malloc(sizeof(coap_subscription_t));
    if (!observer) {
        if (query)
            coap_delete_string(query);
        return NULL;
    }

    // Initialize the observer, increment session's reference counter
    coap_subscription_init(observer);
    observer->session = coap_session_reference( session );

    // Copy the token, if present
    if (token && token->length) {
        observer->token_length = token->length;
        memcpy(observer->token, token->s, min(observer->token_length, 8));
    }

    // Take the ownership over the query
    observer->query = query;

    // Initialize block-transfer-subscription info
    observer->has_block2 = has_block2;
    observer->block2 = block2;

    // Add subscriber to resource
    LL_PREPEND(resource->subscribers, observer);
    coap_log(LOG_DEBUG, "create new subscription\n");

    return observer;
}


void coap_touch_observer(
    coap_session_t *session,
    const coap_binary_t *token
) {
    coap_subscription_t *observer;

    // Iterate over all resources in the context
    RESOURCES_ITER(session->context->resources, resource) {

        // Find an observer
        observer = coap_find_observer(resource, session, token);

        // If observer found, reset fail counter
        if (observer) 
            observer->fail_cnt = 0;
    }
}


int coap_delete_observer(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token
) {

    // Find observer to be deleted
    coap_subscription_t *observer = 
        coap_find_observer(resource, session, token);

    // If LOG_DEBUG verbosity is active, log info containing hexadecimally encoded
    // token of the observer to be deleted
    if ( observer && coap_get_log_level() >= LOG_DEBUG ) {
        char outbuf[2 * COAP_MAX_TOKEN_SIZE + 1] = "";
        for (unsigned int i = 0; i < observer->token_length; i++ )
            snprintf( &outbuf[2 * i], 3, "%02x", observer->token[i] );
        coap_log(LOG_DEBUG, "removed observer token %s\n", outbuf);
    }

    // If observer exists, delete it
    if (observer) {

        // Delete observer from the resource's list
        LL_DELETE(resource->subscribers, observer);

        // Decrement sessions reference counter
        coap_session_release(session);

        // Free observer's resources
        if (observer->query)
            coap_delete_string(observer->query);
        coap_free(observer);
    }

    return observer != NULL;
}


void coap_delete_observers(
    coap_session_t *session
) {
    // Iterate over all resources registered within context
    RESOURCES_ITER(session->context->resources, resource) {
        
        coap_subscription_t *observer, *observer_tmp;

        // Iterate over all observer registered to the resource
        LL_FOREACH_SAFE(resource->subscribers, observer, observer_tmp) {

            // If session matches
            if (observer->session == session) {

                // Delete the observer from the resource's list
                LL_DELETE(resource->subscribers, observer);

                // Decrement sessions reference counter
                coap_session_release(session);

                // Release observer's resources
                if (observer->query)
                    coap_delete_string(observer->query);
                coap_free(observer);
            }
        }
    }
}


int coap_resource_notify_observers(
    coap_resource_t *resource, 
    const coap_string_t *query
) {
    if ( !resource->observable )
        return 0;

    // If query was given ... 
    if (query) {

        int found = 0;
        coap_subscription_t *observer;
        
        // Iterate over all observers registered to the @p resource
        LL_FOREACH(resource->subscribers, observer) {

            bool query_exist = observer->query;
            bool query_match_length = query_exist && observer->query->length;
            bool query_match = query_match_length &&
                memcmp(observer->query->s, query->s, query->length) == 0;

            // If observer was found
            if (query_match) {
                
                // Set the flag
                found = 1;

                // Conditionally, mark resource as partially dirty and the observer as dirty
                if (resource->dirty == 0 && observer->dirty == 0) {
                    observer->dirty = 1;
                    resource->partiallydirty = 1;
                }
            }
        }

        if(!found) 
            return 0;

    // No query given ...
    } else {
        
        // If resource is subscribed mark whole resource as notifications-requiring
        if ( !resource->subscribers )
            return 0;
        resource->dirty = 1;
    }

    // Increment value for next Observe use (Observe value must be < 2^24)
    resource->observe = (resource->observe + 1) & 0xFFFFFF;

    return 1;
}


void coap_check_notify(coap_context_t *context) {
    RESOURCES_ITER(context->resources, resource)
        coap_notify_observers(context, resource);
}


void coap_handle_failed_notify(
    coap_session_t *session,
    const coap_binary_t *token
) {
    // Iterate over all resources to find the observer to be removed
    RESOURCES_ITER(session->context->resources, resource) 
        coap_remove_failed_observer(session->context, resource, session, token);
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */

/**
 * @brief: Finds @p pattern substring in the @p text. If @p match_prefix is true,
 *    function tries to match @p pattern as a prefix of the @p text. If @p match_substring
 *    is true (exclusively), function tries to match @p pattern as a substring
 *    of the @p text. If both are true, the @p match_prefix flag is taken into account.
 *    If bot are false, function checks whether @p pattern is equal to the @p text
 * 
 * @param text:
 *    text to be analysed
 * @param pattern:
 *    pattern to be found in @p text
 * @param match_prefix:
 * @param mmatch_substring:
 *    pair of flag used to establish what kind of substring should be searched;
 *      1) if (true & false): checks if @p pattern is a prefix of the @p text
 *      2) if (false & true): checks if @p pattern is any substring of the @p text
 *      3) if (false & false): checks if @p pattern is equal to @p text
 *      4) if (true & true): checks if @p pattern is a prefix of the @p text (same as 1)
 *    i.e. @p match_prefix is a dominant flag.
 * @return int:
 *    != 0 when pattern is found in @p text
 *    0 otherwise
 * 
 * @note: @p text is parsed word-wide, not byte-wide (i.e. it compares string with word shifts,
 *    not single-character shifts).
 * 
 * @note: Substrings' search is used to parse resources' attributes that can have a few value
 *    values simultaneously (separated with spaces). According to RFC 6690 relation-type ('rel')
 *    is this kind of attribute.
 */
static int match(
    const coap_str_const_t *text, 
    const coap_str_const_t *pattern, 
    int match_prefix,
    int match_substring
){
    assert(text); assert(pattern);

    // Pattern's length cannot be bigger than text's length. Searched @p text cannot be empty
    if (text->length < pattern->length || text->length == 0)
        return 0;

    // Match substring
    if (!match_prefix && match_substring) {

        /**
         * @brief: Initialize token (substring from the @p text) to be compared witch pattern
         *    - token -> first byte of the token (word)
         *    - next_token -> the first byte after the token (word)
         */
        size_t token_length;
        const uint8_t *token, *next_token = text->s;
        
        // Iterate over whole @p text
        size_t remaining_length = text->length;
        while (remaining_length) {

            token = next_token;

            // Check if pattern was found
            if (pattern->length <= remaining_length && memcmp(token, pattern->s, pattern->length) == 0)
                return 1;

            // Advance the token to the next space (next word)
            next_token = (unsigned char *) memchr(token, ' ', remaining_length);

            // If space was found
            if (next_token) {

                // Get a token's length
                token_length = next_token - token;

                // Update remaining length of the @p text (count the ' ')
                remaining_length -= (token_length + 1);

                // Forward end of the token by 1 byte (to the first byte of the next word)
                next_token++;
            } 
            // If end of the text was reached
            else 
                return 0;
        }

        // In case when @p text is ended with ' '
        return 0;
    }

    // Match prefix or the whole pattern
    return (match_prefix || pattern->length == text->length) &&
            memcmp(text->s, pattern->s, pattern->length) == 0;
}


/**
 * @brief: Frees memory allocated on behalf of the @t coap_resource_t objecy.
 * 
 * @param resource:
 *    resource to be freed
 */
static void coap_free_resource(coap_resource_t *resource) {

    assert(resource);

    coap_attr_t *attr, *tmp;

    // Delete registered attributes
    LL_FOREACH_SAFE(resource->link_attr, attr, tmp) 
        coap_delete_attr(attr);

    // Free allocated URI-Path
    coap_delete_str_const(resource->uri_path);


    coap_subscription_t *obs, *otmp;
    
    // Free all elements from resource->subscribers
    LL_FOREACH_SAFE( resource->subscribers, obs, otmp ) {

        // Release observer's session
        coap_session_release(obs->session);

        // Delete observer's query
        if (obs->query)
            coap_delete_string(obs->query);

        // Free observer itself
        coap_free(obs);
    }

    coap_free(resource);
}


/**
 * @brief Finds an observer in the @p resource's observer list matching both @p session
 *    obejct assigned and the @p query.
 * 
 * @param resource:
 *    a resource that observer is subscribing to
 * @param session:
 *    session that observer's subscription is maintained with
 * @param query:
 *    observer's query
 * @return:
 *    observer's object on success
 *    NULL on failure
 */
static coap_subscription_t *coap_find_observer_query(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_string_t *query
) {
    assert(resource);
    assert(session);

    coap_subscription_t *observer;
    LL_FOREACH(resource->subscribers, observer) {
        
        bool session_match = observer->session == session;
        bool query_match = (!query && !observer->query) || 
            (query && observer->query && coap_string_equal(query, observer->query));
        
        if (session_match && query_match)
            return observer;
    }

    return NULL;
}


/**
 * @brief: Notifies all possible observers of the @p resource registered in the given @p context.
 *    Marks @p resource appropriately if some of them could not be notified.
 * 
 * @param context:
 *    a context that @p resource was registered in
 * @param resource:
 *    a subscribed resource 
 */
static void coap_notify_observers(
    coap_context_t *context, 
    coap_resource_t *resource
) {

    // Check whether resource is observable and if so, whether it needs to be notified
    if (resource->observable && (resource->dirty || resource->partiallydirty)) {

        // Mark that the notification procedure has begun
        resource->partiallydirty = 0;                

        coap_subscription_t *observer;

        // Iterate over all resource's subscriber
        LL_FOREACH(resource->subscribers, observer) {

            // If resource is partially dirty (i.e. some of the subscriber was not 
            // notified yet) but the observer itself was notified / unqueued in the
            // previous call , continue
            if (resource->dirty == 0 && observer->dirty == 0)
                continue;


            bool active_con_limit_reached = observer->session->con_active >= COAP_DEFAULT_NSTART;
            bool notify_by_con = observer->non_cnt >= COAP_OBS_MAX_NON ||
                                 resource->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON;
                
            // Continue, if a new CON message connot be sent
            if ( active_con_limit_reached && notify_by_con){
                observer->dirty = 1;
                resource->partiallydirty = 1;
                continue;
            }

            // At this point observer will be notified
            observer->dirty = 0;

            // Initialize notification response
            coap_pdu_t *response = 
                coap_pdu_init(COAP_MESSAGE_CON, 0, 0, coap_session_max_pdu_size(observer->session));

            // If response cannot be sent, setup appropriate markers
            if (!response) {
                observer->dirty = 1;
                resource->partiallydirty = 1;
                coap_log(LOG_DEBUG, "coap_check_notify: pdu init failed, resource stays partially dirty \n");
                continue;
            }

            // The same, if token cannot be added to the PDU
            if ( ! coap_add_token(response, observer->token_length, observer->token)) {
                observer->dirty = 1;
                resource->partiallydirty = 1;
                coap_log(LOG_DEBUG, "coap_check_notify: cannot add token, resource stays partially dirty\n");
                coap_delete_pdu(response);
                continue;
            }

            // Generate a new message ID
            response->tid = coap_new_message_id(observer->session);

            // Establish type of the notification response
            if ( (resource->flags & COAP_RESOURCE_FLAGS_NOTIFY_CON) == 0 && observer->non_cnt < COAP_OBS_MAX_NON) 
                response->type = COAP_MESSAGE_NON;
            else
                response->type = COAP_MESSAGE_CON;
            
            // Get the token entity for user's handler to recognise the observer
            coap_binary_t token = {
                .length = observer->token_length, 
                .s = observer->token
            };
            
            // Retrieve GET handler
            coap_method_handler_t handler = 
                resource->handler[COAP_REQUEST_GET - 1];

            // Subscription is not allowed, when there is no GET handler registered
            assert(handler);

            // Call user-defined GET handler to fill response with data
            handler(resource, observer->session, NULL, &token, observer->query, response);

            // Update NON counter
            if (response->type == COAP_MESSAGE_CON)
                observer->non_cnt = 0;
            else
                observer->non_cnt++;

            // Check if response's code set in the handler belongs to 2.XX (Success) group
            if ( COAP_RESPONSE_CLASS(response->code) == 2 ){

                // Send a message
                coap_tid_t tid = coap_send( observer->session, response );

                // Update 'dirty' markers if notification sending failed
                if (COAP_INVALID_TID == tid) {
                    coap_log(LOG_DEBUG, "coap_check_notify: sending failed, resource stays partially dirty\n");
                    observer->dirty = 1;
                    resource->partiallydirty = 1;
                }

            } else
                coap_log(LOG_INFO, "Notification (MID: %d) won't be sent, as user-handler set return code %d: %s ",
                    response->tid, response-> code, coap_response_phrase(response-> code));

        }
    }
    
    resource->dirty = 0;
}


/**
 * @brief: Checks the failure counter for (peer, token) and removes peer from
 *    the list of observers for the given resource when COAP_OBS_MAX_FAIL
 *    is reached.
 *
 * @param context:
 *     the CoAP context to use
 * @param resource:
 *     the resource to check for (peer, token)
 * @param session:
 *     the observer's session
 * @param token:
 *     the token that has been used for subscription.
 */
static void
coap_remove_failed_observer(
    coap_context_t *context,
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token
) {
    coap_subscription_t *observer, *observer_tmp;

    // Iterate over all resource's subscribera
    LL_FOREACH_SAFE(resource->subscribers, observer, observer_tmp) {

        // Check session and token match
        bool session_match = observer->session == session;
        bool token_length_match = token->length == observer->token_length;
        bool token_match = token_length_match &&
            memcmp(token->s, observer->token, token->length) == 0;
        
        if (session_match && token_match) {

            // For a regular observer, increment the fail counter
            if (observer->fail_cnt < COAP_OBS_MAX_FAIL)
                observer->fail_cnt++;
            // If fail counter exceeded the limit ...
            else {
                
                // Delete observer from the resource's list
                LL_DELETE(resource->subscribers, observer);

                // Log some stuff
                #ifndef NDEBUG
                
                if (LOG_DEBUG <= coap_get_log_level()) {
        
                    #ifndef INET6_ADDRSTRLEN
                    #define INET6_ADDRSTRLEN 40
                    #endif
                    
                    unsigned char addr[INET6_ADDRSTRLEN + 8];
                    if (coap_print_addr(&observer->session->remote_addr, addr, INET6_ADDRSTRLEN + 8))
                        coap_log(LOG_DEBUG, "** removed observer %s\n", addr);
                }

                #endif /* NDEBUG */

                // Cancel all mesages associated with the observer
                coap_cancel_all_messages(observer->session, observer->token, observer->token_length);

                // Release observer's resources
                coap_session_release( observer->session );
                if (observer->query)
                    coap_delete_string(observer->query);
                coap_free(observer);
            }

            break;
        }
    }
}
