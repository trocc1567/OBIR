/* ============================================================================================================
 *  File:
 *  Author: Olaf Bergmann
 *  Source: https://github.com/obgm/libcoap/tree/develop/include/coap2
 *  Modified by: Krzysztof Pierczyk
 *  Modified time: 2020-11-30 21:51:55
 *  Description:
 * 
 *      File contains base API related to CoAP resources management.
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
 * resource.h -- generic resource handling
 *
 * Copyright (C) 2010,2011,2014,2015 Olaf Bergmann <bergmann@tzi.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file resource.h
 * @brief Generic resource handling
 */

/* ------------------------------------------------------------------------------------------------------------ */


#ifndef COAP_RESOURCE_H_
#define COAP_RESOURCE_H_

# include <assert.h>
#include "uthash.h"
#include "async.h"
#include "str.h"
#include "pdu.h"
#include "net.h"
#include "subscribe.h"


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

/** 
 * @brief: The interval used (in seconds) to check if resources have been changed
 */
#ifndef COAP_RESOURCE_CHECK_TIME
#define COAP_RESOURCE_CHECK_TIME 2
#endif

/**
 * @brief: Flags used at resource's attribute adding.
 *
 * @see: @f coap_add_attr()
 */
#define COAP_ATTR_FLAGS_RELEASE_NAME  0x1
#define COAP_ATTR_FLAGS_RELEASE_VALUE 0x2

/**
 * @brief: Flags used at resource's creation.
 *
 * @see: @f coap_resource_init()
 */
#define COAP_RESOURCE_FLAGS_RELEASE_URI 0x1
#define COAP_RESOURCE_FLAGS_NOTIFY_NON  0x0
#define COAP_RESOURCE_FLAGS_NOTIFY_CON  0x2

/**
 * @brief: Print masks
 * @see: @t coap_print_status_t, @f coap_print_link
 */
#define COAP_PRINT_STATUS_MASK  0xF0000000u
#define COAP_PRINT_OUTPUT_LENGTH(v) ((v) & ~COAP_PRINT_STATUS_MASK)
#define COAP_PRINT_STATUS_ERROR 0x80000000u
#define COAP_PRINT_STATUS_TRUNC 0x40000000u

/**
 * @brief: Adds @p obj resource of type @t coap_resource_t* to the @p r array
 *    of @t coap_resource_t *.
 *  
 * @param r:
 *    list of resources to add the resource to
 * @param obj:
 *    pointer to the resource to be added
 */
#define RESOURCES_ADD(r, obj)    \
  HASH_ADD(hh, (r), uri_path->s[0], (obj)->uri_path->length, (obj))

/**
 * @brief: Deletes @p obj resource of type @t coap_resource_t* from the @p r array
 *    of @t coap_resource_t*.
 *  
 * @param r:
 *    list of resources to remove the resource from
 * @param obj:
 *    pointer to the resource to be removed
 */
#define RESOURCES_DELETE(r, obj) \
  HASH_DELETE(hh, (r), (obj))

/**
 * @brief: Header of the functional for-like block used for iterating with @p tmp handler
 *    over the @p r list of resources given with @t coap_resource_t* variable.
 * 
 * @code
 * 
 *   coap_resource_t* resources;
 * 
 *   ... initializes resources ...
 * 
 *   RESOURCES_ITER(resources, tmp){
 *       ... uses 'tmp' as a pointer to the current resource
 *   }
 * 
 * @endcode
 * 
 */
#define RESOURCES_ITER(r,tmp)    \
  coap_resource_t *tmp, *rtmp;   \
  HASH_ITER(hh, (r), tmp, rtmp)

/**
 * @brief: Finds resource with the @p k URI-path in the @p r list of resources and puts
 *    resoult in the @p res.
 * 
 * @param r:
 *    list of resources given as @t coap_resource_t*
 * @param k:
 *    URI-path given as @t coap_str_const_t*
 * @param res [out]:
 *    result resource given as @t coap_resource_t*
 *    NULL if not found
 */
#define RESOURCES_FIND(r, k, res) {                 \
    HASH_FIND(hh, (r), (k)->s, (k)->length, (res)); \
  }

/* -------------------------------------------- [Data structures] --------------------------------------------- */

/**
 * @brief: Message handler function for the @t coap_resource_t.
 * 
 * @param resource:
 *    resource associated with the request
 * @param session:
 *    session that received the request
 * @param request:
 *    request PDU
 * @param token:
 *    request's token
 * @param query_string:
 *    string that pointed to the @p resource
 * @param response [out]:
 *    response PDU (established by the handler)
 * 
 * @see: @t coap_resource_t
 */
typedef void (*coap_method_handler_t)(
    struct coap_resource_t *resource,
    coap_session_t *session,
    coap_pdu_t *request,
    coap_binary_t *token,
    coap_string_t * query_string,
    coap_pdu_t *respons
);


/**
 * @brief: Description of the resource's attribute
 * 
 * @note: attributes are used to send informations about resources available on
 *    the server when the /.well-known/core resource is requested
 */
typedef struct coap_attr_t {

    // Value used to create forward-list 
    struct coap_attr_t *next;

    // Attribute's name
    coap_str_const_t *name;
    // Attributes value
    coap_str_const_t *value;
    // Flags associated with the attribute
    int flags;
    
} coap_attr_t;


/**
 * @brief: Description of the CoAP server's resource.
 */
typedef struct coap_resource_t {

    /**
     * @brief: User-defined data for the resources. It can be used to store context for the coap handler.
     */
    void *user_data;

    /* ---------------------------------- Flags ---------------------------------- */

    // Set to 1 if resource has changed and no subscribers have been notified
    unsigned int dirty:1;
    // Set to 1 if some subscribers have not yet been notified of the last change 
    unsigned int partiallydirty:1;
    // Set if can be observed 
    unsigned int observable:1;
    // Set if can be cached 
    unsigned int cacheable:1;
    // Set if resource was created with unknown handler 
    unsigned int is_unknown:1;

    /**
     * @brief: Resource's flags
     * 
     * @see: @f coap_resource_init
     */
    int flags;

    /* -------------------------------- Handlers --------------------------------- */

    /**
     * @brief: Handlers for the seven coap methods @c GET, @c POST, @c PUT, @c DELETE, @c FETCH,
     *    @c PATCH and @c IPATCH. @f coap_dispatch() will pass incoming requests to the handler
     *    that corresponds to its request method or generate a 4.05 (Method Not Allowed) response
     *    if no handler is available.
     */
    coap_method_handler_t handler[7];

    /* ---------------------------- Resource's info ------------------------------ */

    // Hash used to store resources in the hash table
    UT_hash_handle hh;

    // attributes to be included with the link format in the response to /.well-known/core requests
    coap_attr_t *link_attr;

    /**
     * @brief: URI Path for this resource. This field will point into static or allocated memory which
     *    must remain there for the duration of the resource lifetime.
     * 
     * @note: URI-path is used as the key hash lookup for this resource
     */
    coap_str_const_t *uri_path;

    /* ------------------------- Observers-related info -------------------------- */

    // List of observers for this resource
    coap_subscription_t *subscribers;  

    /**
    * @brief: The next value for the Observe option. This field must be increased each time the resource
    *    changes. Only the lower 24 bits are sent.
    */
    unsigned int observe;

} coap_resource_t;


/**
 * @brief: Status word to encode the result of conditional print or copy operations such as @f coap_print_link().
 *    The lower 28 bits of coap_print_status_t are used to encode the number of characters that has actually
 *    been printed. Bits 28 to 31 encode the status. When COAP_PRINT_STATUS_ERROR is set, an error occurred
 *    during output. In this case, the other bits are undefined. COAP_PRINT_STATUS_TRUNC indicates that the
 *    output is truncated, i.e. the printing would have exceeded the current buffer.
 */
typedef unsigned int coap_print_status_t;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

/**
 * @brief: Creates a new resource object and initializes the link field to the string
 *    @p uri_path. This function returns the new coap_resource_t object.
 *   
 *    If the string is going to be freed off by coap_delete_resource() when
 *    COAP_RESOURCE_FLAGS_RELEASE_URI is set in @p flags, then either the 's'
 *    variable of @t coap_str_const_t has to point to constant text, or point to data
 *    within the allocated @t coap_str_const_t parameter.
 *
 * @param uri_path:
 *    the string URI path of the new resource
 * @param flags:
 *    Flags for memory management (in particular release of memory).
 *    Possible values:@n
 *                 
 *       COAP_RESOURCE_FLAGS_RELEASE_URI
 *        If this flag is set, the URI passed to
 *        coap_resource_init() is free'd by
 *        coap_delete_resource()@n
 *       
 *       COAP_RESOURCE_FLAGS_NOTIFY_CON
 *        If this flag is set, coap-observe notifications
 *        will be sent confirmable by default.@n
 *       
 *       COAP_RESOURCE_FLAGS_NOTIFY_NON (default)
 *        If this flag is set, coap-observe notifications
 *        will be sent non-confirmable by default.@n
 *       
 *        If flags is set to 0 then the
 *        COAP_RESOURCE_FLAGS_NOTIFY_NON is considered.
 *                 
 * @returns:
 *    a pointer to the new object on success
 *    NULL on error
 */
coap_resource_t *coap_resource_init(
    coap_str_const_t *uri_path,
    int flags
);


/**
 * @brief: Creates a new resource object for the unknown resource handler with support
 *    for PUT.
 *
 *    In the same way that additional handlers can be added to the resource
 *    created by coap_resource_init() by using coap_register_handler(), POST,
 *    GET, DELETE etc. handlers can be added to this resource. It is the
 *    responsibility of the application to manage the unknown resources by either
 *    creating new resources with coap_resource_init() (which should have a
 *    DELETE handler specified for the resource removal) or by maintaining an
 *    active resource list.
 *
 * @param put_handler:
 *    the PUT handler to register with @p resource for unknown Uri-Path.
 * @returns:
 *    a pointer to the new object on success
 *    NULL on error
 * 
 * @note: There can only be one unknown resource handler per context - attaching
 *    a new one overrides the previous definition.
 * @note: It is not possible to observe the unknown resource with a GET request
 *    - a separate resource needs to be reated by the PUT (or POST) handler,
 *    and make that resource observable.
 */
coap_resource_t *coap_resource_unknown_init(coap_method_handler_t put_handler);

/**
 * @brief: Registers the given @p resource for @p context. The resource must have been
 *    created by coap_resource_init() or coap_resource_unknown_init(), the
 *    storage allocated for the resource will be released by coap_delete_resource().
 *
 * @param context:
 *    the context to use
 * @param resource:
 *    the resource to store
 */
void coap_add_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * @brief: Deletes a resource identified by @p resource. The storage allocated for that
 *    resource is freed, and removed from the context.
 *
 * @param context:
 *    the context where the resources are stored
 * @param resource:
 *    the resource to delete
 *
 * @returns:
 *    1 if the resource was found (and destroyed)
 *    0 otherwise
 */
int coap_delete_resource(coap_context_t *context, coap_resource_t *resource);

/**
 * @brief: Deletes all resources from given @p context and frees their storage.
 *
 * @param context:
 *    the CoAP context with the resources to be deleted
 */
void coap_delete_all_resources(coap_context_t *context);

/**
 * @brief: Registers a new attribute with the given @p resource. As the attribute's
 *    coap_str_const_ fields will point to @p name and @p value the caller must ensure
 *    that these pointers are valid during the attribute's lifetime.
 *
 *    If the @p name and/or @p value string is going to be freed off at attribute
 *    removal time by the setting of COAP_ATTR_FLAGS_RELEASE_NAME or
 *    COAP_ATTR_FLAGS_RELEASE_VALUE in @p flags, then either the 's' variable of
 *    coap_str_const_t has to point to constant text, or point to data within the allocated
 *    coap_str_const_t parameter.
 *
 * @param resource:
 *    the resource to register the attribute with
 * @param name:
 *    the attribute's name as a string
 * @param value:
 *    the attribute's value as a string or @c NULL if none
 * @param flags:
 *    flags for memory management (in particular release of memory).
 *    Possible values:@n
 *                 
 *       COAP_ATTR_FLAGS_RELEASE_NAME
 *        If this flag is set, the name passed to
 *        coap_add_attr_release() is free'd
 *        when the attribute is deleted@n
 *       
 *       COAP_ATTR_FLAGS_RELEASE_VALUE
 *        If this flag is set, the value passed to
 *        coap_add_attr_release() is free'd
 *        when the attribute is deleted@n
 *       
 * @returns:
 *    a pointer to the new attribute on success
 *    NULL on error
 */
coap_attr_t *coap_add_attr(
    coap_resource_t *resource,
    coap_str_const_t *name,
    coap_str_const_t *value,
    int flags
);

/**
 * @param resource:
 *    the resource to search for attribute @p name
 * @param name:
 *    name of the requested attribute as a string
 * @returns:
 *    the first attribute with specified @p name on success
 *    NULL if none was found
 */
coap_attr_t *coap_find_attr(
    coap_resource_t *resource,
    coap_str_const_t *name
);

/**
 * @brief: Deletes an attribute.
 * 
 * @param attr:
 *    pointer to a previously created attribute.
 *
 * @note: This is for internal use only, as it is not deleted from its chain.
 */
void coap_delete_attr(coap_attr_t *attr);

/**
 * @brief: Writes a description of this resource in link-format to given text buffer. 
 *    @p len must be initialized to the maximum length of @p buf and will be set to
 *    the number of characters actually written if successful. This function
 *    returns 1 on success or 0 on error.
 *
 * @param resource:
 *    the resource to describe.
 * @param buf:
 *    the output buffer to write the description to.
 * @param len:
 *    must be initialized to the length of @p buf and will be set to the length
 *    of the printed link description.
 * @param offset:
 *    the offset within the resource description where to start writing into @p buf.
 *    This is useful for dealing with the Block2 option. @p offset is updated during
 *    output as it is consumed.
 * @returns:
 *    if bits [31 ... 28] are set to COAP_PRINT_STATUS_ERROR an error occured
 *    if bits [31 ... 28] are set to COAP_PRINT_STATUS_TRUNC the output was truncated
 *    and so @p len contains value higher that the number of bytes actually printed to
 *    the @p buf
 *    if no error mask was set, bits [27 .. 0] contains number of bytes actually
 *    printed into the buffer
 */
coap_print_status_t coap_print_link(
    const coap_resource_t *resource,
    unsigned char *buf,
    size_t *len,
    size_t *offset
);

/**
 * @brief: Registers the specified @p handler as message handler for the request type 
 *    @p method
 *
 * @param resource:
 *    the resource for which the handler shall be registered
 * @param method:
 *    the CoAP request method to handle
 * @param handler:
 *    the handler to register with @p resource
 */
void coap_register_handler(
    coap_resource_t *resource,
    unsigned char method,
    coap_method_handler_t handler
);

/**
 * @param context:
 *    the context to look for this resource
 * @param uri_path:
 *    the unique string uri of the resource
 *
 * @returns:
 *    a pointer to the resource if found
 *    NULL if not found
 */
coap_resource_t *coap_get_resource_from_uri_path(
    coap_context_t *context,
    coap_str_const_t *uri_path
);

/**
 * @brief: Adds the specified peer as observer for @p resource. The subscription is
 *    identified by the given @p token. 
 *
 * @param resource:
 *    the observed resource
 * @param session:
 *    the observer's session
 * @param token:
 *    the token that identifies this subscription
 * @param query:
 *    the query string, if any; subscription will take ownership of the string.
 * @param has_block2:
 *    if Option Block2 defined
 * @param block2:
 *    contents of Block2 if Block 2 defined
 * @returns:
 *    a pointer to the added/updated subscription information on success
 *    NULL on error
 */
coap_subscription_t *coap_add_observer(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token,
    coap_string_t *query,
    int has_block2,
    coap_block_t block2
);

/**
 * @param resource:
 *    the observed resource
 * @param session:
 *    the observer's session
 * @param token:
 *    the token that identifies this subscription or @c NULL for any token
 * @returns:
 *    a valid subscription if exists
 *    NULL otherwise
 */
coap_subscription_t *coap_find_observer(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token
);

/**
 * @brief: Marks an observer as alive.
 *
 * @param session:
 *    the observer's session
 * @param token:
 *    the corresponding token that has been used for the subscription.
 */
void coap_touch_observer(
    coap_session_t *session,
    const coap_binary_t *token
);

/**
 * @brief: Removes any subscription for @p observer from @p resource and releases the
 *    allocated storage.
 *
 * @param resource:
 *    the observed resource
 * @param session:
 *    the observer's session
 * @param token:
 *    the token that identifies this subscription or NULL for any token.
 * @returns:
 *    1 if the observer has been deleted
 *    0 otherwise
 */
int coap_delete_observer(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_binary_t *token
);

/**
 * @brief: Removes any subscription for @p session and releases the allocated storage.
 *
 * @param session:
 *    the observer's session
 */
void coap_delete_observers(
    coap_session_t *session
);

/**
 * @brief: Checks for all known resources, if they are dirty and notifies subscribed observers.
 * 
 * @param context:
 *    context to perform notifications on
 */
void coap_check_notify(coap_context_t *context);

/**
 * @brief: Prints the representatio of resources registers in the context to @p buf (if @p buflen
 *   is enough). Even if @p buf is to small to store the representation, function computes 
 *   it's length and returns it via @p buflen.
 *
 * @param context:
 *    the context holding the list of resources
 * @param buf [out]:
 *    the buffer to write the representation to
 * @param buflen [in/out]:
 *    must be initialized to the maximum length of @p buf; will be set to the length of the resources'
 *    representation if no error occur
 * @param offset:
 *    the offset (in bytes) where the function should start printing resources' representation from;
 *    this parameter is used to support the Block2 option if /.well-known/core resource was requested
 *    via block transfer
 * @param query_filter:
 *    a filter query according to RFC 6690 (Section 4.1)
 * @returns:
 *    if bits [31 ... 28] are set to COAP_PRINT_STATUS_ERROR an error occured
 *    if bits [31 ... 28] are set to COAP_PRINT_STATUS_TRUNC the output was truncated
 *    and so @p len contains value higher that the number of bytes actually printed to
 *    the @p buf
 *    if no error mask was set, bits [27 .. 0] contains number of bytes actually
 *    printed into the buffer
 * 
 * @note: Even if output string was truncated, the output of the function is not considere
 *    erroneous and so value passed back in the @p buflen is correct.
 */
coap_print_status_t coap_print_wellknown(
    coap_context_t *context,
    unsigned char *buf,
    size_t *buflen,
    size_t offset,
    coap_opt_t *query_filter
);

/**
 * @brief: Deals with observer's notification failure. Iterates over all resources in the 
 *    @p session->context and checks the failure counter for all (peer, token) tuples. Removes peer
 *    from the list of observers for the given resource when COAP_OBS_MAX_FAIL is reached.
 * 
 * @param session:
 *    session associated with the failed notification
 * @param token: 
 *    token identifying subscription that failed to notify
 */
void coap_handle_failed_notify(
    coap_session_t *session,
    const coap_binary_t *token
);

/**
 * @brief: Marks all observers of the given @p resource so that call to the @f coap_notify_observers()
 *    could notify them. Optionally, when @p query is not NULL, marks only those observer, who has
 *    the same query
 * 
 * Initiate the sending of an Observe packet for all observers of @p resource,
 *   optionally matching @p query if not NULL
 *
 * @param resource:
 *    the CoAP resource to use
 * @param query:
 *    the Query to match against or NULL
 *
 * @returns:
 *    1 if the Observe has been triggered
 *    0 otherwise
 */
int coap_resource_notify_observers(
    coap_resource_t *resource,
    const coap_string_t *query
);


/* ---------------------------------------- [Static-inline functions] ----------------------------------------- */

/**
 * @brief: Sets the notification message type of resource @p resource to given @p mode
 * 
 * @param resource:
 *    the resource to update.
 * @param mode:
 *    must be one of: @c COAP_RESOURCE_FLAGS_NOTIFY_NON, @c COAP_RESOURCE_FLAGS_NOTIFY_CON.
 */
COAP_STATIC_INLINE void
coap_resource_set_mode(coap_resource_t *resource, int mode){
  resource->flags = (resource->flags &
    ~(COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON)) |
    (mode & (COAP_RESOURCE_FLAGS_NOTIFY_CON|COAP_RESOURCE_FLAGS_NOTIFY_NON));
}

/**
 * @brief: Sets the @p resource->user_data. The user_data is exclusively used by the
 *    library-user and can be used as context in the handler functions.
 *
 * @param resource:
 *    resource to attach the data to
 * @param data:
 *    data to attach to the user_data field. This pointer is only used for
 *    storage, the data remains under user control
 */
COAP_STATIC_INLINE void
coap_resource_set_userdata(coap_resource_t *resource, void *data){
  resource->user_data = data;
}

/**
 * @param resource:
 *    resource to retrieve the user_darta from
 * @returns:
 *    the @p resource->user_data pointer 
 */
COAP_STATIC_INLINE void *
coap_resource_get_userdata(coap_resource_t *resource){
  return resource->user_data;
}

/**
 * @brief: Set whether a @p resource is observable. If the resource is observable
 *    and the client has set the COAP_OPTION_OBSERVE in a request packet, then
 *    whenever the state of the resource changes (a call to @f coap_resource_trigger_observe()),
 *    an Observer response will get sent.
 *
 * @param resource:
 *    the CoAP resource to use
 * @param mode:
 *    1 if Observable is to be set
 *    0 otherwise
 */
COAP_STATIC_INLINE void
coap_resource_set_get_observable(coap_resource_t *resource, int mode){
  resource->observable = mode ? 1 : 0;
}

/**
 * @param resource:
 *    the CoAP resource to check
 * @returns:
 *    the URI-Path if it exists
 *    NULL otherwise
 */
COAP_STATIC_INLINE coap_str_const_t*
coap_resource_get_uri_path(coap_resource_t *resource){
  if (resource)
    return resource->uri_path;
  return NULL;
}

#endif /* COAP_RESOURCE_H_ */
