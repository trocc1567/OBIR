
/**
 * @brief Initializes resources present on the server
 * 
 * @param context Pointer to the CoAP context stack
 * @returns 0 on success and a negative number at failure. At the failure
 *  all resources are deleted from the context.
 */
int resources_init(coap_context_t *context);

/**
 * @brief Clears all resources from the context and closes SNTP deamon.
 * 
 * @param context Context related with resources to delete
 */
void resources_deinit(coap_context_t *context);

/**
 * @brief 
 * 
 * @param ctx 
 * @param resource 
 * @param session 
 * @param request 
 * @param token 
 * @param query 
 * @param response 
 */
void hnd_get(
    coap_resource_t *resource,
    coap_session_t *session, 
    coap_pdu_t *request,
    coap_binary_t *token, 
    coap_string_t *query,
    coap_pdu_t *response
);

/**
 * @brief Construct a new hnd espressif put object
 * 
 * @param ctx 
 * @param resource 
 * @param session 
 * @param request 
 * @param token 
 * @param query 
 * @param response 
 */
void hnd_put(
    coap_resource_t *resource,
    coap_session_t *session,
    coap_pdu_t *request,
    coap_binary_t *token,
    coap_string_t *query,
    coap_pdu_t *response
);

/**
 * @brief 
 * 
 * @param ctx 
 * @param resource 
 * @param session 
 * @param request 
 * @param token 
 * @param query 
 * @param response 
 */
void hnd_delete(
    coap_context_t *ctx,
    coap_resource_t *resource,
    coap_session_t *session,
    coap_pdu_t *request,
    coap_binary_t *token,
    coap_string_t *query,
    coap_pdu_t *response
);
