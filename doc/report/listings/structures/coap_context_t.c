typedef struct coap_context_t {
    
    void *app;
    
    /* ---------------- Context's state ---------------- */
    
    struct coap_resource_t    *resources;        
    struct coap_resource_t    *unknown_resource;  
    coap_queue_t              *sendqueue;                  
    coap_tick_t                sendqueue_basetime;           
    coap_endpoint_t           *endpoint;                
    coap_session_t            *sessions;                 
    uint16_t                   message_id;                      
    
    /* ----------- Context-specific routines ----------- */

    coap_response_handler_t response_handler;
    coap_nack_handler_t     nack_handler;
    coap_ping_handler_t     ping_handler;
    
    ssize_t (*network_send)(
        coap_socket_t *sock,
        const coap_session_t *session, 
        const uint8_t *data, 
        size_t datalen);
    ssize_t (*network_read)(
        coap_socket_t *sock, struct coap_packet_t *packet);
    

    /* -------------- Context's parameters ------------- */

    coap_opt_filter_t known_options;
    unsigned int      session_timeout;   
    unsigned int      max_idle_sessions; 
  
} coap_context_t;