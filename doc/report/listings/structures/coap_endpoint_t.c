typedef struct coap_endpoint_t {

    struct coap_endpoint_t *next;
    struct coap_context_t *context; 

    uint16_t        default_mtu;
    coap_socket_t   sock;
    
    coap_address_t  bind_addr;
    coap_session_t *sessions;

} coap_endpoint_t;