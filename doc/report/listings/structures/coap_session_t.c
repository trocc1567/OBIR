typedef struct coap_session_t {
  
    struct coap_session_t *next;
    struct coap_context_t *context;
    void                  *app;                        

    /* --------------- Basic session info -------------- */

    coap_session_type_t  type;
    coap_session_state_t state;
    unsigned             ref;

    /* -------------- Session's parameters ------------- */

    unsigned           mtu;
    unsigned int       max_retransmit;      
    coap_fixed_point_t ack_timeout;   
    coap_fixed_point_t ack_random_factor;

    /* ---------------- Endpoints' info ---------------- */

    coap_address_t          remote_addr;
    coap_address_t          local_addr;
    coap_socket_t           sock;
    struct coap_endpoint_t *endpoint;

    /* ----------------- Messages' info ---------------- */

    uint16_t             tx_mid;
    uint8_t              con_active;
    struct coap_queue_t *delayqueue;
    coap_tick_t          last_rx_tx;
    coap_tick_t          last_tx_rst;
    
} coap_session_t;