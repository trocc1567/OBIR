
// Initialize CoAP's contex structure
coap_context_t *ctx = coap_new_context(NULL);
if (!ctx)
    exit(1);

// Prepare interface for listening
coap_address_init(&serv_addr);
serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
serv_addr.addr.sin.sin_family      = AF_INET;
serv_addr.addr.sin.sin_port        = htons(PORT);

// Create UDP endpoint
coap_endpoint_t *ep = coap_new_endpoint(ctx, &serv_addr);
if (!ep)
    exit(1);