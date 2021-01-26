// Initialize server's address
coap_address_init(&server);
server.addr.sa.sa_family = AF_INET;
server.addr.sin.sin_addr = server_ip_address;
server.addr.sin.sin_port = htons(5683);

// Initialize client session
coap_session_t *session = coap_new_client_session(context, NULL, &server);
if (!session) 
    exit(1);

// Initialize PDU
coap_pdu_t *pdu = coap_pdu_init(
    message_type, 
    request_code, 
    coap_new_message_id(session),
    coap_session_max_pdu_size(session)
);
if (!pdu)
    return 0;

// Add token to the PDU
if (!coap_add_token(pdu, sizeof(token), (unsigned char*)&token)) {
    exit(1);