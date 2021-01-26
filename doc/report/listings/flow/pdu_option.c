char buf[1024];
char *sbuf = buf;
size_t buflen;
coap_optlist_t *optlist_chain = NULL;

// Add in the URI options
buflen = sizeof(buf);
int res = coap_split_path((const uint8_t*) uri, 
    strlen(uri), sbuf, &buflen);
while (res--) {
    if (!coap_insert_optlist(
        &optlist_chain,
        coap_new_optlist(
            COAP_OPTION_URI_PATH,
            coap_opt_length(sbuf), 
            coap_opt_value(sbuf)
        )))
        exit(1);
    sbuf += coap_opt_size(sbuf);
}



// Add in the QUERY options
buflen = sizeof(buf);
res = coap_split_query((const uint8_t*) query,
    strlen(query), sbuf, &buflen);
while (res--) {
    if (!coap_insert_optlist(
        &optlist_chain,
        coap_new_optlist(
            COAP_OPTION_URI_QUERY,
            coap_opt_length(sbuf),
            coap_opt_value(sbuf)
        )))
        exit(1);
    sbuf += coap_opt_size(sbuf);
}

// Add in options to the pdu
if (!coap_add_optlist_pdu(pdu, &optlist_chain))
    exit(1);
