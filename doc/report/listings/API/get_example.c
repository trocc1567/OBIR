// Handle ' GET /metrics/PUT_inputs' request
if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("metrics/GET_inputs")) ){
	
	char bufor[20];
	uint8_t size;
	size=snprintf(bufor, 14, "GET inputs: %d", GET_counter);
	// Send data with dedicated function
	coap_add_data_blocked_response(
		resource,
		session,
		request,
		response,
		token,
		COAP_MEDIATYPE_TEXT_PLAIN,
		0,
		size,
		(uint8_t *) bufor
	);
}