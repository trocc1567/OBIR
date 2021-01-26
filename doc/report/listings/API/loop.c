// Run main processing loop
ESP_LOGI(TAG, "Beginning dispatch loop");
unsigned wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
while (1) {
	if (packet_loss_flag) 
	{
		coap_debug_set_packet_loss("0%");
		packet_loss_flag=0;
	}
	// Server incoming and outcoming packages
	int result = coap_run_once(ctx, wait_ms);

	// Back to CoAP server initialization, when error occurs 
	if (result < 0){
		coap_free_context(ctx);
		break;
	}
	// Decrement timeout if the last one was shorter than expected
	else if (result < wait_ms)
		wait_ms -= result;
	// Reset the timeout otherwise
	else
		wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;