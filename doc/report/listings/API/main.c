void app_main(){

    // Initialize NVS flash for other components' use
    ESP_ERROR_CHECK(nvs_flash_init());

    // LOG start of the Programm
    ESP_LOGI(TAG, "Connecting to WiFi AP...");

    // Connect via WiFi to the AP
    wifi_connect(EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);

    // Create UDP server tasl
    xTaskCreate(coap_example_thread, "coap", 1024 * 10, NULL, 5, NULL);
    // Wait for udpp server task to finish
    main_handler = xTaskGetCurrentTaskHandle();
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

    // Disconnect from the AP
    wifi_disconnect();
}