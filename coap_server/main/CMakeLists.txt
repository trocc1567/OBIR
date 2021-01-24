# Source files and includes
idf_component_register(SRCS "src/coap_server_main.c" "src/coap_server.c" "src/coap_handlers.c" "src/rpn_stack.c"
                       INCLUDE_DIRS "include"
                       PRIV_REQUIRES wifi_station esp_libcoap nvs_flash pthread)
