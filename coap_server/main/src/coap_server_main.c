#include "freertos/FreeRTOS.h" // FreeRTOS tasks
#include "esp_log.h"           // Logging mechanisms
#include "nvs_flash.h"         // Non-Volatile storage flash
#include "station.h"           // WiFi connection [auth]

/* ---------------------------------- Configuration ---------------------------------- */

// WiFi access point data
#define EXAMPLE_ESP_WIFI_SSID      "Patryk"
#define EXAMPLE_ESP_WIFI_PASS      "deus_vult"

/* --------------------------- Global & static definitions --------------------------- */

// Source file's tag
static char *TAG = "main";

// Global variables initialization
TaskHandle_t main_handler;

/* ------------------------------------- Declarations --------------------------------- */

void coap_example_thread(void *p);

/* ---------------------------------------- Code -------------------------------------- */

/**
 * @brief Main task.
 */
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
