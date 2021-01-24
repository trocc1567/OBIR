#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

/* ---------------------------------- Configuration ---------------------------------- */

// WiFi configuration
#define EXAMPLE_ESP_MAXIMUM_RETRY  10

/* --------------------------- Global & static definitions --------------------------- */

/* WiFi connection status flags
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries  */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

/* Tag for log from the file */
static const char *TAG = "wifi_station";

/* Initializglobal, inter-function variables */
static int s_retry_num;
static EventGroupHandle_t s_wifi_event_group;

/* ---------------------------------------- Code -------------------------------------- */

/**
 * @brief Callback for esp_event module managing WiFi events coming from
 *  Wi-Fi Driver and TCP stack
 * 
 * @param arg 
 * @param event_base 
 * @param event_id 
 * @param event_data 
 */
static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    // WIFI_EVENT_STA_START : 
    //     triggered when esp_wifi_start() succesfully returned
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {

        // Tries to connect ESP to the configured AP
        esp_wifi_connect();
    } 
    
    // WIFI_EVENT_STA_DISCONNECTED :
    //     triggered when esp_wifi_connect() returns sucesfully. At that point
    //     system is ready to use Wi-Fi-related functions. LwIP (default IP stack)
    //     is not ready, though. As the app uses IP-functions (namely UDP)
    //     we wait for IP_EVENT_STA_GOT_IP event to come.
    // else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) ...

    // IP_EVENT_STA_GOT_IP :
    //     triggered when DHCP client succesfully gets IPv4 address from DHCP server
    //     (AP in this case).
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IPv4: %s ", ip4addr_ntoa(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
    
    // WIFI_EVENT_STA_DISCONNECTED :
    //     triggered when esp_wifi_disconnect/stop/deinit/restart() is called and the
    //     station is already connected. Also triggered when esp_wifi_connect() routine
    //     fails to connect to configured AP.
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG,"Connect to the AP failed");
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "Retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
    }
}


/**
 * @brief Performs basic routine to connect ESP to the AP in the station mode
 * 
 * @param ssid Name of the AP (up to 32 characters, longer ssid will be truncated)
 * @param passwd Password to the AP (up to 64 characters, longer password will be truncated)
 */
void wifi_connect(char* ssid, char *passwd){

    // Initialized LwIP (TCP/IP stack) (wrapper around tcpip_adapter_init())
    esp_netif_init();

    // Creates default event loop (esp_event API) that's used by Wi-Fi driver 
    // and LwIP to communicate with app
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // Register handlers for anticipated events
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

    // Initialize Wi-Fi driver with default configuration
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    
    // Initialize configuration structure for STA mode
    //     - ssid               : name of the target AP
    //     - password           : password of the target AP
    //     - threshold.authmode : mode of authentication (default : OPEN)
    //
    // If password is a non-epty string and threshold.authmode is set to default,
    // Wi-Fi driver will connect with any mode (WPA, WPA2, ...) that the AP supports.
    // If non-default value is set, only the target authentication mode is used
    // and so driver doesn't connect to AP that does not support it.
    //
    // Using strncpy() to put ssid and password in the suitable fields is a safe
    // practice preventing buffer overflow.
    wifi_config_t wifi_config = {
        .sta = {
            .threshold = {
                .authmode = WIFI_AUTH_WPA2_PSK
            }
        },
    };
    strncpy((char *) wifi_config.sta.ssid, ssid, 32);
    strncpy((char *) wifi_config.sta.password, passwd, 64);
    // Initialize station in the STA mode and configure it with the structure initialized above
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );

    // Create event group (freertos/event_groups) that will be used for communication between
    // connection procedure and the event handler.
    s_wifi_event_group = xEventGroupCreate();
    // Start Wi-Fi connection
    ESP_ERROR_CHECK(esp_wifi_start());

    // Wait for event bits from the event callback that will allow function to proceed
    // (successfull conection or fail)
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY
    );
    // Check if connection suceeded
    if (bits & WIFI_CONNECTED_BIT)
        ESP_LOGI(TAG, "Connected to AP ssid:%s password:%s", ssid, passwd);
    else if (bits & WIFI_FAIL_BIT)
        ESP_LOGI(TAG, "Failed to connect to ssid:%s password:%s", ssid, passwd);
    else
        ESP_LOGE(TAG, "UNEXPECTED EVENT");

    // Unregister handler that was used only at the connection step (other should be uregistered
    // at wifi_dicsonnect() function)
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_START, &event_handler));

    return;
}

/**
 * @brief Performs basic routine to diconnect ESP from the AP in the station mode
 *  and deinitialize all possessed structures
 */
void wifi_disconnect(void){

    // Get name of the AP for further LOG
    wifi_config_t wifi_config;
    esp_wifi_get_config(ESP_IF_WIFI_STA, &wifi_config);
    char ap_name[32];
    strncpy(ap_name, (char *) wifi_config.sta.ssid, 32);

    // Unregister handlers form the default wifi group
    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &event_handler));
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler));

    // Stop WiFi driver
    ESP_ERROR_CHECK(esp_wifi_stop());

    // Deinitialize WiFi driver
    ESP_ERROR_CHECK(esp_wifi_deinit());

    // Delete FreeRTOS event group that was used for inter-function communication
    vEventGroupDelete(s_wifi_event_group);
    s_wifi_event_group = NULL;
    
    // Print log about successfull disconection
    ESP_LOGI(TAG, "Disconnected from %s", ap_name);

    return;
}