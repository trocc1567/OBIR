#include <string.h>            // Basic string operations
#include <sys/socket.h>        // Sockets-related constants
#include "esp_log.h"           // Logging
#include "coap.h"              // CoAP implementation
#include "coap_handlers.h"     // Handlers for CoAP resources [auth]

/* ---------------------------------- Configuration ---------------------------------- */

// Local port
#define PORT 5683

/**
 * @brief: Log level for the libcoap internals
 * 
 * @note: Debugging tools require a few Kb of stack in some points. Assigning
 *    too small stack to the stack and simultanously using a low (i.e. sensitive)
 *    log level will lead to the Exception.
 *  
 */
#define COAP_LOGGING_LEVEL LOG_DEBUG

/* --------------------------- Global & static definitions --------------------------- */

// Source file's tag
static char *TAG = "coap_server";

/* ------------------------------------- Declarations --------------------------------- */

// Global variables initialization
extern TaskHandle_t main_handler;


/* ------------------------------------ Thread Code ----------------------------------- */

/**
 * @brief Thread running CoAP server
 * @param pvParameters
 */
void coap_example_thread(void *pvParameters){

    // Wait for main to block on xTaskNotifyTake()
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Startup CoAP stack
    coap_startup();
    coap_set_log_level(COAP_LOGGING_LEVEL);

    // Create CoAP module's context
    coap_context_t *ctx = NULL;

    // Run CoAP initialization process
    while (1) {

        // Initialize CoAP's contex structure
        ctx = coap_new_context(NULL);
        if (!ctx) {
           continue;
        }

        // Initialize server's resources
        if(resources_init(ctx))
            break;

        /* Prepare the CoAP server socket (it's wrapper around BSD socket approach)
         *
         *     .sin_addr.s_addr : address of the socket (setting to 0 picks random
         *                        addres possessed by the server. ESP has only one
         *                        IP available at the time)
         *     .sin_family : protocoly type (AF_INET = IPv4)
         *     .sin_port : port number for th socket (setting to 0 picks random port)
         * 
         * @note : htonl() and htons() functions revert IP and PORT byte order to 
         * suite network order.
         */
        ESP_LOGI(TAG, "Initializing CoAP socket");
        coap_address_t   serv_addr;
        coap_address_init(&serv_addr);
        serv_addr.addr.sin.sin_addr.s_addr = INADDR_ANY;
        serv_addr.addr.sin.sin_family      = AF_INET;
        serv_addr.addr.sin.sin_port        = htons(PORT);

        // Create UDP endpoint
        ESP_LOGI(TAG, "Creating the endpoint");
        coap_endpoint_t *ep = coap_new_endpoint(ctx, &serv_addr);
        if (!ep) {
           break;
        }

        /*-----------------------------------------------------------------------------*/

        // Run main processing loop
        ESP_LOGI(TAG, "Beginning dispatch loop");
        unsigned wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
        while (1) {

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

        }
        
    }

    // Clean context of the CoAP module before finishing task
    ESP_LOGI(TAG, "Cleaning up CoAP context");
    resources_deinit(ctx);
    coap_free_context(ctx);
    coap_cleanup();

    // Notify main to disconec from WiFi AP
    xTaskNotifyGive(main_handler);

    // Delete task itself
    vTaskDelete(NULL);
}
