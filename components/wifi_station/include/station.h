#include "esp_event.h"

/**
 * @brief Performs basic routine to connect ESP to the AP in the station mode
 * 
 * @param ssid Name of the AP (up to 32 characters, longer ssid will be truncated)
 * @param passwd Password to the AP (up to 64 characters, longer password will be truncated)
 */
void wifi_connect(char* ssid, char *passwd);

/**
 * @brief Performs basic routine to diconnect ESP from the AP in the station mode
 *  and deinitialize all possessed structures
 */
void wifi_disconnect(void);