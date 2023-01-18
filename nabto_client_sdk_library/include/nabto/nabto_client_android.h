#ifndef _NABTO_CLIENT_ANDROID_H_
#define _NABTO_CLIENT_ANDROID_H_

#include <nabto/nabto_client.h>

extern "C" {

/**
 * Internal functions shared between the nabto client core and the
 * nabto client wrapper, these functions can change without notice.
 */

/**
 * Set the handle for the wifi network, this will be used for local
 * connections and mdns.
 */
NABTO_CLIENT_DECL_PREFIX void NABTO_CLIENT_API
nabto_client_android_set_wifi_network_handle(NabtoClient* client, uint64_t network);

} // extern C

#endif
