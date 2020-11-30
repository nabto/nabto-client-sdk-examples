#pragma once

#include <string>

#include <nabto/nabto_client.h>

namespace nabto {
namespace examples {
namespace common {

class ClientKey {
 public:
    // Load a key into the connection, if the key does not exists create it as <homedir>/keys/client.key
    static bool loadKey(const std::string& homeDir, NabtoClient* context, NabtoClientConnection* connection);
};

} } } // namespace
