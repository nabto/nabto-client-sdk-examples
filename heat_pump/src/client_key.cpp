#include "client_key.hpp"
#include "file.hpp"

#include <sstream>

namespace nabto {
namespace examples {
namespace common {

bool ClientKey::loadKey(const std::string& homeDir, NabtoClient* context, NabtoClientConnection* connection)
{
    std::stringstream ss;
    ss << homeDir << "/keys/client.key";
    std::string keyFile = ss.str();
    NabtoClientError ec;
    if (!File::exists(keyFile)) {
        // create a key and save it.
        char* s = NULL;
        ec = nabto_client_create_private_key(context, &s);
        std::string privateKey(s);
        nabto_client_string_free(s);
        if (ec != NABTO_CLIENT_EC_OK) {
            return false;
        }
        if (!File::writeFile(keyFile, privateKey)) {
            return false;
        }
    }

    std::string keyContent;
    // load private key and load key into connection
    if (!File::readFile(keyFile, keyContent)) {
        return false;
    }

    ec = nabto_client_connection_set_private_key(connection, keyContent.c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    return true;
}

} } } // namespace
