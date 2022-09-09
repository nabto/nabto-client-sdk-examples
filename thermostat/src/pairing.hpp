#pragma once

#include "nabto_client_ptr.hpp"

#include <string>
#include <set>

#include <memory>

namespace nabto {
namespace examples {
namespace thermostat {

enum class PairingMode {
    NONE,
    PASSWORD_OPEN,
    PASSWORD_INVITE,
    LOCAL_INITIAL,
    LOCAL_OPEN
};

// response from CoAP GET /pairing
class PairingResponse {
 public:

    std::string getProductId() const {
        return  productId_;
    }

    std::string getDeviceId() const {
        return deviceId_;
    }

    std::set<PairingMode> modes_;
    std::string nabtoVersion_;
    std::string appVersion_;
    std::string appName_;
    std::string productId_;
    std::string deviceId_;
};

class User {
 public:

    std::string getServerConnectToken() {
        return sct_;
    }

    std::string username_;
    std::string displayName_;
    std::string fingerprint_;
    std::string sct_;
};

bool interactive_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& friendlyName);

bool pairing_string_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& pairingString, const std::string& friendlyName);

std::unique_ptr<PairingResponse> get_pairing(NabtoClient* client, NabtoClientConnection* connection);

std::unique_ptr<User> get_me(NabtoClient* client, NabtoClientConnection* connection);

} } } // namespace
