#pragma once

#include "nabto_client_ptr.hpp"

#include <string>
#include <set>

#include <memory>

namespace nabto {
namespace examples {
namespace common {

enum class PairingMode {
    NONE,
    PASSWORD_OPEN,
    PASSWORD_INVITE,
    LOCAL_INITIAL,
    LOCAL_OPEN
};


class ClientSettings {
 public:
    ClientSettings(const std::string& productId, const std::string& deviceId, const std::string& serverConnectToken)
        : productId_(productId), deviceId_(deviceId), serverConnectToken_(serverConnectToken)
    {
    }

    std::string getProductId() { return productId_; }
    std::string getDeviceId() { return deviceId_; }
    std::string getServerConnectToken() { return serverConnectToken_; }

 private:
    std::string productId_;
    std::string deviceId_;
    std::string serverConnectToken_;
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
        return serverConnectToken_;
    }

    std::string id_;
    std::string name_;
    std::string fingerprint_;
    std::string serverConnectToken_;
};

bool interactive_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& friendlyName);

bool string_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& friendlyName, const std::string& pairingString);

std::unique_ptr<PairingResponse> get_pairing(NabtoClient* client, NabtoClientConnection* connection);

std::unique_ptr<User> get_me(NabtoClient* client, NabtoClientConnection* connection);

} } } // namespace