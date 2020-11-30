#pragma once

#include "file.hpp"

#include <string>
#include <memory>
#include <sstream>

#include <3rdparty/nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class ClientState {
 public:
    ClientState(const std::string& productId, const std::string& deviceId, const std::string& deviceFingerprint, const std::string& serverConnectToken)
        : productId_(productId), deviceId_(deviceId), deviceFingerprint_(deviceFingerprint), serverConnectToken_(serverConnectToken)
    {
    }

    std::string getProductId()
    {
        return productId_;
    }
    std::string getDeviceId()
    {
        return deviceId_;
    }
    std::string getDeviceFingerprint()
    {
        return deviceFingerprint_;
    }
    std::string getServerConnectToken()
    {
        return serverConnectToken_;
    }

    static std::unique_ptr<ClientState> loadClientState(const std::string& homedir, const std::string& stateFileName)
    {
        std::stringstream ss;
        ss << homedir << "/state/" << stateFileName;

        std::string content;
        if (!common::File::readFile(ss.str(), content)) {
            return nullptr;
        }

        nlohmann::json j;
        try {
            j = nlohmann::json::parse(content);
        } catch (std::exception& e) {
            return nullptr;
        }

        std::string productId;
        std::string deviceId;
        std::string deviceFingerprint;
        std::string serverConnectToken;

        try {
            productId = j["ProductId"].get<std::string>();
            deviceId = j["DeviceId"].get<std::string>();
            deviceFingerprint = j["DeviceFingerprint"].get<std::string>();
            serverConnectToken = j["ServerConnectToken"].get<std::string>();
        } catch (std::exception& e) {
            return nullptr;
        }

        return std::make_unique<ClientState>(productId, deviceId, deviceFingerprint, serverConnectToken);
    }

    bool writeClientState(const std::string& homedir, const std::string& stateFileName)
    {
        nlohmann::json root;
        root["ProductId"] = productId_;
        root["DeviceId"] = deviceId_;
        root["DeviceFingerprint"] = deviceFingerprint_;
        root["ServerConnectToken"] = serverConnectToken_;

        std::stringstream ss;
        ss << homedir << "/state/" << stateFileName;

        return common::File::writeFile(ss.str(), root.dump());
    }

 private:
    std::string productId_;
    std::string deviceId_;
    std::string deviceFingerprint_;
    std::string serverConnectToken_;
};

} } } // namespace
