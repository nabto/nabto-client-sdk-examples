#pragma once

#include <fstream>

#include <string>
#include <memory>
#include <sstream>

#include <3rdparty/nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace heat_pump {

class File {
 public:
    static bool exists(const std::string& path)
    {
        std::ifstream f(path);
        return (f.is_open() && !f.fail());
    }

    static bool readFile(const std::string& path, std::string& content)
    {
        try {
            std::ifstream f(path);
            std::string str((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
            content = str;
            return true;
        } catch (std::exception &) {
            return false;
        }
    }

    static bool writeFile(const std::string& path, const std::string& content)
    {
        try {
            std::ofstream f(path);
            f << content;
            return true;
        } catch (std::exception &) {
            return false;
        }
    }
};

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
        if (!File::readFile(ss.str(), content)) {
            return nullptr;
        }

        nlohmann::json j;
        try {
            j = nlohmann::json::parse(content);
        } catch (std::exception& ) {
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
        } catch (std::exception& ) {
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

        return File::writeFile(ss.str(), root.dump());
    }

 private:
    std::string productId_;
    std::string deviceId_;
    std::string deviceFingerprint_;
    std::string serverConnectToken_;
};

/**
 * Each client application has a configured api key.
 *
 * Beside an api key, the client config can also contain an url to be
 * used for the client load balancer.
 */

class ClientConfig
{
 public:
    static bool loadClientConfig(const std::string& homedir, const std::string& clientConfigFileName, const std::string& defaultServerKey, NabtoClientConnection* connection)
    {
        std::stringstream ss;
        ss << homedir << "/config/" << clientConfigFileName;
        std::string fileName = ss.str();
        NabtoClientError ec;
        if (!File::exists(fileName)) {
            // write a default client config
            nlohmann::json j;
            j["ServerKey"] = defaultServerKey;
            std::string c = j.dump(4);
            if (!File::writeFile(fileName, c)) {
                return false;
            }
        }

        std::string clientConfigString;
        if (!File::readFile(fileName, clientConfigString)) {
            return false;
        }

        nlohmann::json c;
        try {
            c = nlohmann::json::parse(clientConfigString);
        } catch (std::exception& ) {
            // could not load json, thats an unrecoverable error
            return false;
        }

        try {
            std::string key = c["ServerKey"].get<std::string>();
            ec = nabto_client_connection_set_server_key(connection, key.c_str());
            if (ec != NABTO_CLIENT_EC_OK) {
                return false;
            }
        } catch (std::exception& ) {
            // could not load client key, thats an unrecoverable error
            return false;
        }

        try {
            std::string url = c["ServerUrl"].get<std::string>();
            ec = nabto_client_connection_set_server_url(connection, url.c_str());
            if (ec != NABTO_CLIENT_EC_OK) {
                return false;
            }
        } catch (std::exception& ) {
            // could not load client server url, that's an optional parameter.
        }
        return true;
    }

 private:
    std::string key_;
    std::string url_;

};


} } } // namespace
