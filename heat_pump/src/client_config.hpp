#pragma once

#include <string>
#include "file.hpp"

namespace nabto {
namespace examples {
namespace common {

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
        } catch (std::exception& e) {
            // could not load json, thats an unrecoverable error
            return false;
        }

        try {
            std::string key = c["ServerKey"].get<std::string>();
            ec = nabto_client_connection_set_server_key(connection, key.c_str());
            if (ec != NABTO_CLIENT_EC_OK) {
                return false;
            }
        } catch (std::exception& e) {
            // could not load client key, thats an unrecoverable error
            return false;
        }

        try {
            std::string url = c["ServerUrl"].get<std::string>();
            ec = nabto_client_connection_set_server_url(connection, url.c_str());
            if (ec != NABTO_CLIENT_EC_OK) {
                return false;
            }
        } catch (std::exception& e) {
            // could not load client server url, that's an optional parameter.
        }
        return true;
    }

 private:
    std::string key_;
    std::string url_;

};

} } } // namespace
