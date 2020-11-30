#include "pairing.hpp"

#include "json_config.hpp"
#include "scanner.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>

namespace nabto {
namespace examples {
namespace common {

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

static NabtoClientError connect(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientError ec;
    NabtoClientFuturePtr future(nabto_client_future_new(client));

    nabto_client_connection_connect(connection, future.get());

    ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        if (ec == NABTO_CLIENT_EC_NO_CHANNELS) {
            auto localStatus = nabto_client_connection_get_local_channel_error_code(connection);
            auto remoteStatus = nabto_client_connection_get_remote_channel_error_code(connection);
            auto directCandidatesStatus = nabto_client_connection_get_direct_candidates_channel_error_code(connection);
            NabtoClientError ec2;
            if (localStatus != NABTO_CLIENT_EC_NONE) {
                if (localStatus == NABTO_CLIENT_EC_NOT_FOUND) {
                    std::cerr << "The device was not found on the local network" << std::endl;
                } else {
                    std::cerr << "Could not connect locally to the device " << nabto_client_error_get_message(localStatus) << std::endl;
                }
                ec2 = ec;
            }
            if (remoteStatus != NABTO_CLIENT_EC_NONE) {
                if (remoteStatus == NABTO_CLIENT_EC_FORBIDDEN) {
                    std::cerr << "The client is not allowed to make requests to the basestation with the product id and server key combination. Did you remember to add the appropriate application to the product in the console?" << std::endl;
                } else {
                    std::cerr << "Could not connect to the device through the basestation " << nabto_client_error_get_message(remoteStatus) << std::endl;
                }
                ec2 = ec;
            }
            if (directCandidatesStatus != NABTO_CLIENT_EC_NONE) {
                std::cerr << "Could not connect using direct candidates to the device"  << nabto_client_error_get_message(directCandidatesStatus) << std::endl;
                ec2 = ec;
            }
            return ec2;
        }

        std::cerr << "Connect failed " << nabto_client_error_get_message(ec) << std::endl;
        return ec;
    }
    return NABTO_CLIENT_EC_OK;
}

std::string pairingModeAsString(PairingMode mode) {
    if (mode == PairingMode::PASSWORD_OPEN) {
        return "PasswordOpen";
    } else if (mode == PairingMode::LOCAL_OPEN) {
        return "LocalOpen";
    } else if (mode == PairingMode::PASSWORD_INVITE) {
        return "PasswordInvite";
    } else if (mode == PairingMode::LOCAL_INITIAL) {
        return "LocalInitial";
    }
    return "unknown";
}

std::unique_ptr<PairingResponse> get_pairing(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientCoapPtr coap = NabtoClientCoapPtr(nabto_client_coap_new(connection, "GET", "/iam/pairing"));
    NabtoClientFuturePtr future = NabtoClientFuturePtr(nabto_client_future_new(client));
    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }

    void* payload;
    size_t payloadLength;

    uint16_t statusCode;
    nabto_client_coap_get_response_status_code(coap.get(), &statusCode);

    if (statusCode != 205) {
        return nullptr;
    }
    if (nabto_client_coap_get_response_payload(coap.get(), &payload, &payloadLength) != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }

    std::unique_ptr<PairingResponse> pr = std::make_unique<PairingResponse>();

    nlohmann::json p = nlohmann::json::from_cbor(std::vector<uint8_t>(static_cast<uint8_t*>(payload), static_cast<uint8_t*>(payload)+payloadLength));

    if (p.contains("Modes")) {
        auto ms = p["Modes"];
        if (ms.is_array()) {
            for (auto mode : ms) {
                if (mode.is_string()) {
                    std::string stringMode = mode.get<std::string>();
                    if (stringMode == "PasswordOpen") {
                        pr->modes_.insert(PairingMode::PASSWORD_OPEN);
                    } else if (stringMode == "LocalOpen") {
                        pr->modes_.insert(PairingMode::LOCAL_OPEN);
                    } else if (stringMode == "PasswordInvite") {
                        pr->modes_.insert(PairingMode::PASSWORD_INVITE);
                    } else if (stringMode == "LocalInitial") {
                        pr->modes_.insert(PairingMode::LOCAL_INITIAL);
                    }
                }
            }
        }
    }

    if (p.contains("NabtoVersion")) {
        auto tmp = p["NabtoVersion"];
        if (tmp.is_string()) {
            tmp.get_to(pr->nabtoVersion_);
        }
    }
    if (p.contains("AppVersion")) {
        auto tmp = p["AppVersion"];
        if (tmp.is_string()) {
            tmp.get_to(pr->appVersion_);
        }
    }
    if (p.contains("AppName")) {
        auto tmp = p["AppName"];
        if (tmp.is_string()) {
            tmp.get_to(pr->appName_);
        }
    }
    if (p.contains("ProductId")) {
        auto tmp = p["ProductId"];
        if (tmp.is_string()) {
            tmp.get_to(pr->productId_);
        }
    }
    if (p.contains("DeviceId")) {
        auto tmp = p["DeviceId"];
        if (tmp.is_string()) {
            tmp.get_to(pr->deviceId_);
        }
    }

    return pr;
}


std::unique_ptr<User> get_me(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientCoapPtr coap = NabtoClientCoapPtr(nabto_client_coap_new(connection, "GET", "/iam/me"));
    NabtoClientFuturePtr future = NabtoClientFuturePtr(nabto_client_future_new(client));
    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }

    void* payload;
    size_t payloadLength;

    uint16_t statusCode;
    nabto_client_coap_get_response_status_code(coap.get(), &statusCode);

    if (statusCode != 205) {
        return nullptr;
    }
    if (nabto_client_coap_get_response_payload(coap.get(), &payload, &payloadLength) != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }

    std::unique_ptr<User> user = std::make_unique<User>();

    nlohmann::json p = nlohmann::json::from_cbor(std::vector<uint8_t>(static_cast<uint8_t*>(payload), static_cast<uint8_t*>(payload)+payloadLength));

    if (p.contains("Id")) {
        auto tmp = p["Id"];
        if (tmp.is_string()) {
            tmp.get_to(user->id_);
        }
    }

    if (p.contains("Name")) {
        auto tmp = p["Name"];
        if (tmp.is_string()) {
            tmp.get_to(user->name_);
        }
    }
    if (p.contains("Fingerprint")) {
        auto tmp = p["Fingerprint"];
        if (tmp.is_string()) {
            tmp.get_to(user->fingerprint_);
        }
    }
    if (p.contains("ServerConnectToken")) {
        auto tmp = p["ServerConnectToken"];
        if (tmp.is_string()) {
            tmp.get_to(user->serverConnectToken_);
        }
    }

    return user;
}

bool local_initial_pair(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, "POST", "/iam/pairing/local-initial"));
    NabtoClientFuturePtr future(nabto_client_future_new(client));

    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Pairing failed " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }
    uint16_t status;
    nabto_client_coap_get_response_status_code(coap.get(), &status);
    if (status != 201) {
        // TODO print error
        return false;
    }
    return true;
}


bool local_open_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& name)
{
    nlohmann::json root;
    root["Username"] = name;

    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, "POST", "/iam/pairing/local-open"));
    std::vector<uint8_t> payload = nlohmann::json::to_cbor(root);
    nabto_client_coap_set_request_payload(coap.get(), CONTENT_FORMAT_APPLICATION_CBOR, payload.data(), payload.size());
    NabtoClientFuturePtr future(nabto_client_future_new(client));

    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Pairing failed " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }
    uint16_t status;
    nabto_client_coap_get_response_status_code(coap.get(), &status);
    if (status != 201) {
        // TODO print error
        return false;
    }
    return true;
    //     std::string reason;
    //     auto buffer = coap->getResponsePayload();
    //     reason = std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
    //     std::cout << "Could not pair with the device status: " << coap->getResponseStatusCode() << " " << reason << std::endl;
    //     return false;
    // }
    // return true;
}

static bool password_authenticate_connection(NabtoClient* client, NabtoClientConnection* connection, const std::string& username, const std::string& password)
{
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    nabto_client_connection_password_authenticate(connection, username.c_str(), password.c_str(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Password authentication failed " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }
    return true;
}

bool password_pair_password(NabtoClient* client, NabtoClientConnection* connection, const std::string& name, const std::string& password)
{
    // the name argument to the function is a friendly name
    if (!password_authenticate_connection(client, connection, "", password)) {
        return false;
    }

    nlohmann::json root;
    root["Name"] = name;

    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, "POST", "/pairing/password"));
    std::vector<uint8_t> payload = nlohmann::json::to_cbor(root);
    nabto_client_coap_set_request_payload(coap.get(), CONTENT_FORMAT_APPLICATION_CBOR, payload.data(), payload.size());
    NabtoClientFuturePtr future(nabto_client_future_new(client));

    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Pairing failed " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }
    uint16_t status;
    nabto_client_coap_get_response_status_code(coap.get(), &status);
    if (status == 403) {
        std::cerr << "Password authentication not allowed" << std::endl;
        return false;
    } else if (status == 401) {
        std::cerr << "The connection is not password authenticated" << std::endl;
        return false;
    } else if (status == 400) {
        std::cerr << "Bad password pairing request" << std::endl;
        return false;
    } else if (status == 201) {
        return true;
    }

    std::cerr << "Could not do a password pairing with the device status " << status  << std::endl;;
    return false;
}

bool password_open_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& name)
{
    std::string password;
    std::cout << "enter the password which is used to pair with the device." << std::endl;
    std::cin >> password;
    return password_pair_password(client, connection, name, password);
}



bool interactive_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& friendlyName)
{
    // the private key is already set on the connection.

    nlohmann::json config;

    std::cout << "Scanning for local devices for 2 seconds." << std::endl;
    auto devices = Scanner::scan(client, std::chrono::milliseconds(2000));
    if (devices.size() == 0) {
        std::cout << "Did not find any local devices, is the device on the same local network as the client?" << std::endl;
        return false;
    }

    std::cout << "Found " << devices.size() << " local devices." << std::endl;
    std::cout << "Choose a device for pairing:" << std::endl;
    std::cout << "[q]: Quit without pairing" << std::endl;
    for (size_t i = 0; i < devices.size(); i++) {
        std::string productId;
        std::string deviceId;
        std::string fn;
        std::tie(productId,deviceId,fn) = devices[i];
        std::cout << "[" << i << "] ProductId: " << productId << " DeviceId: " << deviceId << " Name: " << fn << std::endl;
    }
    int deviceChoice = -1;
    {
        char input;
        std::cin >> input;
        if (input == 'q') {
            std::cout << "Quitting" << std::endl;
            return false;
        }

        deviceChoice = input - '0';
    }
    if (deviceChoice < 0 || deviceChoice >= (int)devices.size()) {
        std::cout << "Invalid choice" << std::endl;
        return false;
    }
    // create a connection to the found device.

    std::string productId;
    std::string deviceId;
    std::string fn;
    std::tie(productId, deviceId, fn) = devices[deviceChoice];

    json options;
    options["Remote"] = false;
    options["ProductId"] = productId;
    options["DeviceId"] = deviceId;

    NabtoClientError ec;
    ec = nabto_client_connection_set_options(connection, options.dump().c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    ec = connect(client, connection);
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    std::cout << "Connected to " << productId << "." << deviceId << std::endl;

    auto pr = get_pairing(client, connection);
    if (pr == nullptr) {
        return false;
    }

    std::cout << "The devices supports the following supported pairing modes" << std::endl;
    for (auto mode : pr->modes_) {
        std::cout << " " << pairingModeAsString(mode) << std::endl;
    }

    if (pr->modes_.count(PairingMode::LOCAL_INITIAL) != 0) {
        if (!local_initial_pair(client, connection)) {
            return false;
        }
    } else if (pr->modes_.count(PairingMode::LOCAL_OPEN) != 0) {
        if (!local_open_pair(client, connection, friendlyName)) {
            return false;
        }
    } else if (pr->modes_.count(PairingMode::PASSWORD_OPEN) != 0) {
        if (!password_open_pair(client, connection, friendlyName)) {
            return false;
        }
    } else {
        std::cout << "No supported pairing mode found" << std::endl;
        return false;
    }


    return true;
}

static std::vector<std::string> split(const std::string& s, char delimiter)
{
   std::vector<std::string> tokens;
   std::string token;
   std::istringstream tokenStream(s);
   while (std::getline(tokenStream, token, delimiter))
   {
      tokens.push_back(token);
   }
   return tokens;
}

static std::map<std::string, std::string> parseStringArgs(const std::string pairingString)
{
    // k1=v1,k2=v2
    std::map<std::string, std::string> args;
    auto pairs = split(pairingString, ',');

    for (auto p : pairs) {
        auto kv = split(p, '=');
        if (kv.size() >= 2) {
            args[kv[0]] = kv[1];
        }
    }

    return args;
}

bool string_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& friendlyName, const std::string& pairingString)
{
    std::map<std::string, std::string> args = parseStringArgs(pairingString);

    std::string productId = args["p"];
    std::string deviceId = args["d"];
    std::string pairingPassword = args["pwd"];
    std::string serverConnectToken = args["sct"];

    json options;
    options["ProductId"] = productId;
    options["DeviceId"] = deviceId;
    options["ServerConnectToken"] = serverConnectToken;

    NabtoClientError ec;
    ec = nabto_client_connection_set_options(connection, options.dump().c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    ec = connect(client, connection);
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    std::cout << "Connected to device ProductId: " <<  productId << " DeviceId: " << deviceId << std::endl;

    if (!password_pair_password(client, connection, friendlyName, pairingPassword)) {
        return false;
    }

    return true;
}

} } } // namespace
