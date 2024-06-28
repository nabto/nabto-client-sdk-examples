#include "pairing.hpp"
#include "util.hpp"
#include "scanner.hpp"

#include <3rdparty/nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <regex>

namespace nabto {
namespace examples {
namespace thermostat {

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

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

    if (p.contains("Username")) {
        auto tmp = p["Username"];
        if (tmp.is_string()) {
            tmp.get_to(user->username_);
        }
    }

    if (p.contains("DisplayName")) {
        auto tmp = p["DisplayName"];
        if (tmp.is_string()) {
            tmp.get_to(user->displayName_);
        }
    }
    if (p.contains("Fingerprints")) {
        for (auto f : p["Fingerprints"]) {
            Fingerprint fp;
            if (f.contains("Fingerprint")) {
                auto tmp = f["Fingerprint"];
                if (tmp.is_string()) {
                    tmp.get_to(fp.fingerprint_);
                }
            } else {
                continue;
            }

            if (f.contains("Name")) {
                auto tmp = f["Name"];
                if (tmp.is_string()) {
                    tmp.get_to(fp.name_);
                }
            }
            user->fingerprints_.push_back(fp);
        }
    } else {
        if (p.contains("Fingerprint")) {
            auto tmp = p["Fingerprint"];
            if (tmp.is_string()) {
                Fingerprint fp;
                tmp.get_to(fp.fingerprint_);
                user->fingerprints_.push_back(fp);
            }
        }
    }
    if (p.contains("Sct")) {
        auto tmp = p["Sct"];
        if (tmp.is_string()) {
            tmp.get_to(user->sct_);
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
        void* payload;
        size_t payloadLength;
        if (nabto_client_coap_get_response_payload(coap.get(), &payload, &payloadLength) != NABTO_CLIENT_EC_OK) {
            std::cerr << "Could not pair with the device. Response status: " << status << std::endl;
        } else {
            std::string reason((char*)payload, payloadLength);
            std::cerr << "Could not pair with the device. Response: (" << status << ") " << reason << std::endl;
        }
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
        void* payload;
        size_t payloadLength;
        if (nabto_client_coap_get_response_payload(coap.get(), &payload, &payloadLength) != NABTO_CLIENT_EC_OK) {
            std::cerr << "Could not pair with the device. Response status: " << status << std::endl;
        } else {
            std::string reason((char*)payload, payloadLength);
            std::cerr << "Could not pair with the device. Response: (" << status << ") " << reason << std::endl;
        }
        return false;
    }
    return true;
}

bool password_open_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& name, const std::string& password)
{
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    nabto_client_connection_password_authenticate(connection, "", password.c_str(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Pairing authenticate " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }

    nlohmann::json root;
    root["Username"] = name;

    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, "POST", "/iam/pairing/password-open"));
    std::vector<uint8_t> payload = nlohmann::json::to_cbor(root);
    nabto_client_coap_set_request_payload(coap.get(), CONTENT_FORMAT_APPLICATION_CBOR, payload.data(), payload.size());

    nabto_client_coap_execute(coap.get(), future.get());
    ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Pairing failed " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    }
    uint16_t status;
    nabto_client_coap_get_response_status_code(coap.get(), &status);
    if (status != 201) {
        void* payload;
        size_t payloadLength;
        if (nabto_client_coap_get_response_payload(coap.get(), &payload, &payloadLength) != NABTO_CLIENT_EC_OK) {
            std::cerr << "Could not pair with the device. Response status: " << status << std::endl;
        } else {
            std::string reason((char*)payload, payloadLength);
            std::cerr << "Could not pair with the device. Response: (" << status << ") " << reason << std::endl;
        }
        return false;
    }
    return true;
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

    nlohmann::json options;
    options["Remote"] = false;
    options["ProductId"] = productId;
    options["DeviceId"] = deviceId;

    if (nabto_client_connection_set_options(connection, options.dump().c_str()) != NABTO_CLIENT_EC_OK) {
        return false;
    }

    NabtoClientError ec;
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    nabto_client_connection_connect(connection, future.get());
    if ((ec = nabto_client_future_wait(future.get())) != NABTO_CLIENT_EC_OK) {
        handle_connect_error(connection, ec);
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
        std::cout << "The initial user is not paired. Pairing using local initial pairing" << std::endl;
        if (!local_initial_pair(client, connection)) {
            return false;
        }
    } else if (pr->modes_.count(PairingMode::LOCAL_OPEN) != 0) {
        std::cout << "Pairing using local open pairing" << std::endl;
        if (!local_open_pair(client, connection, friendlyName)) {
            return false;
        }
    } else {
        std::cout << "No supported pairing mode found" << std::endl;
        return false;
    }

    return true;
}

class PairingString {
 public:
    std::string productId;
    std::string deviceId;
    std::string pwd;
    std::string sct;

    bool pairingStringToKv(const std::string& pairingString, std::map<std::string, std::string>& kv)
    {
        std::string reString = R"(([\w\-]+)=([\w\-]+),?)";
        std::regex re(reString);

        std::smatch kvItems;
        auto begin = pairingString.begin();
        auto end = pairingString.end();
        while (std::regex_search(begin, end, kvItems, re)) {
            begin = kvItems[0].second;
            std::ssub_match keyMatch = kvItems[1];
            std::ssub_match valueMatch = kvItems[2];
            std::string key = keyMatch.str();
                std::string value = valueMatch.str();
                kv[key] = value;
        }
        return true;
    }

    bool parse(const std::string& pairingString) {
        std::map<std::string, std::string> kvPairs;
        if (!pairingStringToKv(pairingString, kvPairs)) {
            return false;
        }
        if (kvPairs.count("p") != 0) {
            productId = kvPairs["p"];
        }
        if (kvPairs.count("d") != 0) {
            deviceId = kvPairs["d"];
        }
        if (kvPairs.count("sct") != 0) {
            sct = kvPairs["sct"];
        }
        if (kvPairs.count("pwd") != 0) {
            pwd = kvPairs["pwd"];
        }
        return true;
    }
};

bool pairing_string_pair(NabtoClient* client, NabtoClientConnection* connection, const std::string& pairingString, const std::string& friendlyName)
{
    PairingString ps;
    if (!ps.parse(pairingString)) {
        std::cout << "could not parse pairing string" << std::endl;
        return false;
    }
    if (ps.productId.empty()) {
        std::cout << "Missing required product id in the pairing string" << std::endl;
        return false;
    }
    if (ps.deviceId.empty()) {
        std::cout << "Missing required device id in the pairing string" << std::endl;
        return false;
    }

    nlohmann::json options;
    options["ProductId"] = ps.productId;
    options["DeviceId"] = ps.deviceId;
    if (ps.sct.empty()) {
        options["Remote"] = false;
    } else {
        options["ServerConnectToken"] = ps.sct;
    }

    if (nabto_client_connection_set_options(connection, options.dump().c_str()) != NABTO_CLIENT_EC_OK) {
        return false;
    }

    NabtoClientError ec;
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    nabto_client_connection_connect(connection, future.get());
    if ((ec = nabto_client_future_wait(future.get())) != NABTO_CLIENT_EC_OK) {
        handle_connect_error(connection, ec);
        return false;
    }

    std::cout << "Connected to " << ps.productId << "." << ps.deviceId << std::endl;

    auto pr = get_pairing(client, connection);
    if (pr == nullptr) {
        return false;
    }

    std::cout << "The devices supports the following supported pairing modes" << std::endl;
    for (auto mode : pr->modes_) {
        std::cout << " " << pairingModeAsString(mode) << std::endl;
    }

    if (pr->modes_.count(PairingMode::LOCAL_INITIAL) != 0) {
        std::cout << "The initial user is not paired. Pairing using local initial pairing" << std::endl;
        if (!local_initial_pair(client, connection)) {
            return false;
        }
    } else if (pr->modes_.count(PairingMode::LOCAL_OPEN) != 0) {
        std::cout << "Pairing using local open pairing" << std::endl;
        if (!local_open_pair(client, connection, friendlyName)) {
            return false;
        }
    } else if (pr->modes_.count(PairingMode::PASSWORD_OPEN) != 0 && !ps.pwd.empty()) {
        std::cout << "Pairing using password open pairing" << std::endl;
        if (!password_open_pair(client, connection, friendlyName, ps.pwd)) {
            return false;
        }
    } else {
        std::cout << "No supported pairing mode found" << std::endl;
        return false;
    }

    return true;

}

} } } // namespace
