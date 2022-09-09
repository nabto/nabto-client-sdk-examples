#include "thermostat_requests.hpp"
#include "coap_helper.hpp"

#include <cstdio>
#include <iostream>
#include <sstream>

#include <3rdparty/nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace thermostat {

bool thermostat_get(NabtoClient* client, NabtoClientConnection* connection)
{
    auto coap = coap_get(client, connection, "GET", "/thermostat");
    if (!coap) {
        std::cerr << "Failed to get thermostat state" << std::endl;
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 403) {
        std::cout << "Access denied, ask an administrator for access" << std::endl;
        return false;
    }

    if (!isOkResponse(statusCode)) {
        std::cout << "Request failed, status code: " << statusCode << std::endl;
        return false;
    }

    nlohmann::json data;
    if (!coap_get_cbor_response_data(coap.get(), data)) {
        handle_coap_error(coap.get());
        return true;
    } else {
        std::cout << data.dump(4) << std::endl;
        return false;
    }
}


NabtoClientCoapPtr coap_post_cbor(NabtoClient* client, NabtoClientConnection* connection, const std::string& method, const std::string& path, nlohmann::json data)
{
    std::vector<uint8_t> payload = nlohmann::json::to_cbor(data);

    NabtoClientFuturePtr future(nabto_client_future_new(client));
    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, method.c_str(), path.c_str()));
    NabtoClientError ec = nabto_client_coap_set_request_payload(coap.get(), CONTENT_FORMAT_APPLICATION_CBOR, payload.data(), payload.size());
    if (ec != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }
    nabto_client_coap_execute(coap.get(), future.get());
    ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }
    return coap;
}

bool thermostat_set_target(NabtoClient* client, NabtoClientConnection* connection, double target)
{
    nlohmann::json root;
    root = target;

    std::cout << "target " << target << std::endl;

    auto coap = coap_post_cbor(client, connection, "POST", "/thermostat/target", root);
    int statusCode = coap_get_response_status_code(coap.get());
    if (isOkResponse(statusCode))
    {
        std::cout << "Target temperature set" << std::endl;
        return true;
    } else {
        handle_coap_error(coap.get());
        return false;
    }
}

bool thermostat_set_power(NabtoClient* client, NabtoClientConnection* connection, std::string power)
{
    nlohmann::json root;
    if (power == "ON") {
        root = true;
    } else if (power == "OFF") {
        root = false;
    } else {
        std::cerr << "Invalid power state " << power << ". Valid options is ON or OFF." << std::endl;
        return false;
    }
    auto coap = coap_post_cbor(client, connection, "POST", "/thermostat/power", root);
    int statusCode = coap_get_response_status_code(coap.get());
    if (isOkResponse(statusCode))
    {
        std::cout << "Power set" << std::endl;
        return true;
    } else {
        handle_coap_error(coap.get());
        return false;
    }
}

bool thermostat_set_mode(NabtoClient* client, NabtoClientConnection* connection, const std::string& mode)
{
    nlohmann::json root;
    root = mode;
    auto coap = coap_post_cbor(client, connection, "POST", "/thermostat/mode", root);
    int statusCode = coap_get_response_status_code(coap.get());
    if (isOkResponse(statusCode))
    {
        std::cout << "Mode set" << std::endl;
        return true;
    } else {
        handle_coap_error(coap.get());
        return false;
    }
}


} } } // namespace
