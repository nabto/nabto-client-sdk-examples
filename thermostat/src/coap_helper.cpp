#include "coap_helper.hpp"


#include <vector>
#include <iostream>
#include <sstream>

namespace nabto {
namespace examples {
namespace thermostat {

bool isOkResponse(int code) {
    return (code >= 200 && code < 300);
}


std::vector<uint8_t> coap_get_response_data(NabtoClientCoap* coap)
{
    void* payload;
    size_t payloadLength;
    NabtoClientError ec = nabto_client_coap_get_response_payload(coap, &payload, &payloadLength);
    if (ec != NABTO_CLIENT_EC_OK) {
        return std::vector<uint8_t>();
    }
    return std::vector<uint8_t>(static_cast<uint8_t*>(payload), static_cast<uint8_t*>(payload)+payloadLength);
}

bool coap_get_cbor_response_data(NabtoClientCoap* coap, nlohmann::json& data)
{
    int contentFormat = coap_get_response_content_format(coap);
    if (contentFormat != CONTENT_FORMAT_APPLICATION_CBOR) {
        return false;
    }

    std::vector<uint8_t> payload = coap_get_response_data(coap);

    if (payload.empty()) {
        return false;
    }

    try {
        data = nlohmann::json::from_cbor(payload);
    } catch(std::exception& e) {
        return false;
    }

    return true;
}

int coap_get_response_status_code(NabtoClientCoap* coap)
{
    uint16_t statusCode;
    NabtoClientError ec = nabto_client_coap_get_response_status_code(coap, &statusCode);
    if (ec != NABTO_CLIENT_EC_OK) {
        return -1;
    }
    return statusCode;
}

int coap_get_response_content_format(NabtoClientCoap* coap)
{
    uint16_t contentFormat;
    NabtoClientError ec = nabto_client_coap_get_response_content_format(coap, &contentFormat);
    if (ec != NABTO_CLIENT_EC_OK) {
        return -1;
    }
    return contentFormat;
}

NabtoClientCoapPtr coap_get(NabtoClient* client, NabtoClientConnection* connection, const std::string& method, const std::string& path)
{
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    NabtoClientCoapPtr coap(nabto_client_coap_new(connection, method.c_str(), path.c_str()));
    nabto_client_coap_execute(coap.get(), future.get());
    NabtoClientError ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        return nullptr;
    }
    return coap;
}


void handle_coap_error(NabtoClientCoap* coap)
{
    std::stringstream data;
    int contentFormat = coap_get_response_content_format(coap);
    int statusCode = coap_get_response_status_code(coap);
    if (contentFormat == -1) {
        // no content format handle response as a string
        auto buffer = coap_get_response_data(coap);
        data << std::string(reinterpret_cast<char*>(buffer.data()), buffer.size());
    } else if (contentFormat == CONTENT_FORMAT_APPLICATION_CBOR) {
        std::vector<uint8_t> cbor = coap_get_response_data(coap);
        auto json = nlohmann::json::from_cbor(cbor);
        data << json;
    }

    std::cout << "Response Code: " << statusCode << " " << data.str() << std::endl;
}

} } } // namespace
