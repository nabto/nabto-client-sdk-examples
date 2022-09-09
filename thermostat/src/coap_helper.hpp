#pragma once

#include "nabto_client_ptr.hpp"

#include <vector>
#include <3rdparty/nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace thermostat {

const static int CONTENT_FORMAT_APPLICATION_CBOR = 60; // rfc 7059

bool isOkResponse(int code);
std::vector<uint8_t> coap_get_response_data(NabtoClientCoap* coap);
bool coap_get_cbor_response_data(NabtoClientCoap* coap, nlohmann::json& data);
int coap_get_response_status_code(NabtoClientCoap* coap);
int coap_get_response_content_format(NabtoClientCoap* coap);

void handle_coap_error(NabtoClientCoap* coap);

NabtoClientCoapPtr coap_get(NabtoClient* client, NabtoClientConnection* connection, const std::string& method, const std::string& path);

NabtoClientCoapPtr coap_post_cbor(NabtoClient* client, NabtoClientConnection* connection, const std::string& method, const std::string& path, nlohmann::json data);



} } } // namespace
