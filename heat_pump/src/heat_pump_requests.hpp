#pragma once

#include "nabto_client_ptr.hpp"

namespace nabto {
namespace examples {
namespace heat_pump {

bool heat_pump_get(NabtoClient* client, NabtoClientConnection* connection);
bool heat_pump_set_name(NabtoClient* client, NabtoClientConnection* connection, const std::string& name);
bool heat_pump_set_target(NabtoClient* client, NabtoClientConnection* connection, double target);
bool heat_pump_set_power(NabtoClient* client, NabtoClientConnection* connection, std::string power);
bool heat_pump_set_mode(NabtoClient* client, NabtoClientConnection* connection, const std::string& mode);

} } } // namespace
