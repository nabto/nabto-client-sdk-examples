#pragma once

#include "nabto_client_ptr.hpp"

namespace nabto {
namespace examples {
namespace thermostat {

bool thermostat_get(NabtoClient* client, NabtoClientConnection* connection);
bool thermostat_set_target(NabtoClient* client, NabtoClientConnection* connection, double target);
bool thermostat_set_power(NabtoClient* client, NabtoClientConnection* connection, std::string power);
bool thermostat_set_mode(NabtoClient* client, NabtoClientConnection* connection, const std::string& mode);

} } } // namespace
