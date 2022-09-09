#pragma once

#include "nabto_client_ptr.hpp"

namespace nabto {
namespace examples {
namespace thermostat {

bool is_paired(NabtoClient* client, NabtoClientConnection* connection);
bool user_me(NabtoClient* client, NabtoClientConnection* connection);
bool users(NabtoClient* client, NabtoClientConnection* connection);
bool roles(NabtoClient* client, NabtoClientConnection* connection);
bool user_get(NabtoClient* client, NabtoClientConnection* connection, const std::string& user);
bool user_remove(NabtoClient* client, NabtoClientConnection* connection, const std::string& user);
bool user_set_role(NabtoClient* client, NabtoClientConnection* connection, const std::string& user, const std::string& role);


} } } // namespace
