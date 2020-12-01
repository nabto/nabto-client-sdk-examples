#pragma once

#include <nabto/nabto_client.h>
#include <string>

std::string time_in_HH_MM_SS_MMM();

void handle_connect_error(NabtoClientConnection* connection, NabtoClientError ec);
