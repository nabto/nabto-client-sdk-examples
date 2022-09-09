#include "util.hpp"
#include <chrono>

#include <iomanip>
#include <iostream>
#include <sstream>

std::string time_in_HH_MM_SS_MMM()
{
    using namespace std::chrono;

    // get current time
    auto now = system_clock::now();

    // get number of milliseconds for the current second
    // (remainder after division into seconds)
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    // convert to std::time_t in order to convert to std::tm (broken time)
    auto timer = system_clock::to_time_t(now);

    // convert to broken time
    std::tm bt = *std::localtime(&timer);

    std::ostringstream oss;

    oss << std::put_time(&bt, "%H:%M:%S"); // HH:MM:SS
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    return oss.str();
}

void handle_connect_error(NabtoClientConnection* connection, NabtoClientError ec)
{
    if (ec == NABTO_CLIENT_EC_NO_CHANNELS) {
        std::cerr << "A connection could not be created to the device. None of the possible channels was able to create a connection" << std::endl;
        auto localStatus = nabto_client_connection_get_local_channel_error_code(connection);
        auto remoteStatus = nabto_client_connection_get_remote_channel_error_code(connection);
        auto directCandidatesStatus = nabto_client_connection_get_direct_candidates_channel_error_code(connection);

        if (localStatus != NABTO_CLIENT_EC_NONE) {
            if (localStatus == NABTO_CLIENT_EC_NOT_FOUND) {
                std::cerr << "The device was not found on the local network" << std::endl;
            } else {
                std::cerr << "Could not connect locally to the device " << nabto_client_error_get_message(localStatus) << std::endl;
            }
        }

        if (remoteStatus != NABTO_CLIENT_EC_NONE) {
            if (remoteStatus == NABTO_CLIENT_EC_FORBIDDEN) {
                std::cerr << "The client is not allowed to make requests to the basestation with the product id and server key combination. Did you remember to add the appropriate application to the product in the console?" << std::endl;
            } else {
                std::cerr << "Could not connect to the device through the basestation " << nabto_client_error_get_message(remoteStatus) << std::endl;
            }
        }
        if (directCandidatesStatus != NABTO_CLIENT_EC_NONE) {
            std::cerr << "The direct candidates channel failed the the error " << nabto_client_error_get_message(directCandidatesStatus) << std::endl;
        }
    } else {
        std::cerr << "Failed to connect to device with error: " << nabto_client_error_get_message(ec) << std::endl;
    }

}
