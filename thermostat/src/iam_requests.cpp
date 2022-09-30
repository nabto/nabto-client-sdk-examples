#include "iam_requests.hpp"

#include "coap_helper.hpp"

#include <iostream>

namespace nabto {
namespace examples {
namespace thermostat {

bool is_paired(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/me");
    if (coap == nullptr) {
        return false;
    }
    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 205) {
        return true;
    } else if (statusCode == 404) {
        std::cerr << "You are not paired with the device, pair with the device before doing other requests to it." << std::endl;
    } else {
        std::cerr << "Could not get the user from the device the status code is " << statusCode << std::endl;
    }
    return false;
}

bool user_me(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/me");
    if (coap == nullptr) {
        return false;
    }
    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 205) {
        // ok
    } else if (statusCode == 404) {
        std::cerr << "You are not paired with the device, pair with the device before doing other requests to it." << std::endl;
        return false;
    } else {
        std::cerr << "Could not get the user from the device the status code is " << statusCode << std::endl;
        return false;
    }

    nlohmann::json user;
    if (!coap_get_cbor_response_data(coap.get(), user)) {
        return false;
    }
    std::cout << user.dump(4) << std::endl;
    return true;
}

// list all users on the system
bool users(NabtoClient* client, NabtoClientConnection* connection)
{
    // CoAP GET /iam/users

    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/users");

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 403) {
        std::cerr << "You are not allowed to get the user list" << std::endl;
        return false;
    } else if (statusCode == 205) {
        // ok
    } else {
        std::cerr << "Could not get the user list, status code " << statusCode << std::endl;
        return false;
    }

    nlohmann::json userList;
    if (!coap_get_cbor_response_data(coap.get(), userList)) {
        return false;
    }

    if (!userList.is_array()) {
        return false;
    }

    std::cout << "Users: " << userList << std::endl;

    return true;
}

// list all roles on the system
bool roles(NabtoClient* client, NabtoClientConnection* connection)
{
    // CoAP GET /iam/roles

    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/roles");

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 403) {
        std::cerr << "You are not allowed to get the roles list" << std::endl;
        return false;
    } else if (statusCode == 205) {
        // ok
    } else {
        std::cerr << "Could not get the roles list, status code " << statusCode << std::endl;
        return false;
    }

    nlohmann::json rolesList;
    if (!coap_get_cbor_response_data(coap.get(), rolesList)) {
        return false;
    }

    if (!rolesList.is_array()) {
        return false;
    }

    std::cout << "Roles: " << rolesList << std::endl;

    return true;
}

// show a specific user from the system
bool user_get(NabtoClient* client, NabtoClientConnection* connection, const std::string& user)
{
    // CoAP GET /iam/users/:user
    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/users/"+user);

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 404) {
        std::cerr << "The user " << user << " does not exists on the system." << std::endl;
        return false;
    } else if (statusCode == 403) {
        std::cerr << "You are not allowed to get the user " << user << std::endl;
        return false;
    } else if (statusCode == 205) {
        // ok
    } else {
        std::cerr << "Could not get the user, status code " << statusCode << std::endl;
        return false;
    }

    nlohmann::json userInfo;
    if (!coap_get_cbor_response_data(coap.get(), userInfo)) {
        return false;
    }
    std::cout << userInfo.dump(4) << std::endl;

    return true;
}

// remove a user from the system
bool user_remove(NabtoClient* client, NabtoClientConnection* connection, const std::string& user)
{
    // CoAP DELETE /iam/users/:user
    NabtoClientCoapPtr coap = coap_get(client, connection, "DELETE", "/iam/users/"+user);

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 404) {
        std::cerr << "The user " << user << " does not exists on the system" << std::endl;
        return false;
    } else if (statusCode == 403) {
        std::cerr << "You are not allowed to remove the user " << user << std::endl;
        return false;
    }

    return true;
}

// add admin capabilities to a user
bool user_set_role(NabtoClient* client, NabtoClientConnection* connection, const std::string& user, const std::string& role)
{
    // CoAP PUT /iam/users/:user/roles/Admin

    nlohmann::json root;
    root = role;

    NabtoClientCoapPtr coap = coap_post_cbor(client, connection, "PUT", "/iam/users/"+user+"/role", root);

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 404) {
        std::cerr << "The user or role does not exists on the system" << std::endl;
        return false;
    } else if (statusCode == 403) {
        std::cerr << "You are not allowed to add the role to the user" << std::endl;
        return false;
    }
    return true;
}

bool set_friendly_name(NabtoClient* client, NabtoClientConnection* connection, const std::string& fn)
{
    // CoAP PUT /iam/device-info/friendly-name

    nlohmann::json root;
    root = fn;

    NabtoClientCoapPtr coap = coap_post_cbor(client, connection, "PUT", "/iam/device-info/friendly-name", root);

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 403) {
        std::cerr << "You are not allowed to set friendly name" << std::endl;
        return false;
    } else if (statusCode == 404) {
        std::cerr << "Friendly name does not exist in device. You may need to update your device to a new version of the Embedded SDK.";
        return false;
    }
    std::cout << "Friendly name set successfully" << std::endl;
    return true;
}


bool device_info(NabtoClient* client, NabtoClientConnection* connection)
{
    // CoAP GET /iam/pairing
    NabtoClientCoapPtr coap = coap_get(client, connection, "GET", "/iam/pairing");

    if (coap == nullptr) {
        return false;
    }

    int statusCode = coap_get_response_status_code(coap.get());
    if (statusCode == 403) {
        std::cerr << "You are not allowed to get device info " << std::endl;
        return false;
    } else if (statusCode == 205) {
        // ok
    } else {
        std::cerr << "Could not get device info, status code " << statusCode << std::endl;
        return false;
    }

    nlohmann::json deviceInfo;
    if (!coap_get_cbor_response_data(coap.get(), deviceInfo)) {
        return false;
    }
    std::cout << deviceInfo.dump(4) << std::endl;

    return true;
}

} } } // namespace
