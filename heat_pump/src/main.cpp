#include "heat_pump_requests.hpp"
#include "iam_requests.hpp"

#include "pairing.hpp"
#include "util.hpp"
#include "persistence.hpp"
#include "nabto_client_ptr.hpp"

#include <nabto/nabto_client.h>

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>

#if defined(_WIN32)
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace nabto {
namespace examples {
namespace heat_pump {

static std::string clientConfigFileName = "heat_pump_client_config.json";
static std::string clientStateFileName = "heat_pump_client_state.json";
static std::string defaultClientServerKey = "sk-d8254c6f790001003d0c842d1b63b134";

#if defined(_WIN32)
static std::string homeDirEnvVariable = "APPDATA";
static std::string nabtoFolder = "nabto";
#else
static std::string homeDirEnvVariable = "HOME";
static std::string nabtoFolder = ".nabto";
#endif

bool makeDirectory(const std::string& directory)
{
#if defined(_WIN32)
    _mkdir(directory.c_str());
#else
    mkdir(directory.c_str(), 0777);
#endif
    return true;
}

bool makeDirectories(const std::string& in)
{
    std::string homeDir;
    if (in.empty()) {
        char* tmp = getenv(homeDirEnvVariable.c_str());
        if (tmp == NULL) {
            return false;
        }
        std::string homeEnv = std::string(tmp);
        makeDirectory(homeEnv + "/" + nabtoFolder);
        makeDirectory(homeEnv + "/" + nabtoFolder + "/edge");
        homeDir = homeEnv + "/" + nabtoFolder + "/edge";
    } else {
        homeDir = in;
        makeDirectory(homeDir);
    }

    makeDirectory(homeDir+"/config");
    makeDirectory(homeDir+"/state");
    makeDirectory(homeDir+"/keys");
    return true;
}

void close(NabtoClient* client, NabtoClientConnection* connection)
{
    NabtoClientFuturePtr future(nabto_client_future_new(client));
    nabto_client_connection_close(connection, future.get());
    nabto_client_future_wait(future.get());
}

// given a configuration file, create a connection to the device.
bool connect(NabtoClient* context, NabtoClientConnection* connection, const std::string& homedir)
{
    // Load the client state, the state which tells what device the
    // client is paired with.
    std::unique_ptr<nabto::examples::heat_pump::ClientState> clientState = nabto::examples::heat_pump::ClientState::loadClientState(homedir, clientStateFileName);

    if (clientState == nullptr) {
        std::cerr << "The client is not paired with a device, do the pairing first" << std::endl;
        return false;
    }

    // load the client configuration, e.g. the client server key and
    // the client server url for remote connections.

    NabtoClientError ec;
    ec = nabto_client_connection_set_product_id(connection, clientState->getProductId().c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    ec = nabto_client_connection_set_device_id(connection, clientState->getDeviceId().c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    ec = nabto_client_connection_set_server_connect_token(connection, clientState->getServerConnectToken().c_str());
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }

    NabtoClientFuturePtr future = NabtoClientFuturePtr(nabto_client_future_new(context));

    nabto_client_connection_connect(connection, future.get());

    ec = nabto_client_future_wait(future.get());
    if (ec != NABTO_CLIENT_EC_OK) {
        handle_connect_error(connection, ec);
        return false;
    }

    char* tmp;
    ec = nabto_client_connection_get_device_fingerprint(connection, &tmp);
    std::string deviceFingerprint(tmp);
    nabto_client_string_free(tmp);

    if (deviceFingerprint != clientState->getDeviceFingerprint()) {
        std::cerr << "device fingerprint does not match the paired fingerprint." << std::endl;
        return false;
    }

    return true;
}

bool write_client_state(NabtoClient* client, NabtoClientConnection* connection, const std::string& homedir)
{
    std::unique_ptr<PairingResponse> pr = get_pairing(client, connection);
    if (!pr) {
        std::cerr << "CoAP GET /pairing failed" << std::endl;
    }

    std::unique_ptr<User> user = get_me(client, connection);
    if (!user) {
        std::cerr << "CoAP GET /iam/me failed" << std::endl;
    }

    char* fp;
    NabtoClientError ec = nabto_client_connection_get_device_fingerprint(connection, &fp);
    if (ec != NABTO_CLIENT_EC_OK) {
        return false;
    }
    std::string fingerprint(fp);
    nabto_client_string_free(fp);

    ClientState clientState(pr->getProductId(), pr->getDeviceId(), fingerprint, user->getServerConnectToken());
    return clientState.writeClientState(homedir, clientStateFileName);

}

void log_callback(const NabtoClientLogMessage* message, void* data) {
    std::cout << time_in_HH_MM_SS_MMM() << "[" << std::string(message->severityString) << "] " << std::string(message->message) << std::endl;
}

bool create_private_key(const std::string& keyFile, NabtoClient* context, NabtoClientConnection* connection)
{
    bool res; char* s; NabtoClientError ec;
    if ((ec = nabto_client_create_private_key(context, &s)) != NABTO_CLIENT_EC_OK) {
        std::cerr << "Failed to create new private key: " << nabto_client_error_get_message(ec) << std::endl;
        return false;
    } else if (!(res = File::writeFile(keyFile, std::string(s)))) {
        std::cerr << "Failed to write to key file " << keyFile << " ensure it is accessable" << std::endl;
    }
    nabto_client_string_free(s);
    return res;
}

} } } // namespace


int run_heat_pump(NabtoClient* context, cxxopts::ParseResult& options) {
        std::string homedir;
        if (options.count("home-dir")) {
            homedir = options["home-dir"].as<std::string>();
        } else {
            char* tmp = getenv(nabto::examples::heat_pump::homeDirEnvVariable.c_str());
            if (tmp == NULL) {
                homedir = ".";
            } else {
                homedir = std::string(tmp) + "/" + nabto::examples::heat_pump::nabtoFolder + "/edge";
            }
        }

        NabtoClientConnectionPtr connection(nabto_client_connection_new(context));

        // load the private key for the client/connection
        {
            std::stringstream ss;
            ss << homedir << "/keys/client.key";
            std::string keyFile = ss.str();
            if (!nabto::examples::heat_pump::File::exists(keyFile) &&
                !nabto::examples::heat_pump::create_private_key(keyFile, context, connection.get()))
            {
                std::cerr << "Private key file creation failed" << std::endl;
                return 1;
            }

            std::string keyContent;
            // load private key and load key into connection
            if (!nabto::examples::heat_pump::File::readFile(keyFile, keyContent) ||
                nabto_client_connection_set_private_key(connection.get(), keyContent.c_str()) != NABTO_CLIENT_EC_OK)
            {
                std::cerr << "Failed to load private key from file: " << keyFile << std::endl;
                return 1;
            }
        }


        if (!nabto::examples::heat_pump::ClientConfig::loadClientConfig(homedir, nabto::examples::heat_pump::clientConfigFileName, nabto::examples::heat_pump::defaultClientServerKey, connection.get())) {
            return 1;
        }

        std::string userName = "default";
        const char* user = getenv("USER");
        if (user != NULL) {
            userName = std::string(user);
        }
        if (options.count("pair")) {
            if (!nabto::examples::heat_pump::interactive_pair(context, connection.get(), userName)) {
                std::cerr << "Could not pair with the device" << std::endl;
                return 1;
            }
            if (!nabto::examples::heat_pump::write_client_state(context, connection.get(), homedir)) {
                std::cerr << "Could not write client state" << std::endl;
                return 1;
            }
            std::cout << "Paired with the device" << std::endl;
            return 0;
        }

        if (!nabto::examples::heat_pump::connect(context, connection.get(), homedir)) {
            return 1;
        }

        bool status = true;

        if (!nabto::examples::heat_pump::is_paired(context, connection.get())) {
            status = false;
        } else if (options.count("get")) {
            status = nabto::examples::heat_pump::heat_pump_get(context, connection.get());
        } else if (options.count("set-name")) {
            status = nabto::examples::heat_pump::heat_pump_set_name(context, connection.get(), options["set-name"].as<std::string>());
        } else if (options.count("set-target")) {
            status = nabto::examples::heat_pump::heat_pump_set_target(context, connection.get(), options["set-target"].as<double>());
        } else if (options.count("set-mode")) {
            status = nabto::examples::heat_pump::heat_pump_set_mode(context, connection.get(), options["set-mode"].as<std::string>());
        } else if (options.count("set-power")) {
            status = nabto::examples::heat_pump::heat_pump_set_power(context, connection.get(), options["set-power"].as<std::string>());
        } else if (options.count("user-me")) {
            status = nabto::examples::heat_pump::user_me(context, connection.get());
        } else if (options.count("users")) {
            status = nabto::examples::heat_pump::users(context, connection.get());
        } else if (options.count("user-get")) {
            if (!options.count("user")) {
                std::cerr << "Missing --user argument" << std::endl;
                status = false;
            } else {
                status = nabto::examples::heat_pump::user_get(context, connection.get(), options["user-get"].as<std::string>());
            }
        } else if (options.count("user-remove")) {
            if (!options.count("user")) {
                std::cerr << "Missing --user argument" << std::endl;
                status = false;
            } else {
                status = nabto::examples::heat_pump::user_remove(context, connection.get(), options["user-remove"].as<std::string>());
            }
        } else if (options.count("user-set-role")) {
            if (!options.count("user")) {
                std::cerr << "Missing --user argument" << std::endl;
                status = false;
            } else if (!options.count("role")) {
                std::cerr << "Missing --role argument" << std::endl;
                status = false;
            } else {
                status = nabto::examples::heat_pump::user_set_role(context, connection.get(), options["user"].as<std::string>(), options["role"].as<std::string>());
            }
        } else {
            std::cerr << "No such command" << std::endl;
            status = false;
        }

        nabto::examples::heat_pump::close(context, connection.get());

        if (status) {
            return 0;
        } else {
            return 1;
        }
}


int main(int argc, char** argv)
{
    cxxopts::Options options("Heat pump", "Nabto heat pump client example.");

    options.add_options("0 - General")
        ("h,help", "Show help")
        ("version", "Show version")
        ("H,home-dir", "Set alternative home dir. The default home dir is $HOME/.nabto/edge on Linux, OSX and %APPDATA%\\nabto\\edge on Windows. The following files are used by the example config/heat_pump_client.json and state/heat_pump_client_state.json", cxxopts::value<std::string>())
        ("log-level", "Set the log level", cxxopts::value<std::string>())
        ;

    options.add_options("1 - Pairing")
        ("pair", "Pair with a heat pump interactively")
        ;

    options.add_options("2 - IAM")
        ("users", "List all the users in the heat pump")
        ("roles", "List all the roles in the heat pump")
        ("user", "Specify a user for a command", cxxopts::value<std::string>())
        ("role", "Specify a role for a command", cxxopts::value<std::string>())
        ("user-me", "Get your own user from the system")
        ("user-get", "Get a user from the system")
        ("user-remove", "Remove a user from the system")
        ("user-set-role", "Set a role for a user.")
        ;

    options.add_options("3 - Heatpump")
        ("get", "Get heatpump state")
        ("set-name", "Set friendly name of the heatpump", cxxopts::value<std::string>())
        ("set-target", "Set target temperature", cxxopts::value<double>())
        ("set-power", "Turn ON or OFF", cxxopts::value<std::string>())
        ("set-mode", "Set heatpump mode, valid modes: COOL, HEAT, FAN, DRY", cxxopts::value<std::string>())
        ;

    try {
        cxxopts::ParseResult result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            return 0;
        }

        if (result.count("version"))
        {
            std::cout << "nabto_client_sdk: " << nabto_client_version() << std::endl;
            return 0;
        }

        if (result.count("home-dir")) {
            nabto::examples::heat_pump::makeDirectories(result["home-dir"].as<std::string>());
        } else {
            nabto::examples::heat_pump::makeDirectories("");
        }

        NabtoClientPtr context(nabto_client_new());

        if (result.count("log-level"))
        {
            nabto_client_set_log_callback(context.get(), &nabto::examples::heat_pump::log_callback, NULL);
            nabto_client_set_log_level(context.get(), result["log-level"].as<std::string>().c_str());
        }

        int r = run_heat_pump(context.get(), result);
        nabto_client_stop(context.get());
        return r;
    } catch (cxxopts::OptionParseException& e) {
        std::cerr << "The options could not be parsed. " << e.what() << std::endl;
        std::cerr << options.help() << std::endl;
        return 1;
    }

}
