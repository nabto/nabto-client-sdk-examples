#include <nabto/nabto_client.h>
#include <nabto/nabto_client_experimental.h>

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>

void print_connect_error(NabtoClientError ec, NabtoClientConnection* connection);
void parse_options(int argc, char** argv, nlohmann::json& opts, std::string& logLevel, std::string& username, std::string& password);

void die(std::string msg, cxxopts::Options options) {
    std::cout << msg << std::endl;
    std::cout << options.help({"", "Group"}) << std::endl;
    exit(1);
}

static void log(const NabtoClientLogMessage* message, void* userData)
{
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);
    // convert to broken time
    std::tm bt = *std::localtime(&timer);

    std::cout << std::put_time(&bt, "%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms.count() << " " << " " << message->module << " " << message->message << std::endl;
}

int main(int argc, char** argv) {
    nlohmann::json opts;
    std::string logLevel;
    std::string username;
    std::string password;


    parse_options(argc, argv, opts, logLevel, username, password);

    std::cout << "Nabto Client SDK Version: " << nabto_client_version() << std::endl;
    std::cout << "connecting to " << opts["ProductId"].get<std::string>() << "." << opts["DeviceId"].get<std::string>() << std::endl;

    NabtoClient* context = nabto_client_new();

    nabto_client_set_log_callback(context, &log, NULL);
    nabto_client_set_log_level(context, logLevel.c_str());

    NabtoClientConnection* connection = nabto_client_connection_new(context);

    char* privateKey;
    nabto_client_create_private_key(context, &privateKey);

    opts["PrivateKey"] = std::string(privateKey);
    nabto_client_string_free(privateKey);

    nabto_client_connection_set_options(connection, opts.dump().c_str());

    NabtoClientFuture* fut = nabto_client_future_new(context);
    nabto_client_connection_connect(connection, fut);

    NabtoClientError ec = nabto_client_future_wait(fut);

    char* f;
    if (ec != NABTO_CLIENT_EC_OK) {
        print_connect_error(ec, connection);
    } else if (nabto_client_connection_get_device_fingerprint(connection, &f) != NABTO_CLIENT_EC_OK) {
        std::cerr << "could not get remote peer fingerprint" << std::endl;
    } else {
        std::cout << "Connected to device with fingerprint: " << std::string(f) << std::endl;
        nabto_client_string_free(f);

        nabto_client_connection_password_authenticate(connection, username.c_str(), password.c_str(), fut);
        ec = nabto_client_future_wait(fut);
        if (ec != NABTO_CLIENT_EC_OK) {
            std::cout << "Password authentication failed " << std::string(nabto_client_error_get_message(ec)) << std::endl;
        } else {
            std::cout << "Authenticated succesfully" << std::endl;
        }
    }

    nabto_client_connection_close(connection, fut);
    nabto_client_future_wait(fut);
    nabto_client_stop(context);

    nabto_client_future_free(fut);
    nabto_client_connection_free(connection);
    nabto_client_free(context);
}

void print_connect_error(NabtoClientError ec, NabtoClientConnection* connection)
{
    std::cerr << "could not connect to device "
              << nabto_client_error_get_message(ec)
              << std::endl << "Local error code "
              << nabto_client_error_get_message(nabto_client_connection_get_local_channel_error_code(connection))
              << std::endl << "Remote error code "
              << nabto_client_error_get_message(nabto_client_connection_get_remote_channel_error_code(connection))
              << std::endl;
    exit(1);
}

void parse_options(int argc, char** argv, nlohmann::json& opts, std::string& logLevel, std::string& username, std::string& password)
{
    try
    {
        cxxopts::Options options(argv[0], "Nabto Edge Simple CoAP client");
        options.add_options()
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>())
            ("p,productid", "Product ID to use", cxxopts::value<std::string>())
            ("username", "Username for the user", cxxopts::value<std::string>()->default_value(""))
            ("password", "Password for the user", cxxopts::value<std::string>()->default_value(""))
            ("log-level", "Optional. The log level (error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
            ("h,help", "Shows this help text");
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help({"", "Group"}) << std::endl;
            exit(0);
        }

        if(result.count("deviceid")) {
            (opts)["DeviceId"] = result["deviceid"].as<std::string>();
        } else {
            die("no device ID provided", options);
        }

        if(result.count("productid")) {
            (opts)["ProductId"] = result["productid"].as<std::string>();
        } else {
            die("no product ID provided", options);
        }

        username = result["username"].as<std::string>();
        password = result["password"].as<std::string>();

        logLevel = result["log-level"].as<std::string>();

    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}
