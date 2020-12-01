#include <nabto/nabto_client.h>

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>

void die(std::string msg, cxxopts::Options options) {
    std::cout << msg << std::endl;
    std::cout << options.help({"", "Group"}) << std::endl;
    exit(1);
}

void close_connection(NabtoClient* context, NabtoClientConnection* connection) {
    NabtoClientFuture* closeFuture = nabto_client_future_new(context);
    nabto_client_connection_close(connection, closeFuture);
    nabto_client_future_wait(closeFuture);

    NabtoClientError ec = nabto_client_future_error_code(closeFuture);
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "could not close connection " << nabto_client_error_get_message(ec) << std::endl;
    }
    std::cout << "freed connection" << std::endl;
    nabto_client_future_free(closeFuture);
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

    std::string productId;
    std::string deviceId;
    std::string logLevel;

    std::string service;
    uint16_t localPort;
    
    try
    {
        cxxopts::Options options(argv[0], "Nabto Edge Simple CoAP client");
        options.add_options()
            ("s,serverurl", "Optional. Server URL for the Nabto basestation", cxxopts::value<std::string>())
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>())
            ("p,productid", "Product ID to use", cxxopts::value<std::string>())
            ("k,serverkey", "Server key of the app", cxxopts::value<std::string>())
            ("service", "The id of the tcp tunnel service which is defined in the device.", cxxopts::value<std::string>(service))
            ("local-port", "Optional. The local port for the tunnel", cxxopts::value<uint16_t>(localPort)->default_value("0"))
            ("log-level", "Optional. The log level (error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
            ("force-remote", "Optional. Force the client to connect remote, not using local discovery")
            ("h,help", "Shows this help text");
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if(result.count("serverurl")) {
            opts["ServerUrl"] = result["serverurl"].as<std::string>();
        }

        if(result.count("deviceid")) {
            opts["DeviceId"] = result["deviceid"].as<std::string>();
        } else {
            die("no device ID provided", options);
        }

        if(result.count("productid")) {
            opts["ProductId"] = result["productid"].as<std::string>();
        } else {
            die("no product ID provided", options);
        }

        if(result.count("serverkey")) {
            opts["ServerKey"] = result["serverkey"].as<std::string>();
        } else {
            std::cout << "No Server Key provided, remote connections will not be possible" << std::endl;
        }
        if(result.count("force-remote")) {
            opts["Local"] = false;
        }

        if (result.count("service")) {
            service = result["service"].as<std::string>();
        } else {
            die("Specify a service", options);
        }

        logLevel = result["log-level"].as<std::string>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }

    std::cout << "connecting to " << opts["ProductId"].get<std::string>() << "." << opts["DeviceId"].get<std::string>() << std::endl;

    NabtoClient* context = NULL;
    NabtoClientFuture* future = NULL;
    NabtoClientConnection* connection = NULL;
    NabtoClientTcpTunnel* tunnel = NULL;
    NabtoClientError ec;

    context = nabto_client_new();
    future = nabto_client_future_new(context);

    nabto_client_set_log_callback(context, &log, NULL);
    nabto_client_set_log_level(context, logLevel.c_str());

    connection = nabto_client_connection_new(context);

    char* privateKey;
    nabto_client_create_private_key(context, &privateKey);

    opts["PrivateKey"] = std::string(privateKey);
    nabto_client_string_free(privateKey);

    nabto_client_connection_set_options(connection, opts.dump().c_str());

    nabto_client_connection_connect(connection, future);

    ec = nabto_client_future_wait(future);

    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "could not connect to device " << nabto_client_error_get_message(ec) << std::endl;
        std::cerr << "Local error code " << nabto_client_error_get_message(nabto_client_connection_get_local_channel_error_code(connection)) << std::endl;
        std::cerr << "Remote error code " << nabto_client_error_get_message(nabto_client_connection_get_remote_channel_error_code(connection)) << std::endl;
        goto cleanup;
    }

    tunnel = nabto_client_tcp_tunnel_new(connection);
    nabto_client_tcp_tunnel_open(tunnel, future, service.c_str(), localPort);

    ec = nabto_client_future_wait(future);
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Could not open the tunnel. " << nabto_client_error_get_message(ec) << std::endl;
        goto cleanup;
    }

    ec = nabto_client_tcp_tunnel_get_local_port(tunnel, &localPort);
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Could not get the local port. " << nabto_client_error_get_message(ec) << std::endl;
        goto cleanup;
    }

    std::cout << "Opened a connection to the device and opened a tunnel to the service: " << service << std::endl;
    std::cout << "The service is exposed at TCP 127.0.0.1:" << localPort << std::endl;

    
    std::cout << "Press enter to quit...";
    std::cin.get();

    nabto_client_tcp_tunnel_stop(tunnel);

    close_connection(context, connection);

 cleanup:
    if (tunnel != NULL) {
        nabto_client_tcp_tunnel_free(tunnel);
    }
    if (connection != NULL) {
        nabto_client_connection_free(connection);
    }
    if (future != NULL) {
        nabto_client_future_free(future);
    }
    if (context != NULL) {
        nabto_client_stop(context);
        nabto_client_free(context);
    }

}
