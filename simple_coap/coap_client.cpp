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

NabtoClientError coap_execute(NabtoClient* context, NabtoClientCoap* coap)
{
    NabtoClientFuture* future = nabto_client_future_new(context);
    nabto_client_coap_execute(coap, future);
    NabtoClientError ec = nabto_client_future_wait(future);
    return ec;
}


void coap_get(NabtoClient* context, NabtoClientConnection* connection, std::string req) {
    NabtoClientCoap* request = nabto_client_coap_new(connection, "GET", req.c_str());

    std::cout << "Sending CoAP GET request: " << req << std::endl;
    NabtoClientError ec = coap_execute(context, request);
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cout << "CoAP execution error: " << nabto_client_error_get_message(ec) << std::endl;
        return;
    }
    uint16_t statusCode;
    nabto_client_coap_get_response_status_code(request, &statusCode);
    if (statusCode != 205) {
        std::cout << "CoAP error: " << statusCode << std::endl;
        return;
    }
    void* payload = NULL;
    size_t payloadLength = 0;
    nabto_client_coap_get_response_payload(request, &payload, &payloadLength);
    std::string responseData((const char*)payload, payloadLength);
    std::cout << "Received CoAP response data: " << responseData << std::endl;

    nabto_client_coap_free(request);
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
    std::string request;
    std::string logLevel;


    try
    {
        cxxopts::Options options(argv[0], "Nabto Edge Simple CoAP client");
        options.add_options()
            ("u,serverurl", "Optional Server URL for the Nabto basestation", cxxopts::value<std::string>())
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>())
            ("p,productid", "Product ID to use", cxxopts::value<std::string>())
            ("s,serverkey", "Server key of the app", cxxopts::value<std::string>())
            ("r,request", "The coap request path to use. Ie. /hello-world", cxxopts::value<std::string>()->default_value("/hello-world"))
            ("log-level", "The log level (error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
            ("force-remote", "Force the client to connect remote, not using local discovery")
            ("h,help", "Shows this help text");
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help({"", "Group"}) << std::endl;
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

        request = result["request"].as<std::string>();
        logLevel = result["log-level"].as<std::string>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }

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

    NabtoClientFuture* connect = nabto_client_future_new(context);
    nabto_client_connection_connect(connection, connect);

    NabtoClientError ec = nabto_client_future_wait(connect);

    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "could not connect to device " << nabto_client_error_get_message(ec) << std::endl;
        std::cerr << "Local error code " << nabto_client_error_get_message(nabto_client_connection_get_local_channel_error_code(connection)) << std::endl;
        std::cerr << "Remote error code " << nabto_client_error_get_message(nabto_client_connection_get_remote_channel_error_code(connection)) << std::endl;
        exit(1);
    } else {
        char* f;

        ec = nabto_client_connection_get_device_fingerprint_hex(connection, &f);
        if (ec != NABTO_CLIENT_EC_OK) {
            std::cerr << "could not get remote peer fingerprint" << std::endl;
        } else {
            std::cout << "Connected to device with fingerprint: " << std::string(f) << std::endl;
        }
        nabto_client_string_free(f);
    }

    coap_get(context, connection, request);

    close_connection(context, connection);

    nabto_client_connection_free(connection);

}
