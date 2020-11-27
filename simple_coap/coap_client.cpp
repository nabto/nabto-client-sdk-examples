#include <nabto/nabto_client.h>

#include <3rdparty/cxxopts.hpp>

#include <string>
#include <iostream>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>
//#include <thread>

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
    std::cout << "Sending CoAP GET request" << std::endl;
    NabtoClientCoap* request = nabto_client_coap_new(connection, "GET", req.c_str());

    std::cout << "Sending coap get-request:" << req << std::endl;
    NabtoClientError ec = coap_execute(context, request);
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cout << "coap execution error: " << nabto_client_error_get_message(ec) << std::endl;
        return;
    }
    uint16_t statusCode;
    nabto_client_coap_get_response_status_code(request, &statusCode);
    if (statusCode != 205) {
        std::cout << "coap error: " << statusCode << std::endl;
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
    std::string serverUrl;
    std::string deviceId;
    std::string productId;
    std::string serverKey;
    std::string request;
    std::string logLevel;
    bool forceRemote = false;


    try
    {
        cxxopts::Options options(argv[0], "Nabto 5 test client");
        options.add_options()
            ("H,serverurl", "Optional Server URL for the Nabto basestation", cxxopts::value<std::string>())
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
            serverUrl = result["serverurl"].as<std::string>();
        }

        if(result.count("deviceid")) {
           deviceId = result["deviceid"].as<std::string>();
        } else {
            die("no device ID provided", options);
        }

        if(result.count("productid")) {
            productId = result["productid"].as<std::string>();
        } else {
            die("no product ID provided", options);
        }

        if(result.count("serverkey")) {
            serverKey = result["serverkey"].as<std::string>();
        } else {
            die("no server key provided", options);
        }
        if(result.count("force-remote")) {
            forceRemote=true;
        }

        request = result["request"].as<std::string>();
        logLevel = result["log-level"].as<std::string>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }

    std::cout << "connecting to " << productId << "." << deviceId << std::endl;

    NabtoClient* context = nabto_client_new();

    nabto_client_set_log_callback(context, &log, NULL);
    nabto_client_set_log_level(context, logLevel.c_str());

    NabtoClientConnection* connection = nabto_client_connection_new(context);
    std::cout << "Created a new connection" << std::endl;


    NabtoClientError ec;
    if (!serverUrl.empty()) {
        ec = nabto_client_connection_set_server_url(connection, serverUrl.c_str());
    }
    ec = nabto_client_connection_set_server_api_key(connection, serverKey.c_str());

    ec = nabto_client_connection_set_product_id(connection, productId.c_str());
    ec = nabto_client_connection_set_device_id(connection, deviceId.c_str());

    char* privateKey;
    nabto_client_create_private_key(context, &privateKey);

    ec = nabto_client_connection_set_private_key(connection, privateKey);
    nabto_client_string_free(privateKey);

    if(forceRemote) {
        nabto_client_connection_set_options(connection, "{\"Local\": false}");
    }



    NabtoClientFuture* connect = nabto_client_future_new(context);
    nabto_client_connection_connect(connection, connect);

    ec = nabto_client_future_wait(connect);

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
