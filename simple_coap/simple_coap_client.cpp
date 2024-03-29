#include <nabto/nabto_client.h>

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>

void print_connect_error(NabtoClientError ec, NabtoClientConnection* connection);
void parse_options(int argc, char** argv, nlohmann::json* opts, std::string* request, std::string* logLevel, std::string* postData, uint16_t* contentFormat);

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
    std::string path;
    std::string logLevel;
    std::string postData;
    uint16_t contentFormat;

    parse_options(argc, argv, &opts, &path, &logLevel, &postData, &contentFormat);

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
    } else if (nabto_client_connection_get_device_fingerprint_hex(connection, &f) != NABTO_CLIENT_EC_OK) {
        std::cerr << "could not get remote peer fingerprint" << std::endl;
    } else {
        std::cout << "Connected to device with fingerprint: " << std::string(f) << std::endl;
        nabto_client_string_free(f);
    }

    NabtoClientCoap* request;
    if (postData.size() > 0) {
        request = nabto_client_coap_new(connection, "POST", path.c_str());
        nabto_client_coap_set_request_payload(request, contentFormat, postData.data(), postData.size());
    } else {
        request = nabto_client_coap_new(connection, "GET", path.c_str());
    }
    uint16_t statusCode;

    nabto_client_coap_execute(request, fut);
    if ((ec = nabto_client_future_wait(fut)) != NABTO_CLIENT_EC_OK) {
        std::cout << "CoAP execution error: " << nabto_client_error_get_message(ec) << std::endl;
    } else if ((ec = nabto_client_coap_get_response_status_code(request, &statusCode)) != NABTO_CLIENT_EC_OK) {
        std::cout << "Failed to get CoAP response status code: " << nabto_client_error_get_message(ec) << std::endl;
    } else if (postData.size() == 0 && statusCode != 205) {
        std::cout << "Unexpected CoAP response status code: " << statusCode << std::endl;
    } else if (postData.size() > 0 && statusCode != 204) {
        std::cout << "Unexpected CoAP response status code: " << statusCode << std::endl;
    } else if (postData.size() == 0) {
        void* payload = NULL;
        size_t payloadLength = 0;
        nabto_client_coap_get_response_payload(request, &payload, &payloadLength);
        std::string responseData((const char*)payload, payloadLength);
        std::cout << "Received CoAP get response data: " << responseData << std::endl;
    } else {
        std::cout << "Received CoAP post response OK" << std::endl;
    }
    nabto_client_coap_free(request);

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

void parse_options(int argc, char** argv, nlohmann::json* opts, std::string* request, std::string* logLevel, std::string* postData, uint16_t* contentFormat)
{
    try
    {
        cxxopts::Options options(argv[0], "Nabto Edge Simple CoAP client");
        options.add_options()
            ("s,serverurl", "Optional. Server URL for the Nabto basestation", cxxopts::value<std::string>())
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>())
            ("p,productid", "Product ID to use", cxxopts::value<std::string>())
            ("k,serverkey", "Optional. Server key of the app, required for remote connect if sct set to empty string", cxxopts::value<std::string>()->default_value(""))
            ("t,sct", "Optional. Server connect token from device used for remote connect", cxxopts::value<std::string>()->default_value("demosct"))
            ("r,request", "Optional. The coap request path to use. Ie. /hello-world", cxxopts::value<std::string>()->default_value("/hello-world"))
            ("P,post", "optional. String data to post to the device", cxxopts::value<std::string>()->default_value(""))
            ("c,content-format", "optional. Content format (IANA constants, e.g. 0 => UTF, 50 => JSON); 0 is default", cxxopts::value<uint16_t>()->default_value("0"))
            ("log-level", "Optional. The log level (error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
            ("force-remote", "Optional. Force the client to connect remote, not using local discovery")
            ("h,help", "Shows this help text");
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help({"", "Group"}) << std::endl;
            exit(0);
        }

        if(result.count("serverurl")) {
            (*opts)["ServerUrl"] = result["serverurl"].as<std::string>();
        }

        if(result.count("deviceid")) {
            (*opts)["DeviceId"] = result["deviceid"].as<std::string>();
        } else {
            die("no device ID provided", options);
        }

        if(result.count("productid")) {
            (*opts)["ProductId"] = result["productid"].as<std::string>();
        } else {
            die("no product ID provided", options);
        }
        if(result.count("serverkey")) {
            (*opts)["ServerKey"] = result["serverkey"].as<std::string>();
        }

        (*opts)["ServerConnectToken"] = result["sct"].as<std::string>();

        if(result.count("force-remote")) {
            (*opts)["Local"] = false;
        }

        *request = result["request"].as<std::string>();
        *logLevel = result["log-level"].as<std::string>();
        *postData = result["post"].as<std::string>();
        *contentFormat = result["content-format"].as<uint16_t>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}
