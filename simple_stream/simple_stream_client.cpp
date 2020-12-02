#include <nabto/nabto_client.h>

#include <3rdparty/cxxopts.hpp>
#include <3rdparty/nlohmann/json.hpp>

#include <string>
#include <iostream>
#include <memory>
#include <chrono>
#include <iomanip>
#include <fstream>

#include <thread>

#if defined(WIN32)
const std::string eofSequence = "Ctrl+z";
#else
const std::string eofSequence = "Ctrl+d";
#endif

static void reader(NabtoClient* context, NabtoClientStream* stream);

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

int main(int argc, char** argv)
{
    nlohmann::json opts;
    std::string logLevel;

    try
    {
        cxxopts::Options options(argv[0], "Nabto stream echo client example.");
        options.add_options()
            ("s,serverurl", "Optional. Server URL for the Nabto basestation", cxxopts::value<std::string>())
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>())
            ("p,productid", "Product ID to use", cxxopts::value<std::string>())
            ("k,serverkey", "Server key of the app", cxxopts::value<std::string>())
            ("log-level", "Optional. The log level (error|info|trace)", cxxopts::value<std::string>()->default_value("error"))
            ("force-remote", "Optional. Force the client to connect remote, not using local discovery")
            ("h,help", "Shows this help text");
        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
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
        logLevel = result["log-level"].as<std::string>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }

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
    NabtoClientStream* stream = nabto_client_stream_new(connection);
    nabto_client_stream_open(stream, fut, 42);
    if ((ec = nabto_client_future_wait(fut)) != NABTO_CLIENT_EC_OK) {
        std::cerr << "Failed to open stream: " << nabto_client_error_get_message(ec) << std::endl;
        exit(1);
    }

    std::cout << "Stream opened. Type data to send and press <enter> to send. Send the EOF character (" << eofSequence << ") to close stream." << std::endl;
    std::thread t(reader, context, stream);

    // TODO: sigInt signal handler

    for (;;) {
        std::string input;
        try {
            std::cin >> input;
            if(std::cin.eof()){
                std::cout << "Reached EOF, closing stream" << std::endl;
                nabto_client_stream_close(stream, fut);
                nabto_client_future_wait(fut);
                break;
            }
        } catch (...) {
            nabto_client_stream_close(stream, fut);
            nabto_client_future_wait(fut);
            break;
        }
        nabto_client_stream_write(stream, fut, input.data(), input.size());
        nabto_client_future_wait(fut);
    }

    t.join();
    std::cout << "Stream closed. Cleaning up." << std::endl;
    nabto_client_connection_close(connection, fut);
    nabto_client_future_wait(fut);
    nabto_client_future_free(fut);
    nabto_client_stop(context);

    nabto_client_stream_free(stream);
    nabto_client_connection_free(connection);
    nabto_client_free(context);
}

void reader(NabtoClient* context, NabtoClientStream* stream)
{
    char buffer[1024];
    NabtoClientFuture* fut = nabto_client_future_new(context);
    for (;;) {
        size_t read = 0;
        nabto_client_stream_read_some(stream, fut, buffer, 1024, &read);
        if (nabto_client_future_wait(fut) != NABTO_CLIENT_EC_OK) {
            nabto_client_future_free(fut);
            return;
        }
        std::cout << "Received stream data: " << std::string(buffer, read) << std::endl;
    }
}
