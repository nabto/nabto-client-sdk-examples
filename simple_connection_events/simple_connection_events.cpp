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
void parse_options(int argc, char** argv, nlohmann::json* opts, std::string* logLevel);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// connection event specifics

static NabtoClientFuture* eventFuture_;
static NabtoClientListener* listener_;
static NabtoClientConnectionEvent connectionEvent_;

void arm_connection_event_listener(NabtoClientConnection* connection);

const char* connection_event_to_string(NabtoClientConnectionEvent event) {
    if (event == NABTO_CLIENT_CONNECTION_EVENT_CLOSED) {
        return "Connection closed";
    } else if (event == NABTO_CLIENT_CONNECTION_EVENT_CONNECTED) {
        return "Connection opened";
    } else if (event == NABTO_CLIENT_CONNECTION_EVENT_CHANNEL_CHANGED) {
        return "Channel changed";
    } else {
        return "Unknown event";
    }
}

const char* connection_type_to_string(NabtoClientConnection* connection) {
    NabtoClientConnectionType type;
    nabto_client_connection_get_type(connection, &type);
    return type == NABTO_CLIENT_CONNECTION_TYPE_RELAY ? "Relay" : "Direct";
}

void print_connection_type(NabtoClientConnection* connection) {
    std::cout << "Connection type is now: " << connection_type_to_string(connection) << std::endl;
}

void print_all_connection_info(NabtoClientConnection *connection)
{
    print_connection_type(connection);
    char *f;
    if (nabto_client_connection_get_device_fingerprint_hex(connection, &f) == NABTO_CLIENT_EC_OK)
    {
        std::cout << "Connected to device with fingerprint: " << std::string(f) << std::endl;
        nabto_client_string_free(f);
    }
    else
    {
        std::cerr << "Could not get remote peer fingerprint" << std::endl;
    }
}

void connection_event_cb(NabtoClientFuture* future, NabtoClientError ec, void* data) {
    NabtoClientConnection* connection = (NabtoClientConnection*)data;
    if (ec != NABTO_CLIENT_EC_OK) {
        std::cerr << "Connection event callback error: " << nabto_client_error_get_message(ec) << std::endl;
    } else {
        std::cout << "Connection event: " << connection_event_to_string(connectionEvent_) << std::endl;
        if (connectionEvent_ == NABTO_CLIENT_CONNECTION_EVENT_CONNECTED) {
            print_all_connection_info(connection);
        } else if (connectionEvent_ == NABTO_CLIENT_CONNECTION_EVENT_CHANNEL_CHANGED) {
            print_connection_type(connection);
        }
    }
    arm_connection_event_listener(connection);
}


void init_connection_event_listener(NabtoClient* context, NabtoClientConnection* connection) {
    listener_ = nabto_client_listener_new(context);
    eventFuture_ = nabto_client_future_new(context);
    connectionEvent_ = -1;
    nabto_client_connection_events_init_listener(connection, listener_);
}

void arm_connection_event_listener(NabtoClientConnection* connection) {
    // initialize future for the event listener, the future is resolved when a new connection event is
    // ready or the listener has been stopped (also see https://docs.nabto.com/developer/platforms/embedded/nabto_futures.html#listeners)
    nabto_client_listener_connection_event(listener_, eventFuture_, &connectionEvent_);
    nabto_client_future_set_callback(eventFuture_, connection_event_cb, connection);
}

// connection event specifics
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void connected_cb(NabtoClientFuture* future, NabtoClientError ec, void* data) {
    NabtoClientConnection* connection = (NabtoClientConnection*)data;
    if (ec != NABTO_CLIENT_EC_OK) {
        print_connect_error(ec, connection);
    }
}

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

    parse_options(argc, argv, &opts, &logLevel);

    std::cout << "Nabto Client SDK Version: " << nabto_client_version() << std::endl;
    std::cout << "opts: " << opts.dump() << std::endl;
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

    init_connection_event_listener(context, connection);
    arm_connection_event_listener(connection);

    NabtoClientFuture* connectFuture = nabto_client_future_new(context);
    nabto_client_connection_connect(connection, connectFuture);
    nabto_client_future_set_callback(connectFuture, connected_cb, connection);

    // read a character from stdin
    std::cout << "Press enter to disconnect..." << std::endl;
    getchar();

    NabtoClientFuture* closeFuture = nabto_client_future_new(context);
    nabto_client_connection_close(connection, closeFuture);
    nabto_client_future_wait(closeFuture);
    nabto_client_stop(context);

    nabto_client_future_free(connectFuture);
    nabto_client_future_free(closeFuture);
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

void parse_options(int argc, char** argv, nlohmann::json* opts, std::string* logLevel)
{
    try
    {
        cxxopts::Options options(argv[0], "Nabto Edge Simple CoAP client");
        options.add_options()
            ("s,serverurl", "Optional. Server URL for the Nabto basestation", cxxopts::value<std::string>())
            ("d,deviceid", "Device ID to connect to", cxxopts::value<std::string>()->default_value("de-avmqjaje"))
            ("p,productid", "Product ID to use", cxxopts::value<std::string>()->default_value("pr-fatqcwj9"))
            ("t,sct", "Optional. Server connect token from device used for remote connect", cxxopts::value<std::string>()->default_value("demosct"))
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

        if(!result.count("deviceid")) {
            std::cout << "no device ID provided, using default: " << result["deviceid"].as<std::string>() << std::endl;
        }
        (*opts)["DeviceId"] = result["deviceid"].as<std::string>();

        if(!result.count("productid")) {
            std::cout << "no product ID provided, using default: " << result["productid"].as<std::string>() << std::endl;
        }
        (*opts)["ProductId"] = result["productid"].as<std::string>();

        (*opts)["ServerConnectToken"] = result["sct"].as<std::string>();

        if(result.count("force-remote")) {
            (*opts)["Local"] = false;
        }

        *logLevel = result["log-level"].as<std::string>();
    }
    catch (const cxxopts::OptionException& e)
    {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}
