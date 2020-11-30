#pragma once

#include "nabto_client_ptr.hpp"

#include <nabto/nabto_client.h>

#include <vector>
#include <chrono>
#include <thread>
#include <memory>
#include <set>

#include <3rdparty/nlohmann/json.hpp>

namespace nabto {
namespace examples {
namespace common {


class Scanner {
 public:


    static std::vector<std::tuple<std::string,std::string,std::string> > getDevices(NabtoClient* client, NabtoClientListener* listener)
    {
        std::vector<std::tuple<std::string,std::string, std::string> > result;
        NabtoClientFuturePtr future(nabto_client_future_new(client));
        while(true) {
            NabtoClientMdnsResult* tmp;
            nabto_client_listener_new_mdns_result(listener, future.get(), &tmp);
            NabtoClientError ec = nabto_client_future_wait(future.get());
            if (ec != NABTO_CLIENT_EC_OK) {
                return result;
            }

            std::string productId(nabto_client_mdns_result_get_product_id(tmp));
            std::string deviceId(nabto_client_mdns_result_get_device_id(tmp));

            std::string txtItemsStr(nabto_client_mdns_result_get_txt_items(tmp));
            nlohmann::json txtItems = nlohmann::json::parse(txtItemsStr);

            std::string fn;
            try {
                fn = txtItems["fn"].get<std::string>();
            } catch (std::exception& e) {

            }


            result.push_back(make_tuple(productId, deviceId, fn));
            nabto_client_mdns_result_free(tmp);
        }
    }


    static std::vector<std::tuple<std::string,std::string, std::string> > scan(NabtoClient* client, std::chrono::milliseconds timeout) {
        NabtoClientListenerPtr listener(nabto_client_listener_new(client));
        std::vector<std::tuple<std::string,std::string, std::string> > devices;

        NabtoClientError ec = nabto_client_mdns_resolver_init_listener(client, listener.get(), "heatpump");
        if (ec != NABTO_CLIENT_EC_OK) {
            return devices;
        }

        std::thread t([&listener, timeout]() { std::this_thread::sleep_for(timeout); nabto_client_listener_stop(listener.get()); });

        devices = getDevices(client, listener.get());

        t.join();

        return devices;
    }
};

} } } // namespace
