#pragma once


#include <nabto/nabto_client.h>
#include <nabto/nabto_client_experimental.h>

#include <memory>
#include <ostream>

struct NabtoClientFree {
    void operator ()(NabtoClient* context) { nabto_client_free(context); }
};
typedef std::unique_ptr<NabtoClient, NabtoClientFree> NabtoClientPtr;

struct NabtoClientConnectionFree {
    void operator ()(NabtoClientConnection* connection) { nabto_client_connection_free(connection); }
};
typedef std::unique_ptr<NabtoClientConnection, NabtoClientConnectionFree> NabtoClientConnectionPtr;

struct NabtoClientStreamFree {
    void operator ()(NabtoClientStream* stream) { nabto_client_stream_free(stream); }
};
typedef std::unique_ptr<NabtoClientStream, NabtoClientStreamFree> NabtoClientStreamPtr;


struct NabtoClientFutureFree {
    void operator ()(NabtoClientFuture* future) { nabto_client_future_free(future); }
};
typedef std::unique_ptr<NabtoClientFuture, NabtoClientFutureFree> NabtoClientFuturePtr;

struct NabtoClientCoapFree {
    void operator ()(NabtoClientCoap* coap) { nabto_client_coap_free(coap); }
};
typedef std::unique_ptr<NabtoClientCoap, NabtoClientCoapFree> NabtoClientCoapPtr;

struct NabtoClientTcpTunnelFree {
    void operator ()(NabtoClientTcpTunnel* tcpTunnel) { nabto_client_tcp_tunnel_free(tcpTunnel); }
};
typedef std::unique_ptr<NabtoClientTcpTunnel, NabtoClientTcpTunnelFree> NabtoClientTcpTunnelPtr;


struct NabtoClientStringFree {
    void operator()(char* str) { nabto_client_string_free(str); }
};
typedef std::unique_ptr<char, NabtoClientStringFree> NabtoClientStringPtr;


struct NabtoClientListenerFree {
    void operator()(NabtoClientListener* listener) { nabto_client_listener_free(listener); }
};
typedef std::unique_ptr<NabtoClientListener, NabtoClientListenerFree> NabtoClientListenerPtr;


struct NabtoClientMdnsResultFree {
    void operator()(NabtoClientMdnsResult* result) { nabto_client_mdns_result_free(result); }
};
typedef std::unique_ptr<NabtoClientMdnsResult, NabtoClientMdnsResultFree> NabtoClientMdnsResultPtr;
