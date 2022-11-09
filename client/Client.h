//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Client.h

#ifndef _CLIENT_H
#define _CLIENT_H

#include <thread>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/algorithm/string.hpp>

#include <boost/asio/spawn.hpp>
#include <boost/beast/core.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/property_tree/ptree.hpp>

#include <boost/asio/ssl.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include "../GMAlib/include/ConnectServer.h"


extern SystemStateSettings *g_systemStateSettings;

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using ptree = boost::property_tree::ptree;
class ClientManager
{

public:
    net::io_context ioc;
    ssl::context ctx{ssl::context::tlsv12_client};
    ConnectServer *pConnect = NULL;

    char wifiInterface[100];
    char lteInterface[100];
    char serverAddress[20];
    bool isForeground = true;
    bool lteNetworkConnected = false;
    bool requestLteNetwork = false;
    bool wifiNetworkConnected = false;
    std::string lastWifiRouteGateway = "";
    std::string lastLteRouteGateway = "";

    bool connectRunning = false;
    std::thread connThread;
    std::mutex conn_mtx;
    std::condition_variable conn_cv;
    std::thread::native_handle_type conn_ID = 0;


private:
    static bool bindlte; //true: use lte for discovery, false: use wifi discovery
    int maxConnNum = 1;
    bool ThreadBusy = false;

public:
    ClientManager();
    void updateDevicesInterface(char wifi[], char lte[], char server[]);
    void Connect();
    void onAvailable(char *interfaceName);
    void onLost(char *interfaceName);
    bool checkRoutes();
    void checkExit(bool restart);
    void ConnectThread();
    void Quit();
    void getServerIp(char servername[]);
};

extern ClientManager clientManager;

#endif