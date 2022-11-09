//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ConnectServer.h

#ifndef _CONNECTSERVER_H
#define _CONNECTSERVER_H

#include "ConnectionMessages.h"
#include "SystemStateSettings.h"
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
#include <string>
#include <thread>

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using ptree = boost::property_tree::ptree;

struct SharedPrefs
{
    std::string NAME = "GMAconnection";
    std::string SERVER_ADDRESS = "server.address";
    std::string SERVER_PORT = "server.port";
    std::string K1 = "K1";
    std::string K2 = "K2";
    std::string L = "L";
    std::string VNIC_IP = "0.0.0.0";
    std::string VNIC_SESSION_ID = "0";
};

class ConnectServer
{
public:
    ConnectionMessages connectionMessages;
    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_new;

    std::thread wsRecvInitThread;
    std::thread wsRecvNCMMThread;

    ptree uniqueSessionId;
    ptree mxLTEReconfigReqMsg;
    ptree mxWifiReconfigReqMsg;
    int linkFlag = 1;
    bool websocketsThreadRunning = false;
    bool websocketsCompleted = false;
    bool wsThreadBusy = false;
    std::string wsAddressTmp;
    std::string wsPortTmp;

    SystemStateSettings *p_systemStateSettings = NULL;

    ConnectServer(net::io_context &ioc, ssl::context &ctx, SystemStateSettings *psystemStateSettings);
    void RecvNCMM();
    void RecvInit();
    void Execute();
    void WsConnect();
    void WsNewConnect();

    void InitMxLTEReconfigReqMsg();
    void InitMxWifiReconfigReqMsg();
    bool SetClientLtePrefs(ptree &config_tree);
    bool SetClientWifiPrefs(ptree &config_tree);
    bool SetClientPrefs(ptree &config_tree);
};

#endif