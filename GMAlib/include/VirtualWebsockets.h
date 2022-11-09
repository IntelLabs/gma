//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : VirtualWebsockets.h


#ifndef _VIRTUAL_WEBSOCKETS_H
#define _VIRTUAL_WEBSOCKETS_H

#include <string>
#include <thread>
#include <memory>
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
#include "ConnectionMessages.h"
#include "SystemStateSettings.h"
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;
using ptree = boost::property_tree::ptree;
namespace pt = boost::property_tree;

class VirtualWebsockets{

public:
    bool vnicInit = false;
    int linkFlag = 1;
    bool virtualWebsocketsLastMsg = false;

    bool connectServerRunning = false;
    bool lteLink = false;
    bool wifiLink = false;
    bool threadBusy = false;
    std::string uniqueSessionId;

    ConnectionMessages connectionMessages;

    std::string wsAddress;
    std::string wsPort;

    tcp::resolver *resolver_ = NULL;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> *v_ws=NULL;
    
    std::thread connectThread;
    std::thread wsRecvNCMMThread;

    ptree mxLTEReconfigReqMsg;
    ptree mxWifiReconfigReqMsg;

    SystemStateSettings *p_systemStateSettings = NULL;

    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void sendResumeReq();
    void virtualWebsocketConnect(ptree message);
    void RecvNCMM();
    void CloseWebsocket();
    void WsConnect();


    void InitMxLTEReconfigReqMsg();
    void InitMxWifiReconfigReqMsg();
    void SetClientLtePrefs(ptree message);

    void updateSettings(net::io_context &ioc, ssl::context &ctx);
    void Clear();
};

#endif