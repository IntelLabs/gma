//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : VirtualWebsockets.cpp

#include "../include/VirtualWebsockets.h"
#include "../include/SystemStateSettings.h"

#include <iostream>
#include <exception>
#include <thread>
#include <csignal>
#include <sstream>
#include <memory>
#include <regex>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using ptree = boost::property_tree::ptree;

void VirtualWebsockets::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}



void VirtualWebsockets::updateSettings(net::io_context &ioc, ssl::context &ctx)
{

    resolver_ = new tcp::resolver(ioc);
    v_ws = new websocket::stream<beast::ssl_stream<beast::tcp_stream>>(ioc, ctx);
    
    linkFlag = 1;
    
    virtualWebsocketsLastMsg = false;
    connectServerRunning = false;
    lteLink = false;
    wifiLink = false;

    uniqueSessionId = p_systemStateSettings->uniqueSessionId;
    wsAddress = p_systemStateSettings->serverVnicGw;
    wsPort = std::to_string(p_systemStateSettings->vnicWebsocketPort);

    InitMxLTEReconfigReqMsg();
    InitMxWifiReconfigReqMsg();
}

void VirtualWebsockets::sendResumeReq()
{
    ptree mx_Session_Resume_Req = connectionMessages.MX_Session_Resume_Req;
    std::istringstream sessionStream(uniqueSessionId);
    ptree unique_node;
    pt::read_json(sessionStream, unique_node);
    int ncm_id = unique_node.get<int>("ncm_id");
    int session_id = unique_node.get<int>("session_id");
    mx_Session_Resume_Req.get_child("unique_session_id").put("ncm_id", ncm_id);
    mx_Session_Resume_Req.get_child("unique_session_id").put("session_id", session_id); //update session id
    virtualWebsocketsLastMsg = false;
    std::thread connectThread(&VirtualWebsockets::virtualWebsocketConnect, this, mx_Session_Resume_Req);
    connectThread.join();
    connectServerRunning = false;
}

void VirtualWebsockets::WsConnect()
{
        try
        {
            auto const results = resolver_->resolve(wsAddress, wsPort);
            beast::get_lowest_layer(*v_ws).socket().open(boost::asio::ip::tcp::v4());
            beast::get_lowest_layer(*v_ws).connect(*results);
            v_ws->next_layer().handshake(ssl::stream_base::client);
            v_ws->handshake(wsAddress, "/");
        }
        catch (boost::system::system_error const& e)
        {

            std::stringstream ss;
            ss << "line 90" << e.what() << '\n';
            p_systemStateSettings->PrintLogs(ss);
        }
        threadBusy = false;

}


void VirtualWebsockets::virtualWebsocketConnect(ptree message)
{

    if (connectServerRunning)
        return;

    connectServerRunning = true;
    int k = 0;
    std::thread::native_handle_type wsConnID = 0;
    std::thread wsWsConnectThread;
    threadBusy = true;
    try {
        wsWsConnectThread = std::thread(&VirtualWebsockets::WsConnect, this);
        wsConnID = wsWsConnectThread.native_handle();
    }
    catch (const std::system_error& e) {
        connectServerRunning = false;
        return;
    }
    k = 0;
    while (k < 10 && threadBusy)
    {
        p_systemStateSettings->msleep(1000);
        k++;
    }
    if (threadBusy)
        p_systemStateSettings->terminateThread(wsConnID);

    threadBusy = false;
    wsWsConnectThread.join();

    std::stringstream ss;
    ss << "Prepare to build virtual websockets..#1..\n";
    p_systemStateSettings->PrintLogs(ss);
    wsConnID = 0;
    beast::error_code ec;
    if (v_ws->is_open())
    {
        try {
            wsRecvNCMMThread = std::thread(&VirtualWebsockets::RecvNCMM, this);
            wsConnID = wsRecvNCMMThread.native_handle();
        }
        catch (const std::system_error& e) {
            std::stringstream ss;
            ss << "line 200 " << e.what() << '\n';
            p_systemStateSettings->PrintLogs(ss);
        }
        if (wsConnID > 0)
        {
            virtualWebsocketsLastMsg = false;
            std::ostringstream virtual_out;
            pt::write_json(virtual_out, message);
            std::string jsonObject = virtual_out.str();
            std::regex reg("\\\"([0-9]+|true|false)\\\""); // remove quotes
            jsonObject = std::regex_replace(jsonObject, reg, "$1");
            k = 0;
            try {
                v_ws->write(net::buffer(jsonObject));
            }
            catch (boost::system::system_error const& e)
            {
                k = 10;
                std::stringstream ss;
                ss << "line 168" << e.what() << '\n';
                p_systemStateSettings->PrintLogs(ss);
            }
            while (k < 10 && !virtualWebsocketsLastMsg)
            {
                p_systemStateSettings->msleep(1000);
                k++;
            }
        }

        if (beast::get_lowest_layer(*v_ws).socket().is_open())
        {
            beast::get_lowest_layer(*v_ws).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            beast::get_lowest_layer(*v_ws).socket().close();
        }
        v_ws->close(websocket::close_code::abnormal, ec);

        if (wsConnID > 0)
            wsRecvNCMMThread.join();
    }
    else
    {
        std::stringstream ss;
        ss << "line 214 v_ws not connected" << '\n';
        p_systemStateSettings->PrintLogs(ss);
    }

    connectServerRunning = false;
    return;
  
}

void VirtualWebsockets::RecvNCMM()
{
    beast::error_code ec;
    std::string last_msg;
    std::ostringstream output;

    std::string jsonObject;
    beast::flat_buffer buffer;
    std::stringstream ss;

    while (true)
    {

        v_ws->read(buffer, ec);
       
        if (ec)
        {
            break;
        }
        else
        {
            last_msg = beast::buffers_to_string(buffer.data());
            buffer.consume(buffer.size());
            buffer.clear();
            std::istringstream in(last_msg);
            ptree pnode;
            pt::read_json(in, pnode);
            std::string msg_type = pnode.get<std::string>("message_type");
            if (msg_type.compare("mx_gma_wifi_list") == 0)
            {
                std::string wifiSsidList = pnode.get<std::string>("wifi_ssid_list");
                std::string listType = pnode.get<std::string>("list_type");
                std::stringstream ss;
                ss << "web socket message :" << wifiSsidList << listType << std::endl;
                p_systemStateSettings->PrintLogs(ss);
            }
            else if (msg_type.compare("mx_reconf_rsp") == 0)
            {
                std::stringstream ss;
                try
                {
                    if (mxLTEReconfigReqMsg.get<int>("sequence_num") == pnode.get<int>("sequence_num"))
                    {
                        mxLTEReconfigReqMsg = pnode;
                        ss << "[ncm->ccm] Recv mx_reconf_rsp(LTE)\n";
                        p_systemStateSettings->PrintLogs(ss);
                    }
                    else
                    {
                        if (linkFlag == 1)
                        {
                            mxWifiReconfigReqMsg = pnode;
                            ss << "[ncm->ccm] Recv mx_reconf_rsp(wifi, up)\n";
                            p_systemStateSettings->PrintLogs(ss);
                        }
                        else
                        {
                            p_systemStateSettings->gWifiFlag = false;
                            ss << "[ncm->ccm] Recv mx_reconf_rsp(wifi, down)\n";
                            p_systemStateSettings->PrintLogs(ss);
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    ss << e.what() << '\n';
                    p_systemStateSettings->PrintLogs(ss);
                }
            }
            else if (msg_type.compare("mx_up_setup_conf_req") == 0)
            {
                std::stringstream ss;
                if (vnicInit == false)
                {
                    SetClientLtePrefs(pnode);
                    ss << "virtual [ncm->ccm] Recv mx_up_setup_conf_req(VNIC)\n";
                    p_systemStateSettings->PrintLogs(ss);
                    ptree mx_setup_confirm = connectionMessages.MX_UP_Setup_Confirmation;
                    std::istringstream sessionStream(uniqueSessionId);
                    ptree unique_node;
                    pt::read_json(sessionStream, unique_node);
                    int ncm_id = unique_node.get<int>("ncm_id");
                    int session_id = unique_node.get<int>("session_id");
                    mx_setup_confirm.get_child("unique_session_id").put("ncm_id", ncm_id);
                    mx_setup_confirm.get_child("unique_session_id").put("session_id", session_id); //update session id

                    virtualWebsocketConnect(mx_setup_confirm);
                    lteLink = true;
                }
                else
                {
                    ss << "virtual [ncm->ccm] Recv mx_up_setup_conf_req(WIFI)\n";
                    p_systemStateSettings->PrintLogs(ss);
                    ptree mx_setup_confirm = connectionMessages.MX_UP_Setup_Confirmation;
                    std::istringstream sessionStream(uniqueSessionId);
                    ptree unique_node;
                    pt::read_json(sessionStream, unique_node);
                    int ncm_id = unique_node.get<int>("ncm_id");
                    int session_id = unique_node.get<int>("session_id");
                    mx_setup_confirm.get_child("unique_session_id").put("ncm_id", ncm_id);
                    mx_setup_confirm.get_child("unique_session_id").put("session_id", session_id); //update session id
                    virtualWebsocketConnect(mx_setup_confirm);

                    wifiLink = true;
                }
            }
            else if (msg_type.compare("mx_session_resume_rsp") == 0)
            {
                p_systemStateSettings->gStartTime = 0x7FFFFFFF - p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF;
                std::stringstream ss;
                ss << "virtual [ncm->ccm] mx_session_resume_rsp" << ":" << p_systemStateSettings->gStartTime << "\n";
                p_systemStateSettings->PrintLogs(ss);
                p_systemStateSettings->currentTimeMs = 0;
                p_systemStateSettings->reorderStopTime = 0;
            }
            else if (msg_type.compare("mx_qos_flow_conf") == 0)
            {
                std::stringstream ss;
                ss << "virtual [ncm->ccm] mx_qos_flow_conf\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            else if (msg_type.compare("mx_gma_client_conf") == 0)
            {
                p_systemStateSettings->gISVirtualWebsocket = true;
                std::stringstream ss;
                ss << "virtual [ncm->ccm] mx_gma_client_conf\n";
                p_systemStateSettings->PrintLogs(ss);
                virtualWebsocketsLastMsg = true;
                break;
            }
            else if (msg_type.compare("mx_session_suspend_rsp") == 0)
            {
                std::stringstream ss;
                ss << "[ncm->ccm] mx_session_suspend_rsp\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            else if (msg_type.compare("mx_session_termination_rsp") == 0)
            {
                std::stringstream ss;
                ss << "[ncm->ccm] mx_session_termination_rsp\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            else
            {
                std::stringstream ss;
                ss << "virtual websockets invalid message\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            
        }
    }

    ss << "close virtual websocket!\n";
    p_systemStateSettings->PrintLogs(ss);
}

void VirtualWebsockets::InitMxLTEReconfigReqMsg()
{
    ptree message = connectionMessages.MX_Reconfiguration_Request;
    int i = 0;
    BOOST_FOREACH (pt::ptree::value_type &v, message)
    {
        if (i == 0)
        {
            mxLTEReconfigReqMsg = v.second;
            return;
        }
    }
}

void VirtualWebsockets::InitMxWifiReconfigReqMsg()
{
    ptree message = connectionMessages.MX_Reconfiguration_Request;
    int i = 0;
    BOOST_FOREACH (pt::ptree::value_type &v, message)
    {
        if (i == 1)
        {
            mxWifiReconfigReqMsg = v.second;
            return;
        }
        i++;
    }
}

void VirtualWebsockets::SetClientLtePrefs(ptree message)
{
    BOOST_FOREACH (ptree::value_type &v, message.get_child("anchor_connections"))
    {
        ptree vnic_info = v.second.get_child("vnic_info");
        ptree delivery_connection = v.second.get_child("delivery_connections");
        ptree lte_delivery;
        for (ptree::iterator it = delivery_connection.begin(); it != delivery_connection.end(); ++it)
        {
            if ((it->second).get<int>("connection_id") == 3)
            {
                lte_delivery = it->second;
                break;
            }
        }
        ptree lte_tunnel_info = lte_delivery.get_child("adaptation_method_params");

        p_systemStateSettings->serverUdpPort = v.second.get<int>("udp_port");
        p_systemStateSettings->serverTcpPort = v.second.get<int>("tcp_port");
        p_systemStateSettings->serverVnicIp = vnic_info.get<std::string>("ip");
        std::vector<std::string> splitIp;
        boost::split(splitIp, p_systemStateSettings->serverVnicIp, boost::is_any_of("."), boost::token_compress_on);
        p_systemStateSettings->clientId = ((std::stoi(splitIp[2]) << 8) + std::stoi(splitIp[3]));
        //IP address 10.8.x.y, client id = x * 256 + y

        p_systemStateSettings->serverVnicGw = vnic_info.get<std::string>("gateway");
        p_systemStateSettings->serverVnicMsk = vnic_info.get<std::string>("mask");
        p_systemStateSettings->serverVnicDns = vnic_info.get<std::string>("dns");
        p_systemStateSettings->vnicWebsocketPort = vnic_info.get<int>("vnic_port");
        p_systemStateSettings->serverLteTunnelIp = lte_tunnel_info.get<std::string>("tunnel_ip_addr");
        p_systemStateSettings->serverLteTunnelPort = lte_tunnel_info.get<int>("tunnel_end_port");
        p_systemStateSettings->serverLteHeaderOpt = lte_tunnel_info.get<bool>("mx_header_optimization");

        ptree probe_param = connectionMessages.MX_UP_Setup_Confirmation.get_child("probe_param");
        p_systemStateSettings->clientProbePort = probe_param.get<int>("probe_port");
        ptree client_params = connectionMessages.MX_UP_Setup_Confirmation.get_child("client_params");
        ptree client_info;
        for (ptree::iterator client_it = client_params.begin(); client_it != client_params.end(); client_it++)
        {
            if ((client_it->second).get<int>("connection_id") == 3)
            {
                client_info = client_it->second;
                break;
            }
        }
        p_systemStateSettings->clientLteAdaptPort = client_info.get_child("adapt_param").get<int>("udp_adapt_port");
    }
}

void VirtualWebsockets::CloseWebsocket()
{
    beast::error_code ec;
    try
    {
        v_ws->close(websocket::close_code::normal, ec);
    }
    catch (boost::system::system_error const &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        p_systemStateSettings->PrintLogs(ss);
        return;
    }
    wsRecvNCMMThread.join();
}

void VirtualWebsockets::Clear()
{
    try
    {
        delete v_ws;
        delete resolver_;
    }
    catch (const std::exception &e)
    {
        std::stringstream ss;
        ss << "line 517" << e.what() << std::endl;
        p_systemStateSettings->PrintLogs(ss);
        return;
    }
    v_ws = NULL;
    resolver_ = NULL; 
    connectServerRunning = false;
}

