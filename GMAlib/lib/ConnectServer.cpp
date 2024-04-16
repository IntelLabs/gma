//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ConnectServer.cpp

#include "../include/ConnectServer.h"
#include <iostream>
#include <string>
#include <sstream>
#include <regex>
#include "../include/Common.h"

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using ptree = boost::property_tree::ptree;
namespace pt = boost::property_tree;
struct SharedPrefs sharedPrefs;

ConnectServer::ConnectServer(net::io_context &ioc, ssl::context &ctx, SystemStateSettings *psystemStateSettings)
    : resolver_(ioc), ws(ioc, ctx), ws_new(ioc, ctx), p_systemStateSettings(psystemStateSettings)
{
    InitMxLTEReconfigReqMsg();
    InitMxWifiReconfigReqMsg();
}

void ConnectServer::Execute()
{
    int k = 0;
    std::thread::native_handle_type wsConnID = 0;
    websocketsCompleted = true;
    std::thread wsWsConnectThread;
    wsThreadBusy = true;
    try {
        wsWsConnectThread = std::thread(std::bind(&ConnectServer::WsConnect, this));
        wsConnID = wsWsConnectThread.native_handle();

       k = 0;
        while (k < 10 && wsThreadBusy)
        {
            p_systemStateSettings->msleep(1000);
            k++;
        }
        if (wsThreadBusy)
           {
                p_systemStateSettings->terminateThread(wsConnID);
            }
        wsWsConnectThread.join();
    }
    catch (const std::system_error& e) {
        std::cout << "Caught system_error with code " << e.code()
            << " meaning " << e.what() << '\n';
        return;
    }

    wsConnID = 0;
    try
    {
        if (ws.is_open())
        {
            websocketsCompleted = false;
            try {
                wsRecvInitThread = std::thread(std::bind(&ConnectServer::RecvInit, this));
                wsConnID = wsRecvInitThread.native_handle();
            }
            catch (const std::system_error& e) {
                std::cout << "Caught system_error with code " << e.code()
                    << " meaning " << e.what() << '\n';
                beast::error_code ec;
                ws.close(websocket::close_code::abnormal, ec);
                return;
            }
        }
        else
        {
            if(beast::get_lowest_layer(ws).socket().is_open())
            {
                beast::error_code ec;
                beast::get_lowest_layer(ws).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                beast::get_lowest_layer(ws).socket().close();
            }
            return;
        }
    }
    catch (boost::system::system_error const &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        ss << "\n ****** websocket stage #3c\n";
        p_systemStateSettings->PrintLogs(ss);
        if(beast::get_lowest_layer(ws).socket().is_open())
        {
            beast::error_code ec;
            beast::get_lowest_layer(ws).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            beast::get_lowest_layer(ws).socket().close();
        }
        return;
    }

    ptree mx_discover;
    mx_discover.put("version", "1.0");
    mx_discover.put("message_type", "mx_discover");
    mx_discover.put("sequence_num", 1);

    std::ostringstream out;
    pt::write_json(out, mx_discover);
    std::string jsonObject = out.str();

    try
    {
        if (ws.write(net::buffer(jsonObject)) <= 0)
         printf("\n ws_write error\n");
     }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        p_systemStateSettings->PrintLogs(ss);
    }
    
    k = 0;
    while (k < 10 && !websocketsCompleted)
    {
        p_systemStateSettings->msleep(1000);
        k++;
    }
   
    if (beast::get_lowest_layer(ws).socket().is_open())
    {
        beast::error_code ec;
        beast::get_lowest_layer(ws).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        beast::get_lowest_layer(ws).socket().close();
    }

    try
    {
        if (ws.is_open())
        {
            beast::error_code ec;
            ws.close(websocket::close_code::abnormal, ec);
        }
    }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        p_systemStateSettings->PrintLogs(ss);
    }

      wsRecvInitThread.join();
  return;
}

bool ConnectServer::SetClientLtePrefs(ptree &config_tree)
{
    BOOST_FOREACH (ptree::value_type &v, config_tree.get_child("anchor_connections"))
    {
        ptree vnic_info = v.second.get_child("vnic_info");
        ptree delivery_connection = v.second.get_child("delivery_connections");
        ptree lte_delivery;
        bool flag = true;
        for (ptree::iterator it = delivery_connection.begin(); it != delivery_connection.end(); ++it)
        {
            if ((it->second).get<int>("connection_id") == 3)
            {
                lte_delivery = it->second;
                flag = false;
                break;
            }
        }
        if (flag)
            return false;

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

        bool lte_tunnel_ip_enabled = lte_tunnel_info.get<bool>("mx_header_optimization");
        
        if (lte_tunnel_ip_enabled)
           p_systemStateSettings->serverLteTunnelIp = lte_tunnel_info.get<std::string>("tunnel_ip_addr");
        else
           p_systemStateSettings->serverLteTunnelIp = p_systemStateSettings->serverlteIpv4Address;

        p_systemStateSettings->serverLteTunnelPort = lte_tunnel_info.get<int>("tunnel_end_port");
        
        ptree probe_param = connectionMessages.MX_UP_Setup_Confirmation.get_child("probe_param");
        p_systemStateSettings->clientProbePort = probe_param.get<int>("probe_port");
        ptree client_params = connectionMessages.MX_UP_Setup_Confirmation.get_child("client_params");
        ptree client_info;
        flag = true;
        for (ptree::iterator client_it = client_params.begin(); client_it != client_params.end(); client_it++)
        {
            if ((client_it->second).get<int>("connection_id") == 3)
            {
                client_info = client_it->second;
                flag = false;
                break;
            }
        }
        if (flag)
            return false;

        p_systemStateSettings->clientLteAdaptPort = client_info.get_child("adapt_param").get<int>("udp_adapt_port");
        std::istringstream sessionStream(p_systemStateSettings->uniqueSessionId);
        ptree unique_node;
        pt::read_json(sessionStream, unique_node);
        sharedPrefs.VNIC_IP = vnic_info.get<std::string>("ip");
        sharedPrefs.VNIC_SESSION_ID = std::to_string(unique_node.get<int>("session_id"));
        return true;
        
    }
    return false;
}

bool ConnectServer::SetClientWifiPrefs(ptree &config_tree)
{
    BOOST_FOREACH (ptree::value_type &v, config_tree.get_child("anchor_connections"))
    {
        ptree delivery_connection = v.second.get_child("delivery_connections");
        ptree wifi_delivery;
        bool flag = true;
        for (ptree::iterator it = delivery_connection.begin(); it != delivery_connection.end(); ++it)
        {
            if ((it->second).get<int>("connection_id") == 0)
            {
                wifi_delivery = it->second;
                flag = false;
                break;
            }
        }

        if (flag)
            return false;

        ptree wifi_tunnel_info = wifi_delivery.get_child("adaptation_method_params");
        p_systemStateSettings->serverWifiTunnelIp = wifi_tunnel_info.get<std::string>("tunnel_ip_addr");
        p_systemStateSettings->serverWifiTunnelPort = wifi_tunnel_info.get<int>("tunnel_end_port");
        p_systemStateSettings->serverWifiHeaderOpt = wifi_tunnel_info.get<bool>("mx_header_optimization");

        ptree client_params = connectionMessages.MX_UP_Setup_Confirmation.get_child("client_params");
        ptree client_info;
        flag = true;
        for (ptree::iterator client_it = client_params.begin(); client_it != client_params.end(); client_it++)
        {
            if ((client_it->second).get<int>("connection_id") == 0)
            {
                client_info = client_it->second;
                flag = false;
                break;
            }
        }

        if (flag)
            return false;

        p_systemStateSettings->clientWifiAdaptPort = client_info.get_child("adapt_param").get<int>("udp_adapt_port");
        return true;
        
    }
    return false;
}

bool ConnectServer::SetClientPrefs(ptree &config_tree)
{
    BOOST_FOREACH (ptree::value_type &v, config_tree.get_child("anchor_connections"))
    {
        ptree config = v.second.get_child("client_config");

        p_systemStateSettings->gNetWorkInterfaceMinMTU = config.get<int>("network_interface_minMTU");
        //p_systemStateSettings->gDynamicSplitFlag = config.get<int>("dynamic_split_flag");
        p_systemStateSettings->gLteAlwaysOnFlag = config.get<int>("Lte_always_on_flag");
        p_systemStateSettings->congestDetectLossThreshold = pow(10, 0 - (double)(config.get<int>("congest_detect_loss_threshold")));
        p_systemStateSettings->congestDetectUtilizationThreshold = (double)(config.get<int>("congest_detect_utilization_threshold")) / 100;
        p_systemStateSettings->lteProbeIntervalScreenOff = config.get<int>("lte_probe_interval_screen_off");
        p_systemStateSettings->lteProbeIntervalScreenOn = config.get<int>("lte_probe_interval_screen_on");
        p_systemStateSettings->lteProbeIntervalActive = config.get<int>("lte_probe_interval_active");
        p_systemStateSettings->lteRssiMeasurement = config.get<int>("lte_rssi_measurement");
        p_systemStateSettings->wifiProbeIntervalScreenOff = config.get<int>("wifi_probe_interval_screen_off");
        p_systemStateSettings->wifiProbeIntervalScreenOn = config.get<int>("wifi_probe_interval_screen_on");
        p_systemStateSettings->WiFiProbeIntervalActive = config.get<int>("wifi_probe_interval_active");
        p_systemStateSettings->paramL = config.get<int>("param_l");
        p_systemStateSettings->wifiLowRssi = config.get<int>("wifi_low_rssi");
        p_systemStateSettings->wifiHighRssi = config.get<int>("wifi_high_rssi");
        p_systemStateSettings->MRPintervalActive = config.get<int>("MRP_interval_active");
        p_systemStateSettings->MRPintervalIdle = config.get<int>("MRP_interval_idle");
        p_systemStateSettings->MRPsize = config.get<int>("MRP_size");
        p_systemStateSettings->MAX_MAXREORDERINGDELAY = config.get<int>("max_reordering_delay");
        p_systemStateSettings->MIN_MAXREORDERINGDELAY = config.get<int>("min_reordering_delay");
        p_systemStateSettings->reorderBufferSize = config.get<int>("reorder_buffer_size");
        p_systemStateSettings->reorderLsnEnhanceFlag = config.get<int>("reorder_Lsn_enhance_flag");
        p_systemStateSettings->reorderDropOutOfOrderPkt = config.get<int>("reorder_drop_out_of_order_pkt");
        p_systemStateSettings->minTpt = config.get<int>("min_tpt");
        p_systemStateSettings->idleTimer = config.get<int>("idle_timer");
        p_systemStateSettings->allowAppListEnable = config.get<int>("allow_app_list_enable");
        p_systemStateSettings->wifiOwdOffsetMax = config.get<int>("wifi_owd_offset");
        p_systemStateSettings->gUlDuplicateFlag = config.get<int>("ul_duplicate_flag");

  
        p_systemStateSettings->OWD_CONVERGE_THRESHOLD = ((double)(config.get<int>("OWD_CONVERGE_THRESHOLD"))) / 100;
        p_systemStateSettings->MAX_MEASURE_INTERVAL_NUM = config.get<int>("MAX_MEASURE_INTERVAL_NUM");
        p_systemStateSettings->MIN_PACKET_NUM_PER_INTERVAL = config.get<int>("MIN_PACKET_NUM_PER_INTERVAL");
        p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION = config.get<int>("MAX_MEASURE_INTERVAL_DURATION");
        p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION = config.get<int>("MIN_MEASURE_INTERVAL_DURATION");
        p_systemStateSettings->BURST_SAMPLE_FREQUENCY = config.get<int>("BURST_SAMPLE_FREQUENCY");
        p_systemStateSettings->MAX_RATE_ESTIMATE = config.get<int>("MAX_RATE_ESTIMATE");
        p_systemStateSettings->RATE_ESTIMATE_K = config.get<int>("RATE_ESTIMATE_K");
        p_systemStateSettings->MIN_PACKET_COUNT_PER_BURST = config.get<int>("MIN_PACKET_COUNT_PER_BURST");
        p_systemStateSettings->BURST_INCREASING_ALPHA = ((double)(config.get<int>("BURST_INCREASING_ALPHA"))) / 100;
        p_systemStateSettings->STEP_ALPHA_THRESHOLD = config.get<int>("STEP_ALPHA_THRESHOLD");
        p_systemStateSettings->TOLERANCE_LOSS_BOUND = config.get<int>("TOLERANCE_LOSS_BOUND");
        p_systemStateSettings->TOLERANCE_DELAY_BOUND = config.get<int>("TOLERANCE_DELAY_BOUND");
        p_systemStateSettings->TOLERANCE_DELAY_H = config.get<int>("TOLERANCE_DELAY_H");
        p_systemStateSettings->TOLERANCE_DELAY_L = config.get<int>("TOLERANCE_DELAY_L");
        p_systemStateSettings->SPLIT_ALGORITHM = config.get<int>("SPLIT_ALGORITHM");
        
        if (p_systemStateSettings->SPLIT_ALGORITHM > 0)
        p_systemStateSettings->gDynamicSplitFlag = 1;
        else
        p_systemStateSettings->gDynamicSplitFlag = 0;
        
        p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS = config.get<int>("INITIAL_PACKETS_BEFORE_LOSS");
        p_systemStateSettings->icmpFlowType = (unsigned char)config.get<int>("icmp_flow_type");
        p_systemStateSettings->tcpRTportStart = config.get<int>("tcp_rt_port_start");
        p_systemStateSettings->tcpRTportEnd = config.get<int>("tcp_rt_port_end");
        p_systemStateSettings->tcpHRportStart = config.get<int>("tcp_hr_port_start");
        p_systemStateSettings->tcpHRportEnd = config.get<int>("tcp_hr_port_end");
        p_systemStateSettings->udpRTportStart = config.get<int>("udp_rt_port_start");
        p_systemStateSettings->udpRTportEnd = config.get<int>("udp_rt_port_end");
        p_systemStateSettings->udpHRportStart = config.get<int>("udp_hr_port_start");
        p_systemStateSettings->udpHRportEnd = config.get<int>("udp_hr_port_end");
        p_systemStateSettings->ulQoSFlowEnable = config.get<int>("ul_qos_flow_enable");
        return true;
    }
    return false;
}

void ConnectServer::RecvNCMM()
{
    websocketsThreadRunning = true;
    beast::error_code ec;
    std::string last_msg;
    std::ostringstream output;
    std::string jsonObject;
    beast::flat_buffer mbuffer;
    
    while (1)
    {
       // try
        {
            if (ws_new.read(mbuffer, ec) <=0 )
             printf("ws read error");

            if (ec)
            {
                std::stringstream ss_closeWs;
                ss_closeWs << "close ws_new websocket!\n";
                p_systemStateSettings->PrintLogs(ss_closeWs);
                break;
            }
            else
            {
                last_msg = beast::buffers_to_string(mbuffer.data());
                mbuffer.consume(mbuffer.size());
                mbuffer.clear();
                std::istringstream in(last_msg);
                ptree node;
                pt::read_json(in, node);
                std::string msg_type = node.get<std::string>("message_type");
                if (msg_type.compare("mx_capability_resp") == 0)
                {
                    int connectionID = node.get<int>("num_anchor_connections");
                    ptree mx_ack = connectionMessages.MX_Capability_ACK;
                    output.str("");
                    output.clear();
                    if (connectionID != 0)
                    {
                        uniqueSessionId = node.get_child("unique_session_id");
                        int ncm_id = uniqueSessionId.get<int>("ncm_id");
                        int session_id = uniqueSessionId.get<int>("session_id");

                        std::ostringstream uniqueSessionIDStream;
                        pt::write_json(uniqueSessionIDStream, uniqueSessionId);
                        std::regex reg("\\\"([0-9]+)\\\""); // remove quotes
                        std::string uniqueSessionIdString = std::regex_replace(uniqueSessionIDStream.str(), reg, "$1");
                        p_systemStateSettings->uniqueSessionId = uniqueSessionIdString;
                        p_systemStateSettings->key = session_id;
                   
                        p_systemStateSettings->aesKeyString = node.get<std::string>("aes_key");
                        node.erase("aes_key");
                        p_systemStateSettings->aesKey = base64_decode(p_systemStateSettings->aesKeyString);
                        p_systemStateSettings->enable_encryption = true;
                                              
                        mx_ack.get_child("unique_session_id").put("ncm_id", ncm_id);
                        mx_ack.get_child("unique_session_id").put("session_id", session_id);
                        pt::write_json(output, mx_ack);
                        jsonObject = output.str();
                        std::regex reg2("\\\"([0-9]+|true|false)\\\""); // remove quotes
                        jsonObject = std::regex_replace(jsonObject, reg2, "$1");
                        try {
                            if (ws_new.write(net::buffer(jsonObject)) <= 0)
                             printf("\n ws_write error\n");
                            
                        }
                        catch (boost::system::system_error const& e)
                        {
                            std::stringstream ss;
                            ss << e.what() << std::endl;
                            ss << "ws new write failed\n";
                            p_systemStateSettings->PrintLogs(ss);
                        }
                        output.str("");
                        output.clear();
                    }
                    else
                    {
                        std::stringstream ss;
                        ss << "Error: server reject connect\n";
                        p_systemStateSettings->PrintLogs(ss);
                    }
                }
                else if (msg_type.compare("mx_measurement_conf") == 0)
                {
                    std::stringstream ss;
                    ss << "[ncm->ccm] mx_measurement_conf\n";
                    p_systemStateSettings->PrintLogs(ss);
                }
                else if (msg_type.compare("mx_gma_wifi_list") == 0)
                {
                    std::string wifiSsidList = node.get<std::string>("wifi_ssid_list");
                    std::string listType = node.get<std::string>("list_type");
                    std::stringstream ss;
                    ss << "web socket message :" << wifiSsidList << " : " << listType << std::endl;
                    p_systemStateSettings->PrintLogs(ss);
                }
                else if (msg_type.compare("mx_reconf_rsp") == 0)
                {
                    std::stringstream ss;
                    try
                    {
                        if (mxLTEReconfigReqMsg.get<int>("sequence_num") == node.get<int>("sequence_num"))
                        {
                            mxLTEReconfigReqMsg = node;
                            ss << "[ncm->ccm] Recv mx_reconf_rsp(LTE)\n";
                            p_systemStateSettings->PrintLogs(ss);
                        }
                        else
                        {
                            if (linkFlag == 1)
                            {
                                mxWifiReconfigReqMsg = node;
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
                    
                    ptree mx_setup_confirm = connectionMessages.MX_UP_Setup_Confirmation;

                    int ncm_id = uniqueSessionId.get<int>("ncm_id");
                    int session_id = uniqueSessionId.get<int>("session_id");
                    mx_setup_confirm.get_child("unique_session_id").put("ncm_id", ncm_id);
                    mx_setup_confirm.get_child("unique_session_id").put("session_id", session_id);

                    pt::write_json(output, mx_setup_confirm);
                    jsonObject = output.str();
                    std::regex reg("\\\"([0-9]+|true|false)\\\""); // remove quotes
                    jsonObject = std::regex_replace(jsonObject, reg, "$1");

                    if (ws_new.write(net::buffer(jsonObject)) <= 0)
                    printf("\n ws_write error\n");

                    if (SetClientLtePrefs(node))
                    {
                        if (SetClientWifiPrefs(node))
                        {
                            if (SetClientPrefs(node))
                            {
                                std::stringstream ss1;
                                ss1 << "Websocket completed, send probe now. \n";
                                p_systemStateSettings->PrintLogs(ss1);
                                p_systemStateSettings->vnicInit = true;
                            }
                        }
                    }
                    break;
                }
                else
                {
                    std::stringstream ss2;
                    ss2 << "wrong messages??\n";
                    p_systemStateSettings->PrintLogs(ss2);
                }


                
            }
        }
  
    }
    
    websocketsThreadRunning = false;
    return;
}

void ConnectServer::RecvInit()
{
    std::thread::native_handle_type wsConnID = 0;
    int k = 0;
    beast::error_code ec;

    std::string last_msg;
    beast::flat_buffer buffer;
    if (ws.read(buffer, ec) <=0)
     printf("ws read error");
        
        if (ec)
        {
            std::stringstream ss_closeWs;
            ss_closeWs << "close ws websocket!\n";
            p_systemStateSettings->PrintLogs(ss_closeWs);
        }
        else
        {
            last_msg = beast::buffers_to_string(buffer.data());
            buffer.consume(buffer.size());
            buffer.clear();
            std::istringstream in(last_msg);
            ptree node;
            pt::read_json(in, node);
            std::string msg_type = node.get<std::string>("message_type");
            if (msg_type.compare("mx_system_info") == 0)
            {
                BOOST_FOREACH(pt::ptree::value_type & v, node.get_child("ncm_connections"))
                {
                    pt::ptree ep = v.second.get_child("ncm_end_point");
                    wsAddressTmp = p_systemStateSettings->serverlteIpv4Address;
                    wsPortTmp = ep.get<std::string>("port"); //port 10021
                }

                std::thread wsWsConnectThread;
                wsThreadBusy = true;
                try {
                    wsWsConnectThread = std::thread(std::bind(&ConnectServer::WsNewConnect, this));
                    wsConnID = wsWsConnectThread.native_handle();
                     k = 0;
                    while (k < 10 && wsThreadBusy)
                    {
                        p_systemStateSettings->msleep(1000);
                        k++;
                    }

                    if (wsThreadBusy)
                        {
                            p_systemStateSettings->terminateThread(wsConnID);
                       }
                    wsWsConnectThread.join();
                }
                catch (const std::system_error& e) {
                    std::cout << "Caught system_error with code " << e.code()
                        << " meaning " << e.what() << '\n';
                    return;
                }
                wsThreadBusy = false;
                if (ws_new.is_open())
                {
                    try {
                        wsRecvNCMMThread = std::thread(std::bind(&ConnectServer::RecvNCMM, this));
                    }
                    catch (const std::system_error& e) {
                        std::cout << "Caught system_error with code " << e.code()
                            << " meaning " << e.what() << '\n';
                        beast::error_code ec;
                        ws_new.close(websocket::close_code::abnormal, ec);
                        return;
                    }
                }
                else
                {
                    if (beast::get_lowest_layer(ws_new).socket().is_open())
                    {
                        beast::error_code ec;
                        beast::get_lowest_layer(ws_new).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                        beast::get_lowest_layer(ws_new).socket().close();
                    }
                    return;
                }

                std::string vnicIP = sharedPrefs.VNIC_IP;
                int vnicSessionId = std::atoi(sharedPrefs.VNIC_SESSION_ID.c_str());
               
                ptree mx_capability_req = connectionMessages.MX_Capability_Request;
                if (vnicIP.compare("0.0.0.0") != 0 && vnicSessionId != 0)
                {
                    BOOST_FOREACH(ptree::value_type & v, mx_capability_req.get_child("anchor_connections"))
                    {
                        v.second.put("last_ip_address", vnicIP);
                        v.second.put("last_session_id", vnicSessionId);
                    }
                }
   
                std::ostringstream output;
                pt::write_json(output, mx_capability_req);
                std::string jsonObject = output.str();

                std::regex reg("\\\"([0-9]+|true|false)\\\""); // remove quotes
                jsonObject = std::regex_replace(jsonObject, reg, "$1");
                try {
                    if (ws_new.write(net::buffer(jsonObject)) <= 0)
                     printf("\n ws_write error\n");
                }
                catch (boost::system::system_error const& e)
                {
                    std::stringstream ss;
                    ss << e.what() << std::endl;
                    ss << "ws new write failed\n";
                    p_systemStateSettings->PrintLogs(ss);
                }

                k = 0;
                while (k < 10 && websocketsThreadRunning)
                {
                    p_systemStateSettings->msleep(1000);
                    k++;
                }

                if (beast::get_lowest_layer(ws_new).socket().is_open())
                {
                    beast::error_code ec;
                    beast::get_lowest_layer(ws_new).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                    beast::get_lowest_layer(ws_new).socket().close();
                }

                if (ws_new.is_open())
                {
                    beast::error_code ec;
                    ws_new.close(websocket::close_code::abnormal, ec);
                }

                wsRecvNCMMThread.join();
            }
        }

        
            websocketsCompleted = true;
            return;
}

void ConnectServer::WsNewConnect()
{
    
    auto const results = resolver_.resolve(wsAddressTmp, wsPortTmp);
    beast::get_lowest_layer(ws_new).socket().open(boost::asio::ip::tcp::v4());
    try {
        beast::get_lowest_layer(ws_new).socket().bind(boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address_v4::from_string(p_systemStateSettings->lteIpv4Address.c_str()), 0));
    }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        ss << "ws new bind failed\n";
        p_systemStateSettings->PrintLogs(ss);
        if (beast::get_lowest_layer(ws_new).socket().is_open())
        {
            beast::error_code ec;
            beast::get_lowest_layer(ws_new).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            beast::get_lowest_layer(ws_new).socket().close();
        }
        wsThreadBusy = false;
        return;
    }

    try {
        beast::get_lowest_layer(ws_new).connect(*results);
        ws_new.next_layer().handshake(ssl::stream_base::client);
        ws_new.handshake(wsAddressTmp, "/");
    }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        ss << "ws new Connect failed\n";
        p_systemStateSettings->PrintLogs(ss);
    }
    wsThreadBusy = false;
    return;
}
void ConnectServer::WsConnect()
{
    std::string port = std::to_string(p_systemStateSettings->server_ncm_port);

    auto const results = resolver_.resolve(p_systemStateSettings->serverlteIpv4Address, port);
    beast::get_lowest_layer(ws).socket().open(boost::asio::ip::tcp::v4());
    try
    {
        beast::get_lowest_layer(ws).socket().bind(boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address_v4::from_string(p_systemStateSettings->lteIpv4Address.c_str()), 0));
    }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        ss << "bind failed\n";
        p_systemStateSettings->PrintLogs(ss);
        if (beast::get_lowest_layer(ws).socket().is_open())
        {
            beast::error_code ec;
            beast::get_lowest_layer(ws).socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            beast::get_lowest_layer(ws).socket().close();
        }
        wsThreadBusy = false;
        return;
    }
    
    try
    {
        beast::get_lowest_layer(ws).connect(*results);
        ws.next_layer().handshake(ssl::stream_base::client);
        ws.handshake( p_systemStateSettings->serverlteIpv4Address, "/");
    }
    catch (boost::system::system_error const& e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        ss << "Connect failed\n";
        p_systemStateSettings->PrintLogs(ss);
    }
    wsThreadBusy = false;
    return;
}

void ConnectServer::InitMxLTEReconfigReqMsg()
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

void ConnectServer::InitMxWifiReconfigReqMsg()
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