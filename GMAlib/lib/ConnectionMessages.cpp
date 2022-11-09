//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ConnectionMessages.cpp

#include "../include/ConnectionMessages.h"
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

using ptree = boost::property_tree::ptree;
ConnectionMessages::ConnectionMessages()
{
    //
    ptree unique_session;
    unique_session.put("ncm_id", 110);
    unique_session.put("session_id", 1111);

    //1******mx_discover message
    MX_discover.put("version", "1.0");
    MX_discover.put("message_type", "mx_discover");
    MX_discover.put("sequence_num", 1);

    //2******mx_capability_request message
    MX_Capability_Request.put("version", "1.0");
    MX_Capability_Request.put("message_type", "mx_capability_req");
    MX_Capability_Request.put("sequence_num", 3);
    ptree feature_arr;
    ptree child1, child2;
    child1.put("feature_name", "downlink_aggregation");
    child1.put("active", true);
    child2.put("feature_name", "measurement");
    child2.put("active", true);
    feature_arr.push_back(std::make_pair("", child1));
    feature_arr.push_back(std::make_pair("", child2));
    MX_Capability_Request.add_child("feature_active", feature_arr);
    MX_Capability_Request.put("num_anchor_connections", 1);
    ptree anchor, anchor_child;
    anchor_child.put("connection_id", 4);
    anchor_child.put("connection_type", "vnic");
    anchor_child.put("last_ip_address", "0.0.0.0");
    anchor_child.put("last_session_id", 0);
    anchor_child.put("device_type", 0);
    anchor.push_back(std::make_pair("", anchor_child));
    MX_Capability_Request.add_child("anchor_connections", anchor);

    MX_Capability_Request.put("new_delivery_connections", 2);
    ptree deliver, childwifi, childlte;
    childwifi.put("connection_id", 0);
    childwifi.put("connection_type", "wifi");
    childlte.put("connection_id", 3);
    childlte.put("connection_type", "lte");
    deliver.push_back(std::make_pair("", childwifi));
    deliver.push_back(std::make_pair("", childlte));
    MX_Capability_Request.add_child("delivery_connections", deliver);

    ptree conver, conver_child, adapt, adapt_child;
    conver_child.put("method", "Trailer_Based");
    conver_child.put("supported", true);
    conver.push_back(std::make_pair("", conver_child));
    MX_Capability_Request.add_child("convergence_methods", conver);
    adapt_child.put("method", "UDP_without_DTLS");
    adapt_child.put("supported", true);
    adapt.push_back(std::make_pair("", adapt_child));
    MX_Capability_Request.add_child("adaptation_methods", adapt);

    //3******mx_capability_ack message
    MX_Capability_ACK.put("version", "1.0");
    MX_Capability_ACK.put("message_type", "mx_capability_ack");
    MX_Capability_ACK.put("sequence_num", 3);
    MX_Capability_ACK.put("capability_ack", "MX_ACCEPT");

    MX_Capability_ACK.add_child("unique_session_id", unique_session);

    //4******mx_up_setup_confirmation message
    MX_UP_Setup_Confirmation.put("version", "1.0");
    MX_UP_Setup_Confirmation.put("message_type", "mx_up_setup_cnf");
    MX_UP_Setup_Confirmation.put("sequence_num", 5);
    MX_UP_Setup_Confirmation.add_child("unique_session_id", unique_session);

    ptree conn0, conn3, port0, port3, probe_port;
    ptree clientarr;
    probe_port.put("probe_port", 8888);
    MX_UP_Setup_Confirmation.add_child("probe_param", probe_port);
    port3.put("udp_adapt_port", 9999);
    conn3.put("connection_id", 3);
    conn3.add_child("adapt_param", port3);
    port0.put("udp_adapt_port", 7777);
    conn0.put("connection_id", 0);
    conn0.add_child("adapt_param", port0);
    clientarr.push_back(std::make_pair("", conn3));
    clientarr.push_back(std::make_pair("", conn0));
    MX_UP_Setup_Confirmation.add_child("client_params", clientarr);


    //5****** mx_session_resume_req
    MX_Session_Resume_Req.put("version", "1.0");
    MX_Session_Resume_Req.put("message_type", "mx_session_resume_req");
    MX_Session_Resume_Req.put("sequence_num", 13);
    MX_Session_Resume_Req.add_child("unique_session_id", unique_session);

    //6****** mx_reconfiguration_request
    ptree lteNode, wifiNode;
    lteNode.put("version", "1.0");
    lteNode.put("message_type", "mx_reconf_req");
    lteNode.put("sequence_num", 6);
    lteNode.add_child("unique_session_id", unique_session);
    lteNode.put("reconf_action", "setup");
    lteNode.put("connection_id", 3);
    lteNode.put("ip_address", "192.0.0.4");
    lteNode.put("mtu_size", 1400);
    lteNode.put("connection_status", "connected");

    wifiNode.put("version", "1.0");
    wifiNode.put("message_type", "mx_reconf_req");
    wifiNode.put("sequence_num", 7);
    wifiNode.add_child("unique_session_id", unique_session);
    wifiNode.put("reconf_action", "setup");
    wifiNode.put("connection_id", 0);
    wifiNode.put("ip_address", "10.175.245.239");
    wifiNode.put("mtu_size", 1400);
    wifiNode.put("connection_status", "connected");
    MX_Reconfiguration_Request.push_back(std::make_pair("", lteNode));
    MX_Reconfiguration_Request.push_back(std::make_pair("", wifiNode));
}

