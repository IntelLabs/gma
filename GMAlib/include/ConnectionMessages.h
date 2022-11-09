//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ConnectionMessages.h

#ifndef _CONNECTION_MESSAGES_H
#define _CONNECTION_MESSAGES_H


#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <string>

using ptree = boost::property_tree::ptree;

class ConnectionMessages{
public:
    ptree MX_discover;
    ptree MX_Capability_Request;
    ptree MX_Capability_ACK;
    ptree MX_UP_Setup_Confirmation;
    ptree MX_Session_Resume_Req;
    ptree MX_Reconfiguration_Request;

    
    ConnectionMessages();

};

#endif