//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : DataSend.h

#ifndef _DATA_SEND_H
#define _DATA_SEND_H

#include <stdint.h>

#include "ControlMessage.h"
#include "Header.h"

class DataSend{

public:
    bool isDataSendStart;
    int length;
    int snNumber_dup;
    int snNumber_realtime;
    int snNumber_default;

    GMASocket wifiudp_fd = GMA_INVALID_SOCKET;
    GMASocket lteudp_fd = GMA_INVALID_SOCKET;
    struct sockaddr_in wifiServer;
    struct sockaddr_in lteServer;
    int wifi_server_ip = 0;
    int lte_server_ip = 0;
    
    IPHeader ipHeader;
    GMADataHeader gmaDataHeader;
    SystemStateSettings *p_systemStateSettings = NULL;

    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void updateServerAddress(struct sockaddr_in wifiServerAddr, struct sockaddr_in lteServerAddr);
    void processPackets(char * buffer, int length);
    void updataWifiChannel(GMASocket wifiFd);
    void updataLteChannel(GMASocket lteFd);
    void updateSettings();
    DataSend();
    
private:
    unsigned char current_pkt_tos = 0;
    unsigned char last_pkt_tos = 0;
    void sendPacketToServer(char* data, int offset, int length);
    void sendHRPacketToServer(char* data, int offset, int length);
    void sendRTPacketToServer(char* data, int offset, int length);

    

};

#endif