//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : DataReceve.h

#ifndef _DATA_RECEIVE_H
#define _DATA_RECEIVE_H

#if defined(__unix__) || defined(__APPLE__)
#include <netinet/in.h>
#endif


#include "Header.h"
#include "SystemStateSettings.h"
#include "ReorderingManager.h"
#include "Measurement.h"


class DataReceive{

public:
    bool ThreadBusy = false;
    GMASocket wifiudp_fd = GMA_INVALID_SOCKET;
    GMASocket lteudp_fd = GMA_INVALID_SOCKET;
    int dataOffset = 0;
    int maxPktLen;
    int maxTsaSn = 0;
    bool isDataReceiveStart = true;
    int nextWifiRtSn = 0;
    int nextLteRtSn = 0;
    int nextWifiHrSn = 0;
    int nextLteHrSn = 0;
    GMASocket udpLoop = GMA_INVALID_SOCKET;
    struct sockaddr_in udpInaddr = {};
    struct sockaddr udpAddr = {};

    IPHeader ipHeader = {};
    UDPHeader udpHeader = {};
    GMADataHeader gmaDataHeader = {};
    VnicAck vnicAck = {};
    TrafficSplitAck vnicTSA = {};
    TSCMessage tscMessage = {};
    TFCMessage tfcMessage = {};
    ReqMessage reqMessage = {};

      
    ReorderingManager reorderingManager;
    MeasurementManager measurementManager;

    SystemStateSettings *p_systemStateSettings = NULL;
    
    DataReceive();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void listenSockets();
    void receiveWifiControl(char* packet);
    void receiveLteControl(char* packet);
    void receiveWifiPacket(char* packet);
    void receiveLtePacket(char* packet);

    void updataWifiChannel(GMASocket wifiFd);
    bool updataLteChannel(GMASocket lteFd);
    int rollOverDiff2(int x, int y, int max);
    int rollOverDiff(int x, int y);
    void closeLteChannel();
    void closeWifiChannel();
    bool updateSettings();


    void ExitThread();
    void wakeupSelect();
    bool setupUdpSocket();
    void startReordering();
    void closeReordering();
    void updateReorderingAndMeasurement();
};

#endif