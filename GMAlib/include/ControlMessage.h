//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ControlMessage.h

#ifndef _CONTROL_MESSAGE_H
#define _CONTROL_MESSAGE_H

#if defined(__unix__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "Header.h"
#include "SystemStateSettings.h"

class SendWifiProbeMsg
{
public:
    GMASocket wifiudpFd = GMA_INVALID_SOCKET;
    struct sockaddr_in wifiServer;

    int lastSendWifiProbeTime = 0;
    int intervalTime = 0; //systemStateSettings.wifiProbeInterval;
    int seqNum = 0;
    unsigned char size = 0;
    static const int buf_size = 75;
    unsigned char buf[buf_size];
    static const int plaintext_size = 43;
    unsigned char plainText[plaintext_size];

    static const int plaintext2_size = 41;  //ack 
    unsigned char plainText2[41];
    unsigned char buf2[75];


    int recvAckSN = 1;
    bool sendWifiProbeThreadBusy = false;
    bool ThreadBusy = false; 
    bool probingStart = false;
    std::unordered_map<int, int> snAndTimeArray;

    IPHeader ipHeader;
    UDPHeader udpHeader;
    GMAMessageHeader gmaMessageHeader;

    std::mutex wifiprobe_begin_mtx;
    std::condition_variable wifiprobe_begin_cv;
    std::mutex wifiprobe_ack_mtx;
    std::condition_variable wifiprobe_ack_cv;
    std::mutex wifiprobe_next_mtx;
    std::condition_variable wifiprobe_next_cv;
    
    SystemStateSettings *p_systemStateSettings = NULL;

    SendWifiProbeMsg();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void UpdateWifiFd(GMASocket fd, struct sockaddr_in wifiServerAddr);
    void Execute();
    void SendACK(unsigned char reqtype);
    void BuildPacketHeader();
    void notifyWifiProbeCycle();
    void sendWifiProbe();
    void sendLteProbe();
    void receiveProbeAck(int recvProbeAckSeqNum);
    void updateSettings();
};

class SendLteProbeMsg
{
public:
    GMASocket lteudpFd = GMA_INVALID_SOCKET;
    struct sockaddr_in lteServer;

    int lastSendLteProbeTime = 0;
    int intervalTime = 0; //systemStateSettings.wifiProbeInterval;
    int seqNum = 0;
    int size = 0;
    static const int buf_size = 75;
    unsigned char buf[buf_size];
    static const int plaintext_size = 43;
    unsigned char plainText[plaintext_size];
    int recvAckSN = 1;
    bool sendLteProbeThreadBusy = false;
    bool ThreadBusy = false;
    bool probingStart = false;
    std::unordered_map<int, int> snAndTimeArray;

    IPHeader ipHeader;
    UDPHeader udpHeader;
    GMAMessageHeader gmaMessageHeader;

    std::mutex lteprobe_begin_mtx;
    std::condition_variable lteprobe_begin_cv;
    std::mutex lteprobe_ack_mtx;
    std::condition_variable lteprobe_ack_cv;
    std::mutex lteprobe_next_mtx;
    std::condition_variable lteprobe_next_cv;

    SystemStateSettings *p_systemStateSettings = NULL;

    SendLteProbeMsg();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void UpdateLteFd(GMASocket fd, struct sockaddr_in lteServerAddr);
    void Execute();
    void BuildPacketHeader();
    void notifyLteProbeCycle();
    void sendLteProbe();
    void receiveProbeAck(int recvProbeAckSeqNum);
    void thread_sendLteProbe();
    void updateSettings();
};

class SendMRPMsg
{
public:
    GMASocket wifiudpFd = GMA_INVALID_SOCKET;
    GMASocket lteudpFd = GMA_INVALID_SOCKET;
    struct sockaddr_in wifiServer;
    struct sockaddr_in lteServer;

    long lteNrtDownlinkData = 0;
    long lteRtDownlinkData = 0;
    long lteTotalUplinkData = 0;
    long wifiNrtDownlinkData = 0;
    long wifiRtDownlinkData = 0;

    long wifiTotalUplinkData = 0;
    int lteDownlinkNrtThroughput = 0;
    int wifiDownlinkNrtThroughput = 0;
    int lteDownlinkRtThroughput = 0;
    int wifiDownlinkRtThroughput = 0;
    int lteUplinkThroughput = 0;
    int wifiUplinkThroughput = 0;
    long speed;
    long dl_speed;
    static const int buf_size = 1500;
    unsigned char buf[buf_size];
    int time;

    IPHeader ipHeader;
    UDPHeader udpHeader;
    GMAMessageHeader gmaMessageHeader;

    std::mutex mrp_begin_mtx;
    std::condition_variable mrp_begin_cv;
    std::mutex mrp_exit_mtx;
    std::condition_variable mrp_exit_cv;
    bool ThreadBusy = false;

    SystemStateSettings *p_systemStateSettings = NULL;

    SendMRPMsg();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void Execute();
    void BuildPacketHeader();
    int BuildMeasureReportElement(unsigned char *buf, int offset);
    void PrepareMeasureReport();
    void UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr);
    void UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr);
    void notifyMRPCycle();
    void updateSettings();
};

class SendLRPMsg
{
public:
    GMASocket wifiudpFd = GMA_INVALID_SOCKET;
    GMASocket lteudpFd = GMA_INVALID_SOCKET;
    struct sockaddr_in wifiServer;
    struct sockaddr_in lteServer;
    bool isConnect;
    unsigned char code;
    static const int buf_size = 50;
    unsigned char buf[buf_size];

    IPHeader ipHeader;
    UDPHeader udpHeader;
    GMAMessageHeader gmaMessageHeader;

    std::mutex lrp_begin_mtx;
    std::condition_variable lrp_begin_cv;
    bool ThreadBusy = false;

    SystemStateSettings *p_systemStateSettings = NULL;

    SendLRPMsg();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void Execute();
    void BuildPacketHeader();
    void UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr);
    void UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr);
    void notifyLRPCycle(bool isConnect, unsigned char byte);
    void updateSettings();
 };

class SendTSUMsg
{
public:
    GMASocket wifiudpFd = GMA_INVALID_SOCKET;
    GMASocket lteudpFd = GMA_INVALID_SOCKET;
    struct sockaddr_in wifiServer;
    struct sockaddr_in lteServer;
    int seqNum = 0;
    int nextRecvTSASeqNum = 0;
    static const int buf_size = 77;
    static const int plaintext_size = 45;
    unsigned char buf[buf_size];
    unsigned char plainText[plaintext_size];
    int tsu_success_flag = 0;
    bool tsu_busy_flag = false;
    bool tsu_busy2_flag = false;
    bool ThreadBusy = false;

    int wifiSplitFactor = 32;
    int lteSplitFactor = 0;
    int lvalue = 0;

    std::unordered_map<int, int> lteSnAndTimeArray;
    std::unordered_map<int, int> wifiSnAndTimeArray;
    IPHeader ipHeader;
    UDPHeader udpHeader;
    GMAMessageHeader gmaMessageHeader;

    std::mutex tsu_recv_mtx;
    std::condition_variable tsu_recv_cv;
    std::mutex tsu_send_mtx;
    std::condition_variable tsu_send_cv;

    SystemStateSettings *p_systemStateSettings = NULL;

    SendTSUMsg();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void Execute();
    void sendTSUMsg();
    void thread_sendTSUMsg();
    void trafficSplitingUpdate();
    void receiveWifiTSA(int recvProbeAckSeqNum, int recvWifiTSATime);
    void receiveLteTSA(int recvProbeAckSeqNum, int recvLteTSATime);
    void BuildPacketHeader();
    int rollOverDiff2(int x, int y, int max);
    void UpdateLteFd(GMASocket lteFd, struct sockaddr_in lteServerAddr);
    void UpdateWifiFd(GMASocket wifiFd, struct sockaddr_in wifiServerAddr);
    void updateSettings();
};

class ControlManager
{
public:
    std::thread wifiProbeThread;
    std::thread lteProbeThread;
    std::thread mrpThread;
    std::thread lrpThread;
    std::thread tsuThread;

    std::thread::native_handle_type wifiProbeID;
    std::thread::native_handle_type lteProbeID;
    std::thread::native_handle_type mrpID;
    std::thread::native_handle_type lrpID;
    std::thread::native_handle_type tsuID;

    SendWifiProbeMsg sendWifiProbeMsg;
    SendLteProbeMsg sendLteProbeMsg;
    SendMRPMsg sendMRPMsg;
    SendLRPMsg sendLRPMsg;
    SendTSUMsg obj_sendTSUMsg;
    SystemStateSettings *p_systemStateSettings = NULL;
    void startThread();
    void cancelThread();

    ControlManager();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void UpdateWifiParams(GMASocket wifiFd, struct sockaddr_in wifiServerAddr);
    void UpdateLteParams(GMASocket lteFd, struct sockaddr_in lteServerAddr);
    void updateSystemSettings();

    void notifyMRPCycle();
    void notifyLRPCycle(bool isConnect, unsigned char code);
    void sendTSUMsg();
    void sendWifiProbe();
    void sendLteProbe();   
    void receiveWifiTSA(int seqNumber, int currentTimeMillis);
    void receiveLteTSA(int seqNumber, int systemTimeMs);
    void receiveWifiProbeAck(int seqNumber);
    void receiveLteProbeAck(int seqNumber);
    void SendACK(unsigned char reqtype);

};


#endif