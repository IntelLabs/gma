//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : SystemStateSettings.h

#ifndef _SYSTEM_STATE_SETTINGS_H
#define _SYSTEM_STATE_SETTINGS_H

#include <string>
#include <thread>
#include "Header.h"
#include <climits>
class SystemStateSettings{
public:
    
    int gNetWorkInterfaceMinMTU;  //a configurable WLAN/LTE network MTU size
    int gDynamicSplitFlag;
    int gLteAlwaysOnFlag;
    int lteRssiMeasurement;
    int allowAppListEnable;
    int gUlDuplicateFlag;
    int gUlRToverLteFlag;
    int gDlRToverLteFlag;
    double congestDetectLossThreshold;  //10^(-n)  4--> 0.0001
    double congestDetectUtilizationThreshold;
    int lteProbeIntervalActive; //seconds
    int WiFiProbeIntervalActive;  //seconds
    int paramL; // sum of splitting index of lte and wifi, should not be changed
    int wifiLowRssi;
    int wifiHighRssi;
    int MRPintervalActive; //unit: seconds
    int MRPintervalIdle ; //unit: seconds
    int MRPsize; //40;
    int MAX_MAXREORDERINGDELAY; // 1s
    int MIN_MAXREORDERINGDELAY; //100ms
    int reorderBufferSize; //unit: pkt (default = 200)
    int reorderLsnEnhanceFlag; //1: enable (default)  0: disable
    int reorderDropOutOfOrderPkt; //1: enable 0: disable (default)
    int minTpt;  //10kBps
    int idleTimer; //minutes
    int wifiOwdOffsetMax; //if  .
    int lteProbeIntervalScreenOff;
    int lteProbeIntervalScreenOn;
    int wifiProbeIntervalScreenOff;
    int wifiProbeIntervalScreenOn;

    double OWD_CONVERGE_THRESHOLD;// if the owd difference of two consecutive measure interval is smaller than this threshold, we assume measurement converges.
    int MAX_MEASURE_INTERVAL_NUM; // max allowed measurement interval if the results do not converges.
    int MIN_PACKET_NUM_PER_INTERVAL; //when a interval end (due to time expires) without enough packets, it will be extended until more than this number of packets are received
    int MIN_PACKET_BURST_PER_INTERVAL; // a measurement interval needs at MIN_PACKET_BURST_PER_INTERVAL * paramL packets to end. e.g., 2*128
    long MAX_MEASURE_INTERVAL_DURATION; //1s
    long MIN_MEASURE_INTERVAL_DURATION; //100 ms
    int BURST_SAMPLE_FREQUENCY; //take one measurement very BUSRT_SAMPLE_FREQUENCY for packet burst rate estimate
    long MAX_RATE_ESTIMATE ; //kBps, the maximum rate estimate if no congestion happens
    long RATE_ESTIMATE_K; //kBps, the maximum rate estimate if no congestion happens
    int MIN_PACKET_COUNT_PER_BURST; //if we measure this number of continues delay increase, we estimate a burst rate in this interval
    double BURST_INCREASING_ALPHA; //assume the delay is increasing as long as the new delay is bigger than (1-alpha)* D_MIN + alpha * D_MAX (reference our IDF)
    int STEP_ALPHA_THRESHOLD; //after alphaThreshold continuous increase/decrease, increase the step size linearly. (from 1 to 2, 3, ..)
    int TOLERANCE_LOSS_BOUND;
    int TOLERANCE_DELAY_BOUND;
    int TOLERANCE_DELAY_H; //decrease wifi
    int TOLERANCE_DELAY_L; //increase wifi
    int SPLIT_ALGORITHM; //1: delay algorithm; 2: delay and loss algorithm; 3: gma2 algorithm
    bool FAST_LOSS_DETECTION = true; //default: enable fast loss detection
    int INITIAL_PACKETS_BEFORE_LOSS;  //10^9
    //end/////////////////////////////////////////


    bool m_adaptiveSplittingBurst = true;
    int minOwdMeasurementInterval = 5000; //min OWD measurement interval (ms)
    int minSplitAdjustmentStep = 1;  // m_relocateScaler = minSplitAdjustmentStep/splittingBurst
    int minPktsample;  //minimum number of samples for a valid OWD measurement
    int wifiOwdOffset; //we will compare wifiOwd + wifiOwdOffset with lteOwd. If we want to allocate more traffic over wifi, set this offset to be a negative value.
    int reorderRepeatTimer;  //unit: ms
    int reorderRepeatNum;
    int gmaMTUsize;
    int sizeofGMAMessageHeader;
    int sizeofDlGMAMessageHeader;
    int sizeofDlGmaDataHeader;
    int sizeofUlGmaDataHeader;

    int MRPinterval; //unit: seconds

    int wifiProbeTimeout; //unit: ms
    int reorderPktRateInitValue; //unit: k packet per seconds 20 x 1400 B = 2

    int gVnicMTU;
    int gLteMTU;
    
    bool gWifiFlag;
    bool gLteFlag;
    bool gIsWifiConnect;
    bool gIsLteConnect;
    bool gTunAvailable;
    bool gISVirtualWebsocket;
    int gStartTime;   //JZ the default value = -1

    bool gDLAllOverLte;
    bool gScreenOnFlag;
    int gDisconnectWifiTime;
    int gDisconnectLteTime;
    int gLastScreenOffTime;

    int lastReceiveWifiWakeUpReq;
    int lastReceiveLteWakeUpReq;
    int lastReceiveLteProbeAck;
    int lastReceiveWifiProbeAck;
    int lastReceiveWifiPkt;
    int lastReceiveLtePkt;
    int wifiProbeTh; //the minimum gap between last receive and last transmit astReceiveWifiPkt
    int lastSendWifiProbe;
    int lastSendLteProbe;
    int lastSendLteTsu;
    int lastSendWifiTsu;
    int wifiLinkRtt = 1000; //wifiLinkRtt = wifiLinkCtrlRtt + (average owd measured from data - wifiLinkCtrlOwd)
    int wifiLinkFailureFlag = 0; //0: unknown  1: active 2: inactive (failure) 
    int lteLinkFailureFlag = 0; //0: unknown  1: active 2: inactive (failure) 
    int wifiLinkCtrlRtt;
    int wifiLinkCtrlOwd;
    int wifiLinkMaxRtt;
    int lteLinkRtt = 1000; //lteLinkRtt = lteLinkCtrlRtt + (average owd measured from data - lteLinkCtrlOwd)
    int lteLinkCtrlRtt;
    int lteLinkCtrlOwd;
    int splitEnable;

    long lteReceiveNrtBytes;
    long lteSendBytes;
    long wifiReceiveNrtBytes;
    long wifiSendBytes;

    long lteReceiveRtBytes;
    long wifiReceiveRtBytes;


    unsigned char nonRealtimelModeFlowId;//dl: splitting traffic; ul:wifi only it wifi is available, otherwise lte
    unsigned char realtimeModeFlowId;//no aggregation, select LTE or WIFI, both uplink and downlink
    unsigned char ulDuplicateModeFlowId;//duplicate packets over both lte and wifi.

    unsigned char icmpFlowType;//default
    int tcpRTportStart;//default
    int tcpRTportEnd;//default
    int tcpHRportStart;//default
    int tcpHRportEnd;//default
    int udpRTportStart;//default
    int udpRTportEnd;//default
    int udpHRportStart;//default
    int udpHRportEnd;//default
    int ulQoSFlowEnable; //default



    //measurement manager measures the following parameters, they are normal packets
    long wifiOwdSum = 0; //control and data
    long wifiPacketNum = 0; //control and data
    long wifiPacketNum_last_interval = 0; //control and data
    long wifiRx_interval = INT_MAX; 
    long lteRx_interval = INT_MAX; 
    int wifiOwdMax;
    int wifiOwdMin;
    int wifiOwdMinLongTerm;
    int wifiInorderPacketNum; //data only
    int wifiMissingPacketNum; //data only
    int wifiAbnormalPacketNum; //data only
    long wifiRate; //data only

    bool ENABLE_FLOW_MEASUREMENT;
    int flowInorderPacketNum; //data only
    int flowMissingPacketNum; //data only
    int flowAbnormalPacketNum; //data only
    int flowOwdMax; //data only
    int flowOwdMin; //data only
    long flowOwdSum = 0; //data only
    int flowOwdPacketNum = 0; //data only

    long lteOwdSum; //control and data
    long ltePacketNum; //control and data
    int lteOwdMax;
    int lteOwdMin;
    int lteOwdMinLongTerm;
    int lteInorderPacketNum; //data only
    int lteMissingPacketNum; //data only
    int lteAbnormalPacketNum; //data only
    long lteRate; //data only

    //realtime
    long wifiRtOwdSum; //control and data
    long wifiRtPacketNum; //control and data
    int wifiRtOwdMax;
    int wifiRtOwdMin;

    long lteRtOwdSum; //control and data
    long lteRtPacketNum; //control and data
    int lteRtOwdMax;
    int lteRtOwdMin;

    int wifiRtInorderPacketNum; //data only
    int wifiRtMissingPacketNum; //data only
    int wifiRtAbnormalPacketNum; //data only

    int lteRtInorderPacketNum; //data only
    int lteRtMissingPacketNum; //data only
    int lteRtAbnormalPacketNum; //data only

    int wifiOwdTxOffset = 0; 
    int lteOwdTxOffset = 0;

    //when resetting wifi/lteSplitFactor, please make sure the sum of these two equals paramL
    //and also reset wifiIndexChangeAlpha to 0
    int wifiSplitFactor; // k1 wifi
    int lteSplitFactor;// k2 lte
    long lastSplittingTime = 0; //traffic splitting stop time 
    long resetOWDoffsetTh_s = 30; //reset TX OWD offset 30 seconds after start sending traffic over a single link
    bool resetOWDoffsetFlag = false; //a flag to control resetting TX OWD offset 
    int gLvalue;
    int wifiIndexChangeAlpha; // +n stand for wifi index continuous increases n times, -m stands for wifi index continuous decreases for m times
    // end measurement manager

    int wifiRssi;
    int lteRssi;

    bool ENABLE_LINK_REORDERING;
    int maxReorderingDelay; //unit: ms
    long reorderStopTime;
    int currentTimeMs; //unit: ms --> when a connection is established, the currentTimeMs starts from 0. E.g., currentTimeMs = currentSysTimeMs + gStartTime. Use this for computing time stamp, one-way delay etc.
    int currentSysTimeMs; //unit: ms
  
    int numOfTsuMessages; // the number of transmitted TSU messages
    int numOfReorderingTimeout; // the number of reordering timeouts
    int numOfReorderingOverflow; // the number of reordering buffer overflows
    int maxReorderingPktRate; // the maximum reordering rate

    int numOfWifiLinkFailure;
    int numOfLteLinkFailure;
    int numOfTsuLinkFailure;

    bool stopLterequest;
    int key;

    int controlMsgSn; //we will use the sn for all control msgs (2Bytes)
    int wifiCid;
    int lteCid;
    int wakeupMsgSegWaitTimeout; //ms the max waiting time for a not completed wakeup msg

    std::string aesKey;
    std::string aesKeyString = "";
    bool enable_encryption;
    std::string uniqueSessionId = "";
   
    std::string wifiIpv4Address;
    std::string lteIpv4Address;
    std::string lteDnsv4Address;

    int edgeDNS;

    bool driverMonitorOn;
    
    std::string serverWifiTunnelIp = "";
    int serverWifiTunnelPort = 0;
    bool serverWifiHeaderOpt = false;
    int clientWifiAdaptPort = 0;
    int clientId = 0;
    int serverUdpPort = 0;
    int serverTcpPort = 0;
    std::string serverVnicIp = "";
    std::string serverVnicGw = "";
    std::string serverVnicMsk = "";
    std::string serverVnicDns = "";
    std::string serverLteTunnelIp = "";
    int serverLteTunnelPort = 0;
    bool serverLteHeaderOpt = false;
    int clientProbePort = 0;
    int clientLteAdaptPort = 0;
    int vnicWebsocketPort = 0;


    char server_ncm_ip[20] = {0};
    int server_ncm_port = 0;
    char wifi_interface[100] = {0};
    char lte_interface[100] = {0};
    char domain[100] = {0};
    bool vnicInit = false;
    bool isControlManager = true;
    
    int HRBufferSize = 500;  //pkts
    int HRreorderingTimeout = 50; //ms

    int rttThLow = 999;
    int rttThHigh = 1000;
    int rssiInterval = 1; 
    int logsEnabled = 0; //0: log disable 1: logging via printf 2: logging via file
    std::string serverlteIpv4Address = "";
    FILE *pLogFile = NULL;
    std::string logPath = "";

    SystemStateSettings();
    void updateSystemSettings();
    void GMAIPCMessage(int code, int x1, int x2, bool x3, unsigned char x4);
    int tunwrite(char* buf, int pkt_len);
    void PrintLogs(std::stringstream &ss);
    void mHandler(int signum);
    void msleep(int value);
    void terminateThread(std::thread::native_handle_type handle);
    unsigned int update_current_time_params();
    int GetLinkBitmap();

    bool LogFileOpen();
    void LogFileClose();

    int GetWifiBssid(unsigned char* bssidBuf);
    int GetWifiRssiStrength();

    void closegmasocket(GMASocket sk);

};


#endif