//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : SystemStateSettings.cpp

#include "../GMAlib/include/SystemStateSettings.h"
#include <string.h>
#include <climits>
#include <ctime>
#include <memory>
#include <iostream>
#include <thread>
#include <pthread.h>
#include <unistd.h>
#include "Client.h"
#include "ServiceManager.h"
#include "Methods.h"

SystemStateSettings::SystemStateSettings()
{

    gNetWorkInterfaceMinMTU = 1400; //a configurable WLAN/LTE network MTU size
    gDynamicSplitFlag = 0;
    gLteAlwaysOnFlag = 0;
    lteRssiMeasurement = 0;
    allowAppListEnable = 1;
    gUlDuplicateFlag = 0;
    gUlRToverLteFlag = 0;
    gDlRToverLteFlag = 0;
    congestDetectLossThreshold = 0.0001; //10^(-n)  4--> 0.0001
    congestDetectUtilizationThreshold = 0.8;
    lteProbeIntervalActive = 300; //seconds
    WiFiProbeIntervalActive = 50; //seconds
    paramL = 32;                  // sum of splitting index of lte and wifi, should not be changed
    wifiLowRssi = -85;
    wifiHighRssi = -80;
    MRPintervalActive = 60;        //unit: seconds
    MRPintervalIdle = 300;         //unit: seconds
    MRPsize = 40;                  //40;
    MAX_MAXREORDERINGDELAY = 1000; // 1s
    MIN_MAXREORDERINGDELAY = 100;  //100ms
    reorderBufferSize = 1000;      //unit: pkt (default = 200)
    reorderLsnEnhanceFlag = 0;     //1: enable (default)  0: disable
    reorderDropOutOfOrderPkt = 0;  //1: enable 0: disable (default)
    minTpt = 10;                   //10kBps
    idleTimer = 1;                 //minutes
    wifiOwdOffsetMax = 100;        //  .
    lteProbeIntervalScreenOff = 3600;
    lteProbeIntervalScreenOn = 3600;
    wifiProbeIntervalScreenOff = 3600;
    wifiProbeIntervalScreenOn = 3600;

    OWD_CONVERGE_THRESHOLD = 0.1;         // if the owd difference of two consecutive measure interval is smaller than this threshold, we assume measurement converges.
    MAX_MEASURE_INTERVAL_NUM = 10;        // max allowed measurement interval if the results do not converges.
    MIN_PACKET_NUM_PER_INTERVAL = 300;    //when a interval end (due to time expires) without enough packets, it will be extended until more than this number of packets are received
    MAX_MEASURE_INTERVAL_DURATION = 2000; //1s
    MIN_MEASURE_INTERVAL_DURATION = 100;  //100 ms
    BURST_SAMPLE_FREQUENCY = 3;           //take one measurement very BUSRT_SAMPLE_FREQUENCY for packet burst rate estimate
    MAX_RATE_ESTIMATE = 1000000;          //kBps, the maximum rate estimate if no congestion happens
    RATE_ESTIMATE_K = 105;                //kBps, the maximum rate estimate if no congestion happens
    MIN_PACKET_COUNT_PER_BURST = 30;      //if we measure this number of continues delay increase, we estimate a burst rate in this interval
    BURST_INCREASING_ALPHA = 0.5;         //assume the delay is increasing as long as the new delay is bigger than (1-alpha)* D_MIN + alpha * D_MAX (reference our IDF)
    STEP_ALPHA_THRESHOLD = 4;             //after alphaThreshold continuous increase/decrease, increase the step size linearly. (from 1 to 2, 3, ..)
    TOLERANCE_LOSS_BOUND = 2;
    TOLERANCE_DELAY_BOUND = 5;
    TOLERANCE_DELAY_H = 8;                    //decrease wifi
    TOLERANCE_DELAY_L = 4;                    //increase wifi
    SPLIT_ALGORITHM = 2;                      //1: delay algorithm; 2: delay and loss algorithm
    INITIAL_PACKETS_BEFORE_LOSS = 1000000000; //10^9
    //end/////////////////////////////////////////

    minPktsample = 10;      //minimum number of samples for a valid OWD measurement
    wifiOwdOffset = 0;      //we will compare wifiOwd + wifiOwdOffset with lteOwd. If we want to allocate more traffic over wifi, set this offset to be a negative value.
    reorderRepeatTimer = 3; //unit: ms
    reorderRepeatNum = 2;
    gmaMTUsize = 1500;
    sizeofGMAMessageHeader = 2;
    sizeofDlGMAMessageHeader = 4;
    sizeofDlGmaDataHeader = 14;
    sizeofUlGmaDataHeader = 12;

    MRPinterval = 3; //unit: seconds

    wifiProbeTimeout = 2000;      //unit: ms
    reorderPktRateInitValue = 20; //unit: k packet per seconds 20 x 1400 B = 224Mbps

    gVnicMTU = 1000;
    gLteMTU = 1500;
    gWifiFlag = false;
    gLteFlag = false;
    gIsWifiConnect = false;
    gIsLteConnect = false;
    gTunAvailable = false;
    gISVirtualWebsocket = false;
    gStartTime = -1; //the default value = -1

    gDLAllOverLte = false;
    gScreenOnFlag = true;
    gDisconnectWifiTime = 0;
    gDisconnectLteTime = 0;
    gLastScreenOffTime = 0;

    lastReceiveWifiWakeUpReq = 0;
    lastReceiveLteWakeUpReq = 0;
    lastReceiveLteProbe = 0;
    lastReceiveWifiProbe = 0;
    lastReceiveWifiPkt = 0;
    lastReceiveLtePkt = 0;
    wifiProbeTh = INT_MAX; //the minimum gap between last receive and last transmit astReceiveWifiPkt
    lastSendWifiProbe = 0;
    lastSendLteProbe = 0;
    wifiLinkRtt = 1000;
    wifiLinkMaxRtt = 0;
    lteLinkRtt = 2000;
    splitEnable = 0;

    lteReceiveNrtBytes = 0;
    lteSendBytes = 0;
    wifiReceiveNrtBytes = 0;
    wifiSendBytes = 0;

    //Realtime
    lteReceiveRtBytes = 0;
    wifiReceiveRtBytes = 0;

    nonRealtimelModeFlowId = 3; //dl: splitting traffic; ul:wifi only it wifi is available, otherwise lte
    realtimeModeFlowId = 2;     //no aggregation, select LTE or WIFI, both uplink and downlink
    ulDuplicateModeFlowId = 1;  //duplicate packets over both lte and wifi.

    icmpFlowType = 3;    //default
    tcpRTportStart = 0;  //default
    tcpRTportEnd = 0;    //default
    tcpHRportStart = 0;  //default
    tcpHRportEnd = 0;    //default
    udpRTportStart = 0;  //default
    udpRTportEnd = 0;    //default
    udpHRportStart = 0;  //default
    udpHRportEnd = 0;    //default
    ulQoSFlowEnable = 0; //default

    //measurement manager measures the following parameters, they are normal packets
    wifiOwdSum = 0;    //control and data
    wifiPacketNum = 0; //control and data
    wifiOwdMax = INT_MIN;
    wifiOwdMin = INT_MAX;
    wifiInorderPacketNum = 0;  //data only
    wifiMissingPacketNum = 0;  //data only
    wifiAbnormalPacketNum = 0; //data only
    wifiRate = 100;            //data only

    ENABLE_FLOW_MEASUREMENT = true;
    flowInorderPacketNum = 0;  //data only
    flowMissingPacketNum = 0;  //data only
    flowAbnormalPacketNum = 0; //data only
    flowOwdMax = INT_MIN;      //data only
    flowOwdMin = INT_MAX;      //data only
    flowOwdSum = 0;            //data only
    flowOwdPacketNum = 0;      //data only

    lteOwdSum = 0;    //control and data
    ltePacketNum = 0; //control and data
    lteOwdMax = INT_MIN;
    lteOwdMin = INT_MAX;
    lteInorderPacketNum = 0;  //data only
    lteMissingPacketNum = 0;  //data only
    lteAbnormalPacketNum = 0; //data only
    lteRate = 100;            //data only

    //realtime
    wifiRtOwdSum = 0;    //control and data
    wifiRtPacketNum = 0; //control and data
    wifiRtOwdMax = INT_MIN;
    wifiRtOwdMin = INT_MAX;


    lteRtOwdSum = 0;    //control and data
    lteRtPacketNum = 0; //control and data
    lteRtOwdMax = INT_MIN;
    lteRtOwdMin = INT_MAX;

    wifiRtInorderPacketNum = 0;  //data only
    wifiRtMissingPacketNum = 0;  //data only
    wifiRtAbnormalPacketNum = 0; //data only

    lteRtInorderPacketNum = 0;  //data only
    lteRtMissingPacketNum = 0;  //data only
    lteRtAbnormalPacketNum = 0; //data only

    //when resetting wifi/lteSplitFactor, please make sure the sum of these two equals paramL
    //and also reset wifiIndexChangeAlpha to 0
    wifiSplitFactor = paramL; // k1 wifi
    lteSplitFactor = 0;       // k2 lte
    gLvalue = paramL;
    wifiIndexChangeAlpha = 0; // +n stand for wifi index continuous increases n times, -m stands for wifi index continuous decreases for m times
    // end measurement manager

    wifiRssi = 0;
    lteRssi = 0;

    ENABLE_LINK_REORDERING = true;
    maxReorderingDelay = MIN_MAXREORDERINGDELAY; //unit: ms
    reorderStopTime = 0;
    currentTimeMs = 0;    //unit: ms
    currentSysTimeMs = 0; //unit: ms
    
    numOfTsuMessages = 0;        // the number of transmitted TSU messages
    numOfReorderingTimeout = 0;  // the number of reordering timeouts
    numOfReorderingOverflow = 0; // the number of reordering buffer overflows
    maxReorderingPktRate = 20;   // the maximum reordering rate

    numOfWifiLinkFailure = 0;
    numOfLteLinkFailure = 0;
    numOfTsuLinkFailure = 0;

    stopLterequest = true;
    key = 0;

    controlMsgSn = 1; //we will use the sn for all control msgs (2Bytes)
    wifiCid = 0;
    lteCid = 3;
    wakeupMsgSegWaitTimeout = 10000; //ms the max waiting time for a not completed wakeup msg

    //public SecretKey aesKey;
    aesKey = "";
    enable_encryption = false;
    uniqueSessionId = "";
    aesKeyString = "";

    wifiIpv4Address = "0.0.0.0";
    lteIpv4Address = "0.0.0.0";
    lteDnsv4Address = "8.8.8.8";

    edgeDNS = 0;
    driverMonitorOn = false;
    lastSendLteTsu = 0;
    lastSendWifiTsu = 0;

    serverWifiTunnelIp = "";
    serverWifiTunnelPort = 0;
    serverWifiHeaderOpt = false;
    clientWifiAdaptPort = 0;
    clientId = 0;
    serverUdpPort = 0;
    serverTcpPort = 0;
    serverVnicIp = "";
    serverVnicGw = "";
    serverVnicMsk = "";
    serverVnicDns = "";
    serverLteTunnelIp = "";
    serverLteTunnelPort = 0;
    serverLteHeaderOpt = false;
    clientProbePort = 0;
    clientLteAdaptPort = 0;
    vnicWebsocketPort = 0;
    isControlManager = true;
}

void SystemStateSettings::updateSystemSettings()
{
    minPktsample = 10;      //minimum number of samples for a valid OWD measurement
    wifiOwdOffset = 0;      //we will compare wifiOwd + wifiOwdOffset with lteOwd. If we want to allocate more traffic over wifi, set this offset to be a negative value.
    reorderRepeatTimer = 3; //unit: ms
    reorderRepeatNum = 2;
    gmaMTUsize = 1500;
    sizeofGMAMessageHeader = 2;
    sizeofDlGMAMessageHeader = 4;
    sizeofDlGmaDataHeader = 14;
    sizeofUlGmaDataHeader = 12;

    MRPinterval = 3; //unit: seconds

    wifiProbeTimeout = 2000;      //unit: ms
    reorderPktRateInitValue = 20; //unit: k packet per seconds 20 x 1400 B = 224Mbps

    gVnicMTU = 0;
    gWifiFlag = false;
    gLteFlag = false;
    gIsWifiConnect = false;
    gIsLteConnect = false;
    gTunAvailable = false;
    gISVirtualWebsocket = false;
    gStartTime = -1; //JZ the default value = -1

    gDLAllOverLte = false;
    gScreenOnFlag = true;
    gDisconnectWifiTime = 0;
    gDisconnectLteTime = 0;
    gLastScreenOffTime = 0;

    lastReceiveWifiWakeUpReq = 0;
    lastReceiveLteWakeUpReq = 0;
    lastReceiveLteProbe = 0;
    lastReceiveWifiProbe = 0;
    lastReceiveWifiPkt = 0;
    lastReceiveLtePkt = 0;
    wifiProbeTh = INT_MAX; //the minimum gap between last receive and last transmit astReceiveWifiPkt
    lastSendWifiProbe = 0;
    lastSendLteProbe = 0;
    lastSendLteTsu = 0;
    lastSendWifiTsu = 0;

    wifiLinkRtt = 1000;
    wifiLinkMaxRtt = 0;
    lteLinkRtt = 2000;
    splitEnable = 0;

    lteReceiveNrtBytes = 0;
    lteSendBytes = 0;
    wifiReceiveNrtBytes = 0;
    wifiSendBytes = 0;

    //Realtime
    lteReceiveRtBytes = 0;
    wifiReceiveRtBytes = 0;

    nonRealtimelModeFlowId = 3; //dl: splitting traffic; ul:wifi only it wifi is available, otherwise lte
    realtimeModeFlowId = 2;     //no aggregation, select LTE or WIFI, both uplink and downlink
    ulDuplicateModeFlowId = 1;  //duplicate packets over both lte and wifi.

    
    //measurement manager measures the following parameters, they are normal packets
    wifiOwdSum = 0;    //control and data
    wifiPacketNum = 0; //control and data
    wifiOwdMax = INT_MIN;
    wifiOwdMin = INT_MAX;
    wifiInorderPacketNum = 0;  //data only
    wifiMissingPacketNum = 0;  //data only
    wifiAbnormalPacketNum = 0; //data only
    wifiRate = 100;            //data only
    //ENABLE_FLOW_MEASUREMENT = true;
    flowInorderPacketNum = 0;  //data only
    flowMissingPacketNum = 0;  //data only
    flowAbnormalPacketNum = 0; //data only
    flowOwdMax = INT_MIN;      //data only
    flowOwdMin = INT_MAX;      //data only
    flowOwdSum = 0;            //data only
    flowOwdPacketNum = 0;      //data only

    lteOwdSum = 0;    //control and data
    ltePacketNum = 0; //control and data
    lteOwdMax = INT_MIN;
    lteOwdMin = INT_MAX;
    lteInorderPacketNum = 0;  //data only
    lteMissingPacketNum = 0;  //data only
    lteAbnormalPacketNum = 0; //data only
    lteRate = 100;            //data only

    //realtime
    wifiRtOwdSum = 0;    //control and data
    wifiRtPacketNum = 0; //control and data
    wifiRtOwdMax = INT_MIN;
    wifiRtOwdMin = INT_MAX;

    lteRtOwdSum = 0;    //control and data
    lteRtPacketNum = 0; //control and data
    lteRtOwdMax = INT_MIN;
    lteRtOwdMin = INT_MAX;

    wifiRtInorderPacketNum = 0;  //data only
    wifiRtMissingPacketNum = 0;  //data only
    wifiRtAbnormalPacketNum = 0; //data only

    lteRtInorderPacketNum = 0;  //data only
    lteRtMissingPacketNum = 0;  //data only
    lteRtAbnormalPacketNum = 0; //data only

    //when resetting wifi/lteSplitFactor, please make sure the sum of these two equals paramL
    //and also reset wifiIndexChangeAlpha to 0
    wifiSplitFactor = paramL; // k1 wifi
    lteSplitFactor = 0;       // k2 lte
    gLvalue = paramL;
    wifiIndexChangeAlpha = 0; // +n stand for wifi index continuous increases n times, -m stands for wifi index continuous decreases for m times
    // end measurement manager

    wifiRssi = 0;
    lteRssi = 0;

    ENABLE_LINK_REORDERING = true;
    maxReorderingDelay = MIN_MAXREORDERINGDELAY; //unit: ms
    reorderStopTime = 0;
    currentTimeMs = 0;    //unit: ms
    currentSysTimeMs = 0; //unit: ms

    numOfTsuMessages = 0;        // the number of transmitted TSU messages
    numOfReorderingTimeout = 0;  // the number of reordering timeouts
    numOfReorderingOverflow = 0; // the number of reordering buffer overflows
    maxReorderingPktRate = 20;   // the maximum reordering rate

    numOfWifiLinkFailure = 0;
    numOfLteLinkFailure = 0;
    numOfTsuLinkFailure = 0;

    stopLterequest = true;

    controlMsgSn = 1; //we will use the sn for all control msgs (2Bytes)
    wifiCid = 0;
    lteCid = 3;
    wakeupMsgSegWaitTimeout = 10000; //ms the max waiting time for a not completed wakeup msg

}

void SystemStateSettings::GMAIPCMessage(int code, int x1, int x2, bool x3, unsigned char x4)
{
    switch (code)
    {
    case 1:
        serviceManager.controlManager.sendTSUMsg();
        break;
    case 2:

        serviceManager.controlManager.sendWifiProbe();
        break;
    case 3:
        serviceManager.controlManager.sendLteProbe();
        break;
    case 4:
        serviceManager.controlManager.receiveWifiTSA(x1, x2);
        break;
    case 5:
        serviceManager.controlManager.receiveLteTSA(x1, x2);
        break;
    case 6:
        serviceManager.controlManager.receiveWifiProbeAck(x1);
        break;
    case 7:
        serviceManager.controlManager.receiveLteProbeAck(x1);
        break;
    case 8:
        serviceManager.controlManager.SendACK(x4);
        break;
    case 9:
        serviceManager.controlManager.notifyLRPCycle(x3, x4);
        break;
    case 10:
        serviceManager.updateWifiChannel();
        break;
    case 11:
        serviceManager.updateLteChannel();
        break;
    case 12:
        serviceManager.OpenLteTcpSocketChannel(); //open a lte tcp socket channel if not open yet
        break;
    case 13:
        serviceManager.OpenWifiTcpSocketChannel();
        break;
    case 14:
        serviceManager.CloseWifiTcpSocketChannel();
        break;
    case 15:
        serviceManager.CloseLteTcpSocketChannel();
        break;
    case 16: 
        serviceManager.dataReceive.reorderingManager.hrReorderingWorker.updateReorderingTimer(x1);
        serviceManager.dataReceive.reorderingManager.nrtReorderingWorker.updateReorderingTimer(x2);
        break;
    default:
        std::cout << "Invalid GMAIPCMessage Code!!!\n";
        break;
    }
}

int SystemStateSettings::tunwrite(char* buf, int pkt_len)
{
    return (serviceManager.tun_write(buf, pkt_len)); //linux
}


void SystemStateSettings::PrintLogs(std::stringstream &ss)
{
    switch (this->logsEnabled)
    {
    case 1:
        std::cout << ss.str();
        break; //logging via printf
    case 2:
        if (this->pLogFile)
        {
            fputs(ss.str().c_str(), this->pLogFile);
            fflush(this->pLogFile);
        }
        break; //logging via file
    default:
        break; //no logging
    }
}

void SystemStateSettings::mHandler(int signum)
{
    std::thread eventThread(&ServiceManager::handler, &serviceManager, signum);
    eventThread.detach();
}

void SystemStateSettings::msleep(int value) //sleep milliseconds
{
    usleep(value * 1000); //linux: usleep(us)
}

void SystemStateSettings::terminateThread(std::thread::native_handle_type handle)
{
    pthread_cancel(handle);  //Linux
}

unsigned int SystemStateSettings::update_current_time_params()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned int g_time_param_ms = (unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);

    return g_time_param_ms;
}

int SystemStateSettings::GetLinkBitmap()
{
    int linkBitmap = 0;
    if (this->gIsWifiConnect)
    {
        linkBitmap += 1; //first bit
    }
    if (this->gIsLteConnect)
    {
        linkBitmap += 2; // second bit
    }
    return linkBitmap;
}

bool SystemStateSettings::LogFileOpen()
{
	 if (this->logsEnabled == 2)
    {
		std::string prefixPath = "/home/gmaclient/gma-";
		std::time_t rawtime;
		std::tm *timeinfo;
        char tmbuf[80] = "11111111";
		std::time(&rawtime);
		timeinfo = std::localtime(&rawtime);
        if (timeinfo != NULL)
        {
            std::strftime(tmbuf, 80, "%Y%m%d", timeinfo);
        }
        std::string tmstr = std::string(tmbuf);
		this->logPath = prefixPath + tmstr + ".log";

		LogFileClose();

		pLogFile = fopen(this->logPath.c_str(), "a+");
		if (pLogFile == NULL)
			return false;
	}
    return true;
}

void SystemStateSettings::LogFileClose()
{
    if (this->pLogFile != NULL)
    {
        fclose(this->pLogFile);
        this->pLogFile = NULL;
    }
}

int SystemStateSettings::GetWifiBssid(unsigned char *bssidBuf)
{
    FILE *fp;
    char buf[50] = {0};
    std::string cmd = "iw " + std::string(this->wifi_interface) + " link | grep Connected | awk \'{print $3}\'";
    fp = popen_with_return(cmd.c_str(), cmd.size());
    if (fp != NULL)
    {
        fgets(buf, sizeof(buf), fp);
        pclose(fp);
        if (strlen(buf) > 0)
        {
            std::istringstream iss(buf);
            std::vector<std::string> ssidArray;
            std::string item;
            while (std::getline(iss, item, ':'))
            {
                ssidArray.push_back(item);
            }
            for (int k = 0; k < ssidArray.size(); k++)
            {
                bssidBuf[k] = (unsigned char)std::stoi(ssidArray[k], nullptr, 16); //base hex=16
            }
            return 1;
        }
        else
            return 0;
    }
    return 0;
}

int SystemStateSettings::GetWifiRssiStrength()
{
    FILE *fp;
    int value = 0;
    char buffer[200] = {0};
    std::string cmd = "iw dev " + std::string(this->wifi_interface) + " link | grep signal";
    fp = popen_with_return(cmd.c_str(), cmd.size());
    if (fp != NULL)
    {
        fgets(buffer, sizeof(buffer), fp);
        pclose(fp);
    }
    if (strlen(buffer) > 0) //get info from iw dev command
    {
        std::istringstream iss(buffer);
        std::vector<std::string> tokens{std::istream_iterator<std::string>(iss),
                                        std::istream_iterator<std::string>()};
        value = std::stoi(tokens[1]);
        iss.clear();
    }
    else
    {
        value = -60; //default rssi is -60
    }
    return value;
}



void SystemStateSettings::closegmasocket(GMASocket sk)
{
    close(sk);  //linux
}
