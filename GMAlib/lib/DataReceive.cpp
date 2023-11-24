//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : DataReceive.cpp



#if defined(__unix__) || defined(__APPLE__)
#include <linux/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#elif defined(_WIN32) || defined(_WIN64) 
#define NOMINMAX
#endif


#include <cmath>
#include <iostream>
#include <sstream>
#include <functional>
#include <errno.h>

#include "../include/DataReceive.h"
#include "../include/Header.h"
#include "../include/SystemStateSettings.h"

DataReceive::DataReceive()
{
    dataOffset = 0;
    maxPktLen = 0;
    nextWifiRtSn = 0;
    nextLteRtSn = 0;
    nextWifiHrSn = 0;
    nextLteHrSn = 0;
    wifiudp_fd = GMA_INVALID_SOCKET;
    lteudp_fd = GMA_INVALID_SOCKET;
    udpLoop = GMA_INVALID_SOCKET;
}

void DataReceive::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
    maxPktLen = p_systemStateSettings->gmaMTUsize - p_systemStateSettings->sizeofDlGmaDataHeader;
    reorderingManager.initUnitSystemStateSettings(p_systemStateSettings);
    measurementManager.initUnitSystemStateSettings(p_systemStateSettings);
}

void DataReceive::ExitThread()
{
    if (udpLoop != GMA_INVALID_SOCKET)
    {
        p_systemStateSettings->closegmasocket(udpLoop);
    }
    udpLoop = GMA_INVALID_SOCKET;
    
    ThreadBusy = false;
}

void DataReceive::wakeupSelect()
{
    if (udpLoop != GMA_INVALID_SOCKET)
    {
        char buf[1];
        buf[0] = 'x';
        if (sendto(udpLoop, (char *)buf, 1, 0, (struct sockaddr *)&udpAddr, sizeof(udpAddr)) <= 0)
         printf("\n sendto error \n");
    }
}

void DataReceive::listenSockets()
{
    ThreadBusy = true;
    fd_set socks;
    GMASocket nsocks;
    int nBytes;
    char pipebuff[100];
    while ((p_systemStateSettings->gWifiFlag || p_systemStateSettings->gLteFlag) && p_systemStateSettings->isControlManager) //gSystemOn
    {

        FD_ZERO(&socks);
        if (lteudp_fd != GMA_INVALID_SOCKET)
            FD_SET(lteudp_fd, &socks);
        if (wifiudp_fd != GMA_INVALID_SOCKET)
            FD_SET(wifiudp_fd, &socks);
        if (udpLoop != GMA_INVALID_SOCKET)
            FD_SET(udpLoop, &socks);

        nsocks = std::max(std::max(wifiudp_fd, lteudp_fd), udpLoop) + 1;

        if (select(nsocks, &socks, (fd_set *)0, (fd_set *)0, 0) > 0)
        {

            if (wifiudp_fd != GMA_INVALID_SOCKET && FD_ISSET(wifiudp_fd, &socks))
            {
                char *packet = reorderingManager.requestBuffer();
                nBytes = recvfrom(wifiudp_fd, packet, 1500, 0, NULL, NULL);
                receiveWifiPacket(packet);
            }
            if (lteudp_fd != GMA_INVALID_SOCKET && FD_ISSET(lteudp_fd, &socks))
            {
                char *packet = reorderingManager.requestBuffer();
                nBytes = recvfrom(lteudp_fd, packet, 1500, 0, NULL, NULL);
                receiveLtePacket(packet);
            }
            if (udpLoop != GMA_INVALID_SOCKET && FD_ISSET(udpLoop, &socks))
            {
                int ret;
                char udpBuf[100];
                ret = recv(udpLoop, udpBuf, 100, 0);
                if (ret <= 0)
                {
                    //connection gracefully closed
                    p_systemStateSettings->closegmasocket(udpLoop);
                    udpLoop = GMA_INVALID_SOCKET;
                    setupUdpSocket(); //suppose success
                }
                std::stringstream logs;
                logs.str("");
                logs << "data receive wake up select and break....\n";
                p_systemStateSettings->PrintLogs(logs);
            }
        }
    }

    ThreadBusy = false;
}

void DataReceive::receiveWifiControl(char *packet)
{
    vnicAck.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
    int seqNumber = -1;
    switch (vnicAck.getType())
    {
    case 0x000000FF:
    {
        reqMessage.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
        if (reqMessage.getSubType() == 4)
        {
            //controlManager.SendACK(4);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 4);
            
            tscMessage.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
            switch (tscMessage.getULDuplicationEnabled())
            {
            case 0:
                p_systemStateSettings->gUlRToverLteFlag = 0;
                p_systemStateSettings->gDlRToverLteFlag = 0;
                break;
            case 1:
                p_systemStateSettings->gUlRToverLteFlag = 0;
                p_systemStateSettings->gDlRToverLteFlag = 1;
                break;
            case 2:
                p_systemStateSettings->gUlRToverLteFlag = 1;
                p_systemStateSettings->gDlRToverLteFlag = 0;
                break;
            case 3:
                p_systemStateSettings->gUlRToverLteFlag = 1;
                p_systemStateSettings->gDlRToverLteFlag = 1;
                break;
            default:
                break; //do not update for RT if > 3
            }

            if (p_systemStateSettings->gDlRToverLteFlag == 1)
            {
                p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe();
            }

            if (tscMessage.getDLDynamicSplittingEnabled() < 16) //do not update traffic splitting configurations for NRT if > 16
            {
                if (tscMessage.getDLDynamicSplittingEnabled() == 0)
                    p_systemStateSettings->gDynamicSplitFlag = 0;
                else
                {
                    p_systemStateSettings->gDynamicSplitFlag = 1;
                    p_systemStateSettings->SPLIT_ALGORITHM = tscMessage.getDLDynamicSplittingEnabled();
                }
                p_systemStateSettings->wifiSplitFactor = tscMessage.getK1();
                p_systemStateSettings->lteSplitFactor = tscMessage.getK2();
                p_systemStateSettings->paramL = tscMessage.getL();
            }
            p_systemStateSettings->GMAIPCMessage(1,0,0,false,0); //controlManager.sendTSUMsg();
        }
        else if (reqMessage.getSubType() == 5)
        {
            //controlManager.SendACK(5);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 5);

            int offset = dataOffset + p_systemStateSettings->sizeofGMAMessageHeader + 6; //what is this 6 bytes?
            p_systemStateSettings->gNetWorkInterfaceMinMTU = ((unsigned int)(packet[offset + 3]) << 24 | (unsigned int)(packet[offset + 2]) << 16 | (unsigned int)(packet[offset + 1]) << 8 | (unsigned int)(packet[offset + 0]));
            p_systemStateSettings->gDynamicSplitFlag = ((unsigned int)(packet[offset + 7]) << 24 | (unsigned int)(packet[offset + 6]) << 16 | (unsigned int)(packet[offset + 5]) << 8 | (unsigned int)(packet[offset + 4]));
            p_systemStateSettings->gLteAlwaysOnFlag = ((unsigned int)(packet[offset + 11]) << 24 | (unsigned int)(packet[offset + 10]) << 16 | (unsigned int)(packet[offset + 9]) << 8 | (unsigned int)(packet[offset + 8]));
            int x = ((unsigned int)(packet[offset + 15]) << 24 | (unsigned int)(packet[offset + 14]) << 16 | (unsigned int)(packet[offset + 13]) << 8 | (unsigned int)(packet[offset + 12]));
            p_systemStateSettings->congestDetectLossThreshold = std::pow(10, 0 - (double)x);
            x = ((unsigned int)(packet[offset + 19]) << 24 | (unsigned int)(packet[offset + 18]) << 16 | (unsigned int)(packet[offset + 17]) << 8 | (unsigned int)(packet[offset + 16]));
            p_systemStateSettings->congestDetectUtilizationThreshold = ((double)x) / 100;

            p_systemStateSettings->lteProbeIntervalScreenOff = ((unsigned int)(packet[offset + 23]) << 24 | (unsigned int)(packet[offset + 22]) << 16 | (unsigned int)(packet[offset + 21]) << 8 | (unsigned int)(packet[offset + 20]));
            p_systemStateSettings->lteProbeIntervalScreenOn = ((unsigned int)(packet[offset + 27]) << 24 | (unsigned int)(packet[offset + 26]) << 16 | (unsigned int)(packet[offset + 25]) << 8 | (unsigned int)(packet[offset + 24]));
            p_systemStateSettings->lteProbeIntervalActive = ((unsigned int)(packet[offset + 31]) << 24 | (unsigned int)(packet[offset + 30]) << 16 | (unsigned int)(packet[offset + 29]) << 8 | (unsigned int)(packet[offset + 28]));
            p_systemStateSettings->lteRssiMeasurement = ((unsigned int)(packet[offset + 35]) << 24 | (unsigned int)(packet[offset + 34]) << 16 | (unsigned int)(packet[offset + 33]) << 8 | (unsigned int)(packet[offset + 32]));
            p_systemStateSettings->wifiProbeIntervalScreenOff = ((unsigned int)(packet[offset + 39]) << 24 | (unsigned int)(packet[offset + 38]) << 16 | (unsigned int)(packet[offset + 37]) << 8 | (unsigned int)(packet[offset + 36]));
            p_systemStateSettings->wifiProbeIntervalScreenOn = ((unsigned int)(packet[offset + 43]) << 24 | (unsigned int)(packet[offset + 42]) << 16 | (unsigned int)(packet[offset + 41]) << 8 | (unsigned int)(packet[offset + 40]));
            p_systemStateSettings->WiFiProbeIntervalActive = ((unsigned int)(packet[offset + 47]) << 24 | (unsigned int)(packet[offset + 46]) << 16 | (unsigned int)(packet[offset + 45]) << 8 | (unsigned int)(packet[offset + 44]));
            p_systemStateSettings->paramL = ((unsigned int)(packet[offset + 51]) << 24 | (unsigned int)(packet[offset + 50]) << 16 | (unsigned int)(packet[offset + 49]) << 8 | (unsigned int)(packet[offset + 48]));
            p_systemStateSettings->wifiLowRssi = ((unsigned int)(packet[offset + 55]) << 24 | (unsigned int)(packet[offset + 54]) << 16 | (unsigned int)(packet[offset + 53]) << 8 | (unsigned int)(packet[offset + 52]));
            p_systemStateSettings->wifiHighRssi = ((unsigned int)(packet[offset + 59]) << 24 | (unsigned int)(packet[offset + 58]) << 16 | (unsigned int)(packet[offset + 57]) << 8 | (unsigned int)(packet[offset + 56]));
            p_systemStateSettings->MRPintervalActive = ((unsigned int)(packet[offset + 63]) << 24 | (unsigned int)(packet[offset + 62]) << 16 | (unsigned int)(packet[offset + 61]) << 8 | (unsigned int)(packet[offset + 60]));
            p_systemStateSettings->MRPintervalIdle = ((unsigned int)(packet[offset + 67]) << 24 | (unsigned int)(packet[offset + 66]) << 16 | (unsigned int)(packet[offset + 65]) << 8 | (unsigned int)(packet[offset + 64]));
            p_systemStateSettings->MRPsize = ((unsigned int)(packet[offset + 71]) << 24 | (unsigned int)(packet[offset + 70]) << 16 | (unsigned int)(packet[offset + 69]) << 8 | (unsigned int)(packet[offset + 68]));
            p_systemStateSettings->MAX_MAXREORDERINGDELAY = ((unsigned int)(packet[offset + 75]) << 24 | (unsigned int)(packet[offset + 74]) << 16 | (unsigned int)(packet[offset + 73]) << 8 | (unsigned int)(packet[offset + 72]));
            p_systemStateSettings->MIN_MAXREORDERINGDELAY = ((unsigned int)(packet[offset + 79]) << 24 | (unsigned int)(packet[offset + 78]) << 16 | (unsigned int)(packet[offset + 77]) << 8 | (unsigned int)(packet[offset + 76]));
            p_systemStateSettings->reorderBufferSize = ((unsigned int)(packet[offset + 83]) << 24 | (unsigned int)(packet[offset + 82]) << 16 | (unsigned int)(packet[offset + 81]) << 8 | (unsigned int)(packet[offset + 80]));
            p_systemStateSettings->reorderLsnEnhanceFlag = ((unsigned int)(packet[offset + 87]) << 24 | (unsigned int)(packet[offset + 86]) << 16 | (unsigned int)(packet[offset + 85]) << 8 | (unsigned int)(packet[offset + 84]));
            p_systemStateSettings->reorderDropOutOfOrderPkt = ((unsigned int)(packet[offset + 91]) << 24 | (unsigned int)(packet[offset + 90]) << 16 | (unsigned int)(packet[offset + 89]) << 8 | (unsigned int)(packet[offset + 88]));
            p_systemStateSettings->minTpt = ((unsigned int)(packet[offset + 95]) << 24 | (unsigned int)(packet[offset + 94]) << 16 | (unsigned int)(packet[offset + 93]) << 8 | (unsigned int)(packet[offset + 92]));
            p_systemStateSettings->idleTimer = ((unsigned int)(packet[offset + 99]) << 24 | (unsigned int)(packet[offset + 98]) << 16 | (unsigned int)(packet[offset + 97]) << 8 | (unsigned int)(packet[offset + 96]));
            p_systemStateSettings->allowAppListEnable = ((unsigned int)(packet[offset + 103]) << 24 | (unsigned int)(packet[offset + 102]) << 16 | (unsigned int)(packet[offset + 101]) << 8 | (unsigned int)(packet[offset + 100]));
            p_systemStateSettings->wifiOwdOffsetMax = ((unsigned int)(packet[offset + 107]) << 24 | (unsigned int)(packet[offset + 106]) << 16 | (unsigned int)(packet[offset + 105]) << 8 | (unsigned int)(packet[offset + 104]));
            p_systemStateSettings->gUlDuplicateFlag = ((unsigned int)(packet[offset + 111]) << 24 | (unsigned int)(packet[offset + 110]) << 16 | (unsigned int)(packet[offset + 109]) << 8 | (unsigned int)(packet[offset + 108]));

            x = ((unsigned int)(packet[offset + 115]) << 24 | (unsigned int)(packet[offset + 114]) << 16 | (unsigned int)(packet[offset + 113]) << 8 | (unsigned int)(packet[offset + 112]));
            p_systemStateSettings->OWD_CONVERGE_THRESHOLD = ((double)x) / 100;

            p_systemStateSettings->MAX_MEASURE_INTERVAL_NUM = ((unsigned int)(packet[offset + 119]) << 24 | (unsigned int)(packet[offset + 118]) << 16 | (unsigned int)(packet[offset + 117]) << 8 | (unsigned int)(packet[offset + 116]));
            p_systemStateSettings->MIN_PACKET_NUM_PER_INTERVAL = ((unsigned int)(packet[offset + 123]) << 24 | (unsigned int)(packet[offset + 122]) << 16 | (unsigned int)(packet[offset + 121]) << 8 | (unsigned int)(packet[offset + 120]));
            p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION = ((unsigned int)(packet[offset + 127]) << 24 | (unsigned int)(packet[offset + 126]) << 16 | (unsigned int)(packet[offset + 125]) << 8 | (unsigned int)(packet[offset + 124]));
            p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION = ((unsigned int)(packet[offset + 131]) << 24 | (unsigned int)(packet[offset + 130]) << 16 | (unsigned int)(packet[offset + 129]) << 8 | (unsigned int)(packet[offset + 128]));
            p_systemStateSettings->BURST_SAMPLE_FREQUENCY = ((unsigned int)(packet[offset + 135]) << 24 | (unsigned int)(packet[offset + 134]) << 16 | (unsigned int)(packet[offset + 133]) << 8 | (unsigned int)(packet[offset + 132]));
            p_systemStateSettings->MAX_RATE_ESTIMATE = ((unsigned int)(packet[offset + 139]) << 24 | (unsigned int)(packet[offset + 138]) << 16 | (unsigned int)(packet[offset + 137]) << 8 | (unsigned int)(packet[offset + 136]));
            p_systemStateSettings->RATE_ESTIMATE_K = ((unsigned int)(packet[offset + 143]) << 24 | (unsigned int)(packet[offset + 142]) << 16 | (unsigned int)(packet[offset + 141]) << 8 | (unsigned int)(packet[offset + 140]));
            p_systemStateSettings->MIN_PACKET_COUNT_PER_BURST = ((unsigned int)(packet[offset + 147]) << 24 | (unsigned int)(packet[offset + 146]) << 16 | (unsigned int)(packet[offset + 145]) << 8 | (unsigned int)(packet[offset + 144]));
            x = ((unsigned int)(packet[offset + 151]) << 24 | (unsigned int)(packet[offset + 150]) << 16 | (unsigned int)(packet[offset + 149]) << 8 | (unsigned int)(packet[offset + 148]));
            p_systemStateSettings->BURST_INCREASING_ALPHA = ((double)x) / 100;

            p_systemStateSettings->STEP_ALPHA_THRESHOLD = ((unsigned int)(packet[offset + 155]) << 24 | (unsigned int)(packet[offset + 154]) << 16 | (unsigned int)(packet[offset + 153]) << 8 | (unsigned int)(packet[offset + 152]));

            p_systemStateSettings->TOLERANCE_LOSS_BOUND = ((unsigned int)(packet[offset + 159]) << 24 | (unsigned int)(packet[offset + 158]) << 16 | (unsigned int)(packet[offset + 157]) << 8 | (unsigned int)(packet[offset + 156]));
            p_systemStateSettings->TOLERANCE_DELAY_BOUND = ((unsigned int)(packet[offset + 163]) << 24 | (unsigned int)(packet[offset + 162]) << 16 | (unsigned int)(packet[offset + 161]) << 8 | (unsigned int)(packet[offset + 160]));
            p_systemStateSettings->TOLERANCE_DELAY_H = ((unsigned int)(packet[offset + 167]) << 24 | (unsigned int)(packet[offset + 166]) << 16 | (unsigned int)(packet[offset + 165]) << 8 | (unsigned int)(packet[offset + 164]));
            p_systemStateSettings->TOLERANCE_DELAY_L = ((unsigned int)(packet[offset + 171]) << 24 | (unsigned int)(packet[offset + 170]) << 16 | (unsigned int)(packet[offset + 169]) << 8 | (unsigned int)(packet[offset + 168]));
            p_systemStateSettings->SPLIT_ALGORITHM = ((unsigned int)(packet[offset + 175]) << 24 | (unsigned int)(packet[offset + 174]) << 16 | (unsigned int)(packet[offset + 173]) << 8 | (unsigned int)(packet[offset + 172]));
            p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS = ((unsigned int)(packet[offset + 179]) << 24 | (unsigned int)(packet[offset + 178]) << 16 | (unsigned int)(packet[offset + 177]) << 8 | (unsigned int)(packet[offset + 176]));
            p_systemStateSettings->icmpFlowType = (unsigned char)((unsigned int)(packet[offset + 183]) << 24 | (unsigned int)(packet[offset + 182]) << 16 | (unsigned int)(packet[offset + 181]) << 8 | (unsigned int)(packet[offset + 180]));
            p_systemStateSettings->tcpRTportStart = ((unsigned int)(packet[offset + 187]) << 24 | (unsigned int)(packet[offset + 186]) << 16 | (unsigned int)(packet[offset + 185]) << 8 | (unsigned int)(packet[offset + 184]));
            p_systemStateSettings->tcpRTportEnd = ((unsigned int)(packet[offset + 191]) << 24 | (unsigned int)(packet[offset + 190]) << 16 | (unsigned int)(packet[offset + 189]) << 8 | (unsigned int)(packet[offset + 188]));
            p_systemStateSettings->tcpHRportStart = ((unsigned int)(packet[offset + 195]) << 24 | (unsigned int)(packet[offset + 194]) << 16 | (unsigned int)(packet[offset + 193]) << 8 | (unsigned int)(packet[offset + 192]));
            p_systemStateSettings->tcpHRportEnd = ((unsigned int)(packet[offset + 199]) << 24 | (unsigned int)(packet[offset + 198]) << 16 | (unsigned int)(packet[offset + 197]) << 8 | (unsigned int)(packet[offset + 196]));
            p_systemStateSettings->udpRTportStart = ((unsigned int)(packet[offset + 203]) << 24 | (unsigned int)(packet[offset + 202]) << 16 | (unsigned int)(packet[offset + 201]) << 8 | (unsigned int)(packet[offset + 200]));
            p_systemStateSettings->udpRTportEnd = ((unsigned int)(packet[offset + 207]) << 24 | (unsigned int)(packet[offset + 206]) << 16 | (unsigned int)(packet[offset + 205]) << 8 | (unsigned int)(packet[offset + 204]));
            p_systemStateSettings->udpHRportStart = ((unsigned int)(packet[offset + 211]) << 24 | (unsigned int)(packet[offset + 210]) << 16 | (unsigned int)(packet[offset + 209]) << 8 | (unsigned int)(packet[offset + 208]));
            p_systemStateSettings->udpHRportEnd = ((unsigned int)(packet[offset + 215]) << 24 | (unsigned int)(packet[offset + 214]) << 16 | (unsigned int)(packet[offset + 213]) << 8 | (unsigned int)(packet[offset + 212]));
            p_systemStateSettings->ulQoSFlowEnable = ((unsigned int)(packet[offset + 219]) << 24 | (unsigned int)(packet[offset + 218]) << 16 | (unsigned int)(packet[offset + 217]) << 8 | (unsigned int)(packet[offset + 216]));
        }
        else if (reqMessage.getSubType() == 6)
        {
            //controlManager.SendACK(6);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 6);


            tfcMessage.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
            switch (tfcMessage.getProtoType())
            {
            case 0: //disable UL QoS flow
                p_systemStateSettings->ulQoSFlowEnable = 0;
                break;
            case 1:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->tcpHRportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->tcpHRportEnd = tfcMessage.getPortEnd();
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->tcpRTportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->tcpRTportEnd = tfcMessage.getPortEnd();
                }
                else
                {
                    p_systemStateSettings->tcpRTportStart = 0;
                    p_systemStateSettings->tcpRTportEnd = 0;
                }

                break; //tcp
            case 2:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->udpHRportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->udpHRportEnd = tfcMessage.getPortEnd();
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->udpRTportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->udpRTportEnd = tfcMessage.getPortEnd();
                }
                else
                {
                    p_systemStateSettings->udpRTportStart = 0;
                    p_systemStateSettings->udpRTportEnd = 0;
                }
                break; //udp
            case 3:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->icmpFlowType = 1;
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->icmpFlowType = 2;
                }
                else
                {
                    p_systemStateSettings->icmpFlowType = 3;
                }
                break; //icmp
            default:
                break;
            }
            std::stringstream ss;
            ss << "Traffic Flow Config, icmp:" << (int)(p_systemStateSettings->icmpFlowType) << "\n"
               << "RT TCP " << p_systemStateSettings->tcpRTportStart << "~" << p_systemStateSettings->tcpRTportEnd << "\n"
               << "HR TCP " << p_systemStateSettings->tcpHRportStart << "~" << p_systemStateSettings->tcpHRportEnd << "\n"
               << "RT UDP " << p_systemStateSettings->udpRTportStart << "~" << p_systemStateSettings->udpRTportEnd << "\n"
               << "HR UDP " << p_systemStateSettings->udpHRportStart << "~" << p_systemStateSettings->udpHRportEnd << "\n";
            p_systemStateSettings->PrintLogs(ss);
        }
        break;
    }
    case 6: //normal ACK
    {
        seqNumber = vnicAck.getAckNum();
        int reqType = vnicAck.getReqType();
        switch (reqType)
        {
        case 1:
        {
            std::stringstream ss;
            ss << "receive WIFI probe ack! \n";
            p_systemStateSettings->PrintLogs(ss);
            //this is the prob ack
            p_systemStateSettings->lastReceiveWifiProbe = p_systemStateSettings->currentSysTimeMs;

            //controlManager.receiveWifiProbeAck(seqNumber);
            p_systemStateSettings->GMAIPCMessage(6, seqNumber, 0, false, 0);
            if (p_systemStateSettings->gStartTime >= 0)
            {
                int wifiowd = p_systemStateSettings->currentTimeMs - vnicAck.getTimeStampMillis();
                (measurementManager.wifi)->updateLastPacketOwd(wifiowd);
            }
            break;
        }
        default:
            break;
        }
        break;
    }
    case 7: //TSA
    {
        seqNumber = vnicAck.getAckNum();
        p_systemStateSettings->GMAIPCMessage(4, seqNumber, p_systemStateSettings->currentSysTimeMs, false, 0); //controlManager.receiveWifiTSA(seqNumber, p_systemStateSettings->currentSysTimeMs);
        
        vnicTSA.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader); //GMA header + ip header + udp header

        if (!measurementManager.measurementOn)
            {
                //measurement cycle not started yet and the receive TSA sequence is bigger than last one
                measurementManager.measureCycleStart(vnicTSA.getStartSn1()); //start next measurement cycle from start-Sn
            }

        if (p_systemStateSettings->gStartTime >= 0)
        {
            int wifiowd = p_systemStateSettings->currentTimeMs - vnicTSA.getTimeStampMillis();
            //   Log.v("wifi tsa owd (ms)",":" + Integer.toString(wifiowd));
            (measurementManager.wifi)->updateLastPacketOwd(wifiowd);
        }
        break;
    }
    default:
        break;
    }

}

void DataReceive::receiveLteControl(char *packet)
{
    vnicAck.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
    int seqNumber = vnicAck.getAckNum();
    switch (vnicAck.getType())
    {
    case 0x000000FF:
    {
        reqMessage.init((unsigned char*)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
        if (reqMessage.getSubType() == 4)
        {
            //controlManager.SendACK(4);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 4);

            tscMessage.init((unsigned char*)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
            switch (tscMessage.getULDuplicationEnabled())
            {
            case 0:
                p_systemStateSettings->gUlRToverLteFlag = 0;
                p_systemStateSettings->gDlRToverLteFlag = 0;
                break;
            case 1:
                p_systemStateSettings->gUlRToverLteFlag = 0;
                p_systemStateSettings->gDlRToverLteFlag = 1;
                break;
            case 2:
                p_systemStateSettings->gUlRToverLteFlag = 1;
                p_systemStateSettings->gDlRToverLteFlag = 0;
                break;
            case 3:
                p_systemStateSettings->gUlRToverLteFlag = 1;
                p_systemStateSettings->gDlRToverLteFlag = 1;
                break;
            default:
                break; //do not update for RT if > 3
            }

            if (p_systemStateSettings->gDlRToverLteFlag == 1)
            {
                p_systemStateSettings->GMAIPCMessage(3, 0, 0, false, 0); //controlManager.sendLteProbe();
            }

            if (tscMessage.getDLDynamicSplittingEnabled() < 16) //do not update traffic splitting configurations for NRT if > 16
            {
                if (tscMessage.getDLDynamicSplittingEnabled() == 0)
                    p_systemStateSettings->gDynamicSplitFlag = 0;
                else
                {
                    p_systemStateSettings->gDynamicSplitFlag = 1;
                    p_systemStateSettings->SPLIT_ALGORITHM = tscMessage.getDLDynamicSplittingEnabled();
                }
            //    p_systemStateSettings->wifiSplitFactor = tscMessage.getK1();
            //    p_systemStateSettings->lteSplitFactor = tscMessage.getK2();
            //    p_systemStateSettings->paramL = tscMessage.getL();
            }
           // p_systemStateSettings->GMAIPCMessage(1, 0, 0, false, 0); //controlManager.sendTSUMsg();
        }
        else if (reqMessage.getSubType() == 5)
        {
            //controlManager.SendACK(5);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 5);

            int offset = dataOffset + p_systemStateSettings->sizeofGMAMessageHeader + 6; //what is this 6 bytes?
            p_systemStateSettings->gNetWorkInterfaceMinMTU = ((unsigned int)(packet[offset + 3]) << 24 | (unsigned int)(packet[offset + 2]) << 16 | (unsigned int)(packet[offset + 1]) << 8 | (unsigned int)(packet[offset + 0]));
            p_systemStateSettings->gDynamicSplitFlag = ((unsigned int)(packet[offset + 7]) << 24 | (unsigned int)(packet[offset + 6]) << 16 | (unsigned int)(packet[offset + 5]) << 8 | (unsigned int)(packet[offset + 4]));
            p_systemStateSettings->gLteAlwaysOnFlag = ((unsigned int)(packet[offset + 11]) << 24 | (unsigned int)(packet[offset + 10]) << 16 | (unsigned int)(packet[offset + 9]) << 8 | (unsigned int)(packet[offset + 8]));
            int x = ((unsigned int)(packet[offset + 15]) << 24 | (unsigned int)(packet[offset + 14]) << 16 | (unsigned int)(packet[offset + 13]) << 8 | (unsigned int)(packet[offset + 12]));
            p_systemStateSettings->congestDetectLossThreshold = std::pow(10, 0 - (double)x);
            x = ((unsigned int)(packet[offset + 19]) << 24 | (unsigned int)(packet[offset + 18]) << 16 | (unsigned int)(packet[offset + 17]) << 8 | (unsigned int)(packet[offset + 16]));
            p_systemStateSettings->congestDetectUtilizationThreshold = ((double)x) / 100;

            p_systemStateSettings->lteProbeIntervalScreenOff = ((unsigned int)(packet[offset + 23]) << 24 | (unsigned int)(packet[offset + 22]) << 16 | (unsigned int)(packet[offset + 21]) << 8 | (unsigned int)(packet[offset + 20]));
            p_systemStateSettings->lteProbeIntervalScreenOn = ((unsigned int)(packet[offset + 27]) << 24 | (unsigned int)(packet[offset + 26]) << 16 | (unsigned int)(packet[offset + 25]) << 8 | (unsigned int)(packet[offset + 24]));
            p_systemStateSettings->lteProbeIntervalActive = ((unsigned int)(packet[offset + 31]) << 24 | (unsigned int)(packet[offset + 30]) << 16 | (unsigned int)(packet[offset + 29]) << 8 | (unsigned int)(packet[offset + 28]));
            p_systemStateSettings->lteRssiMeasurement = ((unsigned int)(packet[offset + 35]) << 24 | (unsigned int)(packet[offset + 34]) << 16 | (unsigned int)(packet[offset + 33]) << 8 | (unsigned int)(packet[offset + 32]));
            p_systemStateSettings->wifiProbeIntervalScreenOff = ((unsigned int)(packet[offset + 39]) << 24 | (unsigned int)(packet[offset + 38]) << 16 | (unsigned int)(packet[offset + 37]) << 8 | (unsigned int)(packet[offset + 36]));
            p_systemStateSettings->wifiProbeIntervalScreenOn = ((unsigned int)(packet[offset + 43]) << 24 | (unsigned int)(packet[offset + 42]) << 16 | (unsigned int)(packet[offset + 41]) << 8 | (unsigned int)(packet[offset + 40]));
            p_systemStateSettings->WiFiProbeIntervalActive = ((unsigned int)(packet[offset + 47]) << 24 | (unsigned int)(packet[offset + 46]) << 16 | (unsigned int)(packet[offset + 45]) << 8 | (unsigned int)(packet[offset + 44]));
            p_systemStateSettings->paramL = ((unsigned int)(packet[offset + 51]) << 24 | (unsigned int)(packet[offset + 50]) << 16 | (unsigned int)(packet[offset + 49]) << 8 | (unsigned int)(packet[offset + 48]));
            p_systemStateSettings->wifiLowRssi = ((unsigned int)(packet[offset + 55]) << 24 | (unsigned int)(packet[offset + 54]) << 16 | (unsigned int)(packet[offset + 53]) << 8 | (unsigned int)(packet[offset + 52]));
            p_systemStateSettings->wifiHighRssi = ((unsigned int)(packet[offset + 59]) << 24 | (unsigned int)(packet[offset + 58]) << 16 | (unsigned int)(packet[offset + 57]) << 8 | (unsigned int)(packet[offset + 56]));
            p_systemStateSettings->MRPintervalActive = ((unsigned int)(packet[offset + 63]) << 24 | (unsigned int)(packet[offset + 62]) << 16 | (unsigned int)(packet[offset + 61]) << 8 | (unsigned int)(packet[offset + 60]));
            p_systemStateSettings->MRPintervalIdle = ((unsigned int)(packet[offset + 67]) << 24 | (unsigned int)(packet[offset + 66]) << 16 | (unsigned int)(packet[offset + 65]) << 8 | (unsigned int)(packet[offset + 64]));
            p_systemStateSettings->MRPsize = ((unsigned int)(packet[offset + 71]) << 24 | (unsigned int)(packet[offset + 70]) << 16 | (unsigned int)(packet[offset + 69]) << 8 | (unsigned int)(packet[offset + 68]));
            p_systemStateSettings->MAX_MAXREORDERINGDELAY = ((unsigned int)(packet[offset + 75]) << 24 | (unsigned int)(packet[offset + 74]) << 16 | (unsigned int)(packet[offset + 73]) << 8 | (unsigned int)(packet[offset + 72]));
            p_systemStateSettings->MIN_MAXREORDERINGDELAY = ((unsigned int)(packet[offset + 79]) << 24 | (unsigned int)(packet[offset + 78]) << 16 | (unsigned int)(packet[offset + 77]) << 8 | (unsigned int)(packet[offset + 76]));
            p_systemStateSettings->reorderBufferSize = ((unsigned int)(packet[offset + 83]) << 24 | (unsigned int)(packet[offset + 82]) << 16 | (unsigned int)(packet[offset + 81]) << 8 | (unsigned int)(packet[offset + 80]));
            p_systemStateSettings->reorderLsnEnhanceFlag = ((unsigned int)(packet[offset + 87]) << 24 | (unsigned int)(packet[offset + 86]) << 16 | (unsigned int)(packet[offset + 85]) << 8 | (unsigned int)(packet[offset + 84]));
            p_systemStateSettings->reorderDropOutOfOrderPkt = ((unsigned int)(packet[offset + 91]) << 24 | (unsigned int)(packet[offset + 90]) << 16 | (unsigned int)(packet[offset + 89]) << 8 | (unsigned int)(packet[offset + 88]));
            p_systemStateSettings->minTpt = ((unsigned int)(packet[offset + 95]) << 24 | (unsigned int)(packet[offset + 94]) << 16 | (unsigned int)(packet[offset + 93]) << 8 | (unsigned int)(packet[offset + 92]));
            p_systemStateSettings->idleTimer = ((unsigned int)(packet[offset + 99]) << 24 | (unsigned int)(packet[offset + 98]) << 16 | (unsigned int)(packet[offset + 97]) << 8 | (unsigned int)(packet[offset + 96]));
            p_systemStateSettings->allowAppListEnable = ((unsigned int)(packet[offset + 103]) << 24 | (unsigned int)(packet[offset + 102]) << 16 | (unsigned int)(packet[offset + 101]) << 8 | (unsigned int)(packet[offset + 100]));
            p_systemStateSettings->wifiOwdOffsetMax = ((unsigned int)(packet[offset + 107]) << 24 | (unsigned int)(packet[offset + 106]) << 16 | (unsigned int)(packet[offset + 105]) << 8 | (unsigned int)(packet[offset + 104]));
            p_systemStateSettings->gUlDuplicateFlag = ((unsigned int)(packet[offset + 111]) << 24 | (unsigned int)(packet[offset + 110]) << 16 | (unsigned int)(packet[offset + 109]) << 8 | (unsigned int)(packet[offset + 108]));

            x = ((unsigned int)(packet[offset + 115]) << 24 | (unsigned int)(packet[offset + 114]) << 16 | (unsigned int)(packet[offset + 113]) << 8 | (unsigned int)(packet[offset + 112]));
            p_systemStateSettings->OWD_CONVERGE_THRESHOLD = ((double)x) / 100;

            p_systemStateSettings->MAX_MEASURE_INTERVAL_NUM = ((unsigned int)(packet[offset + 119]) << 24 | (unsigned int)(packet[offset + 118]) << 16 | (unsigned int)(packet[offset + 117]) << 8 | (unsigned int)(packet[offset + 116]));
            p_systemStateSettings->MIN_PACKET_NUM_PER_INTERVAL = ((unsigned int)(packet[offset + 123]) << 24 | (unsigned int)(packet[offset + 122]) << 16 | (unsigned int)(packet[offset + 121]) << 8 | (unsigned int)(packet[offset + 120]));
            p_systemStateSettings->MAX_MEASURE_INTERVAL_DURATION = ((unsigned int)(packet[offset + 127]) << 24 | (unsigned int)(packet[offset + 126]) << 16 | (unsigned int)(packet[offset + 125]) << 8 | (unsigned int)(packet[offset + 124]));
            p_systemStateSettings->MIN_MEASURE_INTERVAL_DURATION = ((unsigned int)(packet[offset + 131]) << 24 | (unsigned int)(packet[offset + 130]) << 16 | (unsigned int)(packet[offset + 129]) << 8 | (unsigned int)(packet[offset + 128]));
            p_systemStateSettings->BURST_SAMPLE_FREQUENCY = ((unsigned int)(packet[offset + 135]) << 24 | (unsigned int)(packet[offset + 134]) << 16 | (unsigned int)(packet[offset + 133]) << 8 | (unsigned int)(packet[offset + 132]));
            p_systemStateSettings->MAX_RATE_ESTIMATE = ((unsigned int)(packet[offset + 139]) << 24 | (unsigned int)(packet[offset + 138]) << 16 | (unsigned int)(packet[offset + 137]) << 8 | (unsigned int)(packet[offset + 136]));
            p_systemStateSettings->RATE_ESTIMATE_K = ((unsigned int)(packet[offset + 143]) << 24 | (unsigned int)(packet[offset + 142]) << 16 | (unsigned int)(packet[offset + 141]) << 8 | (unsigned int)(packet[offset + 140]));
            p_systemStateSettings->MIN_PACKET_COUNT_PER_BURST = ((unsigned int)(packet[offset + 147]) << 24 | (unsigned int)(packet[offset + 146]) << 16 | (unsigned int)(packet[offset + 145]) << 8 | (unsigned int)(packet[offset + 144]));
            x = ((unsigned int)(packet[offset + 151]) << 24 | (unsigned int)(packet[offset + 150]) << 16 | (unsigned int)(packet[offset + 149]) << 8 | (unsigned int)(packet[offset + 148]));
            p_systemStateSettings->BURST_INCREASING_ALPHA = ((double)x) / 100;

            p_systemStateSettings->STEP_ALPHA_THRESHOLD = ((unsigned int)(packet[offset + 155]) << 24 | (unsigned int)(packet[offset + 154]) << 16 | (unsigned int)(packet[offset + 153]) << 8 | (unsigned int)(packet[offset + 152]));

            p_systemStateSettings->TOLERANCE_LOSS_BOUND = ((unsigned int)(packet[offset + 159]) << 24 | (unsigned int)(packet[offset + 158]) << 16 | (unsigned int)(packet[offset + 157]) << 8 | (unsigned int)(packet[offset + 156]));
            p_systemStateSettings->TOLERANCE_DELAY_BOUND = ((unsigned int)(packet[offset + 163]) << 24 | (unsigned int)(packet[offset + 162]) << 16 | (unsigned int)(packet[offset + 161]) << 8 | (unsigned int)(packet[offset + 160]));
            p_systemStateSettings->TOLERANCE_DELAY_H = ((unsigned int)(packet[offset + 167]) << 24 | (unsigned int)(packet[offset + 166]) << 16 | (unsigned int)(packet[offset + 165]) << 8 | (unsigned int)(packet[offset + 164]));
            p_systemStateSettings->TOLERANCE_DELAY_L = ((unsigned int)(packet[offset + 171]) << 24 | (unsigned int)(packet[offset + 170]) << 16 | (unsigned int)(packet[offset + 169]) << 8 | (unsigned int)(packet[offset + 168]));
            p_systemStateSettings->SPLIT_ALGORITHM = ((unsigned int)(packet[offset + 175]) << 24 | (unsigned int)(packet[offset + 174]) << 16 | (unsigned int)(packet[offset + 173]) << 8 | (unsigned int)(packet[offset + 172]));
            p_systemStateSettings->INITIAL_PACKETS_BEFORE_LOSS = ((unsigned int)(packet[offset + 179]) << 24 | (unsigned int)(packet[offset + 178]) << 16 | (unsigned int)(packet[offset + 177]) << 8 | (unsigned int)(packet[offset + 176]));
            p_systemStateSettings->icmpFlowType = (unsigned char)((unsigned int)(packet[offset + 183]) << 24 | (unsigned int)(packet[offset + 182]) << 16 | (unsigned int)(packet[offset + 181]) << 8 | (unsigned int)(packet[offset + 180]));
            p_systemStateSettings->tcpRTportStart = ((unsigned int)(packet[offset + 187]) << 24 | (unsigned int)(packet[offset + 186]) << 16 | (unsigned int)(packet[offset + 185]) << 8 | (unsigned int)(packet[offset + 184]));
            p_systemStateSettings->tcpRTportEnd = ((unsigned int)(packet[offset + 191]) << 24 | (unsigned int)(packet[offset + 190]) << 16 | (unsigned int)(packet[offset + 189]) << 8 | (unsigned int)(packet[offset + 188]));
            p_systemStateSettings->tcpHRportStart = ((unsigned int)(packet[offset + 195]) << 24 | (unsigned int)(packet[offset + 194]) << 16 | (unsigned int)(packet[offset + 193]) << 8 | (unsigned int)(packet[offset + 192]));
            p_systemStateSettings->tcpHRportEnd = ((unsigned int)(packet[offset + 199]) << 24 | (unsigned int)(packet[offset + 198]) << 16 | (unsigned int)(packet[offset + 197]) << 8 | (unsigned int)(packet[offset + 196]));
            p_systemStateSettings->udpRTportStart = ((unsigned int)(packet[offset + 203]) << 24 | (unsigned int)(packet[offset + 202]) << 16 | (unsigned int)(packet[offset + 201]) << 8 | (unsigned int)(packet[offset + 200]));
            p_systemStateSettings->udpRTportEnd = ((unsigned int)(packet[offset + 207]) << 24 | (unsigned int)(packet[offset + 206]) << 16 | (unsigned int)(packet[offset + 205]) << 8 | (unsigned int)(packet[offset + 204]));
            p_systemStateSettings->udpHRportStart = ((unsigned int)(packet[offset + 211]) << 24 | (unsigned int)(packet[offset + 210]) << 16 | (unsigned int)(packet[offset + 209]) << 8 | (unsigned int)(packet[offset + 208]));
            p_systemStateSettings->udpHRportEnd = ((unsigned int)(packet[offset + 215]) << 24 | (unsigned int)(packet[offset + 214]) << 16 | (unsigned int)(packet[offset + 213]) << 8 | (unsigned int)(packet[offset + 212]));
            p_systemStateSettings->ulQoSFlowEnable = ((unsigned int)(packet[offset + 219]) << 24 | (unsigned int)(packet[offset + 218]) << 16 | (unsigned int)(packet[offset + 217]) << 8 | (unsigned int)(packet[offset + 216]));
        }
        else if (reqMessage.getSubType() == 6)
        {
            //controlManager.SendACK(6);
            p_systemStateSettings->GMAIPCMessage(8, 0, 0, false, 6);


            tfcMessage.init((unsigned char*)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader);
            switch (tfcMessage.getProtoType())
            {
            case 0: //disable UL QoS flow
                p_systemStateSettings->ulQoSFlowEnable = 0;
                break;
            case 1:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->tcpHRportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->tcpHRportEnd = tfcMessage.getPortEnd();
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->tcpRTportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->tcpRTportEnd = tfcMessage.getPortEnd();
                }
                else
                {
                    p_systemStateSettings->tcpRTportStart = 0;
                    p_systemStateSettings->tcpRTportEnd = 0;
                }

                break; //tcp
            case 2:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->udpHRportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->udpHRportEnd = tfcMessage.getPortEnd();
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->udpRTportStart = tfcMessage.getPortStart();
                    p_systemStateSettings->udpRTportEnd = tfcMessage.getPortEnd();
                }
                else
                {
                    p_systemStateSettings->udpRTportStart = 0;
                    p_systemStateSettings->udpRTportEnd = 0;
                }
                break; //udp
            case 3:
                p_systemStateSettings->ulQoSFlowEnable = 1;
                if (tfcMessage.getFlowID() == 1)
                {
                    p_systemStateSettings->icmpFlowType = 1;
                }
                else if (tfcMessage.getFlowID() == 2)
                {
                    p_systemStateSettings->icmpFlowType = 2;
                }
                else
                {
                    p_systemStateSettings->icmpFlowType = 3;
                }
                break; //icmp
            default:
                break;
            }
            std::stringstream ss;
            ss << "Traffic Flow Config, icmp:" << (int)(p_systemStateSettings->icmpFlowType) << "\n"
                << "RT TCP " << p_systemStateSettings->tcpRTportStart << "~" << p_systemStateSettings->tcpRTportEnd << "\n"
                << "HR TCP " << p_systemStateSettings->tcpHRportStart << "~" << p_systemStateSettings->tcpHRportEnd << "\n"
                << "RT UDP " << p_systemStateSettings->udpRTportStart << "~" << p_systemStateSettings->udpRTportEnd << "\n"
                << "HR UDP " << p_systemStateSettings->udpHRportStart << "~" << p_systemStateSettings->udpHRportEnd << "\n";
            p_systemStateSettings->PrintLogs(ss);
        }
        break;
    }
    case 6:
        switch (vnicAck.getReqType())
        {
        case 1:
        {
            std::stringstream ss;
            ss << "receive lte probes ack\n";
            p_systemStateSettings->PrintLogs(ss);
            p_systemStateSettings->lastReceiveLteProbe = p_systemStateSettings->currentSysTimeMs;
            //controlManager.receiveLteProbeAck(seqNumber);
            p_systemStateSettings->GMAIPCMessage(7, seqNumber, 0, false, 0);
            if (p_systemStateSettings->gStartTime >= 0)
            {
                int lteowd = p_systemStateSettings->currentTimeMs - vnicAck.getTimeStampMillis();
                (measurementManager.lte)->updateLastPacketOwd(lteowd);
            }
            break;
        }
        default:
            break;
        }
        break;
    case 7:
    {
        p_systemStateSettings->GMAIPCMessage(5, seqNumber, p_systemStateSettings->currentSysTimeMs, false, 0); //controlManager.receiveLteTSA(seqNumber, p_systemStateSettings->currentSysTimeMs);
        vnicTSA.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofGMAMessageHeader); //GMA header + ip header + udp header
        if (!measurementManager.measurementOn)
            {
                measurementManager.measureCycleStart(vnicTSA.getStartSn1()); //start next measurement cycle from start-Sn
            }
        if (p_systemStateSettings->gStartTime >= 0)
        {
            int lteowd = p_systemStateSettings->currentTimeMs - vnicTSA.getTimeStampMillis();
            (measurementManager.lte)->updateLastPacketOwd(lteowd);
        }
        break;
    }
    default:
        break;
    }
    
}

void DataReceive::receiveWifiPacket(char *packet)
{
    int length = 0;
    long systemTimeMsLong = (long)(p_systemStateSettings->update_current_time_params());
    int systemTimeMs = (int)(systemTimeMsLong & 0x7FFFFFFF);
    p_systemStateSettings->currentSysTimeMs = systemTimeMs;
    p_systemStateSettings->lastReceiveWifiPkt = systemTimeMs;
    p_systemStateSettings->currentTimeMs = (systemTimeMs + p_systemStateSettings->gStartTime) & 0x7FFFFFFF;

    gmaDataHeader.init((unsigned char *)packet, dataOffset);
    short gmaflag = gmaDataHeader.getFlag();
    int flagInt = gmaflag & 0xffff;
    switch (flagInt)
    {
    case 0x0: // control message or mams message
        receiveWifiControl(packet);
        break;
    case 0xF807:
    {
        ipHeader.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofDlGmaDataHeader);
        length = ipHeader.getTotalLength();
        if (length <= maxPktLen)
        {
            int mSeqNum = gmaDataHeader.getDlGSeqNum();
            short lSeqNum = gmaDataHeader.getDlLSeqNum();
            short flowNum = gmaDataHeader.getDlFlowId();
            int tx_time = gmaDataHeader.getDlTimeStampMillis();
            switch (flowNum) {
            case 3: //p_systemStateSettings->nonRealtimelModeFlowId)
            {
                p_systemStateSettings->wifiReceiveNrtBytes += length;
                if (measurementManager.measurementOn)
                {
                    if (measurementManager.measureIntervalStartConditionCheck(reorderingManager.nrtReorderingWorker.GetNextSn()))
                    { //received a packet with sn larger than measurement start_sn
                        //start the first measurement interval
                        measurementManager.measureIntervalStart(systemTimeMsLong);
                    }
                    (measurementManager.wifi)->updateLastPacketOwd(p_systemStateSettings->currentTimeMs - tx_time);
                    (measurementManager.wifi)->updateLsn(lSeqNum);
                    measurementManager.measureIntervalEndCheck(systemTimeMsLong);
                }

                if (p_systemStateSettings->splitEnable == 1 || p_systemStateSettings->currentTimeMs < p_systemStateSettings->reorderStopTime)
                {
                    reorderingManager.nrtReorderingWorker.receiveHRPacket(packet, (int)lSeqNum, mSeqNum, length, 0, tx_time);
                }
                else
                {
                    reorderingManager.nrtReorderingWorker.outputHRPacket(packet, length, mSeqNum, tx_time);
                    reorderingManager.nrtReorderingWorker.updateNextSn(mSeqNum, (int)lSeqNum, 0);
                }
                /*
                if (p_systemStateSettings->splitEnable == 1 || p_systemStateSettings->currentTimeMs < p_systemStateSettings->reorderStopTime)
                {
                    reorderingManager.receivePacket(packet, (int)lSeqNum, mSeqNum, length, 0, tx_time);
                }
                else
                {
                    reorderingManager.outputPacket(packet, length, mSeqNum, tx_time);
                    if (rollOverDiff(mSeqNum, reorderingManager.GetNextSn()) >= 0)
                    {
                        reorderingManager.updateNextSn(mSeqNum);
                    }
                }*/
            }
            break;
            case 2: //p_systemStateSettings->realtimeModeFlowId)
            {
                //realtime traffic here.
                p_systemStateSettings->wifiReceiveRtBytes += length;

                //owd measurement
                int owdMs = p_systemStateSettings->currentTimeMs - gmaDataHeader.getDlTimeStampMillis();
                if (owdMs < 10000)
                { //only update OWD smaller than 10 s
                    p_systemStateSettings->wifiRtOwdSum += owdMs;
                    p_systemStateSettings->wifiRtPacketNum++;

                    if (p_systemStateSettings->wifiRtOwdMin > owdMs)
                    {
                        p_systemStateSettings->wifiRtOwdMin = owdMs;
                    }
                    if (p_systemStateSettings->wifiRtOwdMax < owdMs)
                    {
                        p_systemStateSettings->wifiRtOwdMax = owdMs;
                    }
                }

                //loss measurement
                if (mSeqNum == nextWifiRtSn)
                {
                    p_systemStateSettings->wifiRtInorderPacketNum++;
                    nextWifiRtSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else if (rollOverDiff(mSeqNum, nextWifiRtSn) > 0)
                {
                    p_systemStateSettings->wifiRtInorderPacketNum++;
                    p_systemStateSettings->wifiRtMissingPacketNum += rollOverDiff(mSeqNum, nextWifiRtSn);
                    nextWifiRtSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else
                {
                    p_systemStateSettings->wifiRtAbnormalPacketNum++;
                }

                p_systemStateSettings->tunwrite(packet + dataOffset + p_systemStateSettings->sizeofDlGmaDataHeader, length);
         
            }
            break;
            case 1: 
            {
                p_systemStateSettings->wifiReceiveRtBytes += length;

                //owd measurement
                int owdMs = p_systemStateSettings->currentTimeMs - gmaDataHeader.getDlTimeStampMillis();
                if (owdMs < 10000)
                { //only update OWD smaller than 10 s
                    p_systemStateSettings->wifiRtOwdSum += owdMs;
                    p_systemStateSettings->wifiRtPacketNum++;

                    if (p_systemStateSettings->wifiRtOwdMin > owdMs)
                    {
                        p_systemStateSettings->wifiRtOwdMin = owdMs;
                    }
                    if (p_systemStateSettings->wifiRtOwdMax < owdMs)
                    {
                        p_systemStateSettings->wifiRtOwdMax = owdMs;
                    }
                }

                //loss measurement
                if (mSeqNum == nextWifiHrSn)
                {
                    p_systemStateSettings->wifiRtInorderPacketNum++;
                    nextWifiHrSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else if (rollOverDiff(mSeqNum, nextWifiHrSn) > 0)
                {
                    p_systemStateSettings->wifiRtInorderPacketNum++;
                    p_systemStateSettings->wifiRtMissingPacketNum += rollOverDiff(mSeqNum, nextWifiHrSn);
                    nextWifiHrSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else
                {
                    p_systemStateSettings->wifiRtAbnormalPacketNum++;
                }
                reorderingManager.hrReorderingWorker.receiveHRPacket(packet, (int)lSeqNum, mSeqNum, length, 0, tx_time);
            }
            break;   //duplication flow
            default:
            {
                std::stringstream ss;
                ss << "Error! Unknown flow!\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            break;
            }
        }
        else
        {
            
        }
        break;
    }
    default:
        break;
    }
}

void DataReceive::receiveLtePacket(char *packet)
{
    int length = 0;
    long systemTimeMsLong = (long)(p_systemStateSettings->update_current_time_params());
    int systemTimeMs = (int)(systemTimeMsLong & 0x7FFFFFFF);
    p_systemStateSettings->currentSysTimeMs = systemTimeMs;
    p_systemStateSettings->lastReceiveLtePkt = systemTimeMs;
    p_systemStateSettings->currentTimeMs = (systemTimeMs + p_systemStateSettings->gStartTime) & 0x7FFFFFFF;

    gmaDataHeader.init((unsigned char *)packet, dataOffset);
    short gmaflag = gmaDataHeader.getFlag();
    int flagInt = gmaflag & 0xffff;
    switch (flagInt)
    {
    case 0x0: // control message or mams message
        receiveLteControl(packet);
        break;
    case 0xF807:
    {
        ipHeader.init((unsigned char *)packet, dataOffset + p_systemStateSettings->sizeofDlGmaDataHeader);
        length = ipHeader.getTotalLength();
        if (length <= maxPktLen)
        {
            int mSeqNum = gmaDataHeader.getDlGSeqNum();
            short lSeqNum = gmaDataHeader.getDlLSeqNum();
            short flowNum = gmaDataHeader.getDlFlowId();
            int tx_time = gmaDataHeader.getDlTimeStampMillis();
            switch (flowNum) {
            case 3: //p_systemStateSettings->nonRealtimelModeFlowId:
            {
                p_systemStateSettings->lteReceiveNrtBytes += length;
                if (measurementManager.measurementOn)
                {
                    if (measurementManager.measureIntervalStartConditionCheck(reorderingManager.nrtReorderingWorker.GetNextSn()))
                    { //received a packet with sn larger than measurement start_sn
                        //start the first measurement interval
                        measurementManager.measureIntervalStart(systemTimeMsLong);
                    }
                    (measurementManager.lte)->updateLastPacketOwd(p_systemStateSettings->currentTimeMs - tx_time);
                    (measurementManager.lte)->updateLsn(lSeqNum);
                    measurementManager.measureIntervalEndCheck(systemTimeMsLong);
                }
                
                if (p_systemStateSettings->splitEnable == 1 || p_systemStateSettings->currentTimeMs < p_systemStateSettings->reorderStopTime)
                {
                    reorderingManager.nrtReorderingWorker.receiveHRPacket(packet, (int)lSeqNum, mSeqNum, length, 3, tx_time);
                }
                else
                {
                    reorderingManager.nrtReorderingWorker.outputHRPacket(packet, length, mSeqNum, tx_time);
                    reorderingManager.nrtReorderingWorker.updateNextSn(mSeqNum, (int)lSeqNum, 3);
                }
                /*
                if (p_systemStateSettings->splitEnable == 1 || p_systemStateSettings->currentTimeMs < p_systemStateSettings->reorderStopTime)
                {
                    reorderingManager.receivePacket(packet, (int)lSeqNum, mSeqNum, length, 3, tx_time);
                }
                else
                {
                    reorderingManager.outputPacket(packet, length, mSeqNum, tx_time);
                    if (rollOverDiff(mSeqNum, reorderingManager.GetNextSn()) >= 0)
                    {
                        reorderingManager.updateNextSn(mSeqNum);
                    }
                }
                */
            }
                break;
            case 2: //p_systemStateSettings->realtimeModeFlowId:
            {
                //realtime traffic here.
                p_systemStateSettings->lteReceiveRtBytes += length;

                //delay measurement
                int owdMs = p_systemStateSettings->currentTimeMs - gmaDataHeader.getDlTimeStampMillis();
                if (owdMs < 10000)
                { //only update OWD smaller than 10 s
                    p_systemStateSettings->lteRtOwdSum += owdMs;
                    p_systemStateSettings->lteRtPacketNum++;

                    if (p_systemStateSettings->lteRtOwdMin > owdMs)
                    {
                        p_systemStateSettings->lteRtOwdMin = owdMs;
                    }
                    if (p_systemStateSettings->lteRtOwdMax < owdMs)
                    {
                        p_systemStateSettings->lteRtOwdMax = owdMs;
                    }
                }

                //loss measurement
                if (mSeqNum == nextLteRtSn)
                {
                    p_systemStateSettings->lteRtInorderPacketNum++;
                    nextLteRtSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else if (rollOverDiff(mSeqNum, nextLteRtSn) > 0)
                {
                    p_systemStateSettings->lteRtInorderPacketNum++;
                    p_systemStateSettings->lteRtMissingPacketNum += rollOverDiff(mSeqNum, nextLteRtSn);
                    nextLteRtSn = (mSeqNum + 1) & 0x00FFFFFF;
                }
                else
                {
                    p_systemStateSettings->lteRtAbnormalPacketNum++;
                }

                p_systemStateSettings->tunwrite(packet + dataOffset + p_systemStateSettings->sizeofDlGmaDataHeader, length);
                
            }
                break;
            case 1: //p_systemStateSettings->ulDuplicateModeFlowId:
                
            {    p_systemStateSettings->lteReceiveRtBytes += length;

            //delay measurement
            int owdMs = p_systemStateSettings->currentTimeMs - gmaDataHeader.getDlTimeStampMillis();
            if (owdMs < 10000)
            { //only update OWD smaller than 10 s
                p_systemStateSettings->lteRtOwdSum += owdMs;
                p_systemStateSettings->lteRtPacketNum++;

                if (p_systemStateSettings->lteRtOwdMin > owdMs)
                {
                    p_systemStateSettings->lteRtOwdMin = owdMs;
                }
                if (p_systemStateSettings->lteRtOwdMax < owdMs)
                {
                    p_systemStateSettings->lteRtOwdMax = owdMs;
                }
            }

            //loss measurement
            if (mSeqNum == nextLteHrSn)
            {
                p_systemStateSettings->lteRtInorderPacketNum++;
                nextLteHrSn = (mSeqNum + 1) & 0x00FFFFFF;
            }
            else if (rollOverDiff(mSeqNum, nextLteHrSn) > 0)
            {
                p_systemStateSettings->lteRtInorderPacketNum++;
                p_systemStateSettings->lteRtMissingPacketNum += rollOverDiff(mSeqNum, nextLteHrSn);
                nextLteHrSn = (mSeqNum + 1) & 0x00FFFFFF;
            }
            else
            {
                p_systemStateSettings->lteRtAbnormalPacketNum++;
            }
               reorderingManager.hrReorderingWorker.receiveHRPacket(packet, (int)lSeqNum, mSeqNum, length, 3, tx_time);
            }
                break;
            default:
            {
                std::stringstream ss;
                ss << "Error! Unknown flow!\n";
                p_systemStateSettings->PrintLogs(ss);
            }
            break;
            }
        }
        else
        {
            
        }
        break;
    }
    default:
        break;
    }
}

void DataReceive::updataWifiChannel(GMASocket wifiFd)
{
    wifiudp_fd = wifiFd;
    wakeupSelect();
}

bool DataReceive::updataLteChannel(GMASocket lteFd)
{
    lteudp_fd = lteFd;
    if (lteudp_fd != GMA_INVALID_SOCKET)
    {
        wakeupSelect();
        return true;
    }
    else
    {
        return false;
    }
}

int DataReceive::rollOverDiff2(int x, int y, int max)
{
    int diff = x - y;
    if (diff > (max / 2))
    {
        diff = diff - max;
    }
    else if (diff < 0 - max / 2)
    {
        diff = diff + max;
    }
    return diff;
}

int DataReceive::rollOverDiff(int x, int y)
{
    int diff = x - y;
    //2^24 = 16777216, 2^23 = 8388608
    if (diff > 8388608)
    {
        diff = diff - 16777216;
    }
    else if (diff < -8388608)
    {
        diff = diff + 16777216;
    }
    return diff;
}

void DataReceive::closeWifiChannel()
{
   
    wifiudp_fd = GMA_INVALID_SOCKET;
}

void DataReceive::closeLteChannel()
{
    
    lteudp_fd = GMA_INVALID_SOCKET;
}

bool DataReceive::updateSettings()
{
    dataOffset = 0;
    maxTsaSn = 0;
    maxPktLen = p_systemStateSettings->gmaMTUsize - p_systemStateSettings->sizeofDlGmaDataHeader;
    isDataReceiveStart = true;
    nextWifiRtSn = 0;
    nextLteRtSn = 0;
    nextWifiHrSn = 0;
    nextLteHrSn = 0;


    if (!setupUdpSocket())
        return false;

    std::stringstream ss;
    ss << "data receive settings update... ok \n";
    p_systemStateSettings->PrintLogs(ss);

    return true;
}

bool DataReceive::setupUdpSocket()
{
    socklen_t len;
    udpLoop = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpLoop == GMA_INVALID_SOCKET)
    {
        return false;
    }
    udpInaddr.sin_family = AF_INET;
    udpInaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udpInaddr.sin_port = 0;
    if (bind(udpLoop, (struct sockaddr*)&udpInaddr, sizeof(udpInaddr)) != 0)
    {
        p_systemStateSettings->closegmasocket(udpLoop);
        udpLoop = GMA_INVALID_SOCKET;
        return false;
    }

    len = sizeof(udpAddr);
    if (getsockname(udpLoop, &udpAddr, &len) != 0)
    {
        p_systemStateSettings->closegmasocket(udpLoop);
        udpLoop = GMA_INVALID_SOCKET;
        return false;
    }

    if (connect(udpLoop, &udpAddr, len) != 0)
    {
        p_systemStateSettings->closegmasocket(udpLoop);
        udpLoop = GMA_INVALID_SOCKET;
        return false;
    } 
    return true;

}

void DataReceive::startReordering()
{
    reorderingManager.startReordering();
}

void DataReceive::closeReordering()
{
    reorderingManager.closeReorderingManager();
 
}

void DataReceive::updateReorderingAndMeasurement()
{
    reorderingManager.updateSystemSettings();
    measurementManager.updateSystemSettings();
}