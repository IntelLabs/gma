//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : DataSend.cpp

#include "../include/DataSend.h"
#include "../include/Header.h"
#include "../include/SystemStateSettings.h"

DataSend::DataSend()
{
    isDataSendStart = true;
    length = 0;
    snNumber_dup = 1;
    snNumber_realtime = 1;
    snNumber_default = 1;
    wifiudp_fd = GMA_INVALID_SOCKET;
    lteudp_fd = GMA_INVALID_SOCKET;
    wifiServer = { 0 };
    lteServer = { 0 };
}

void DataSend::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

void DataSend::updateServerAddress(struct sockaddr_in wifiServerAddr, struct sockaddr_in lteServerAddr)
{
    wifiServer = wifiServerAddr;
    lteServer = lteServerAddr;
}

void DataSend::updateSettings()
{
    int length = 0;
    int snNumber_dup = 1;
    int snNumber_realtime = 1;
    int snNumber_default = 1;
}

void DataSend::processPackets(char *buffer, int length)
{
    ipHeader.init((unsigned char *)buffer, p_systemStateSettings->sizeofUlGmaDataHeader);
    if (ipHeader.getVersion() != 4)
    {
        return;
    }
    int dst_port = 0;
    int flow_id = p_systemStateSettings->nonRealtimelModeFlowId;
    
    if (p_systemStateSettings->ulQoSFlowEnable == 1)
        {
           switch (ipHeader.getProtocol())
                {
                case 1: //ICMP
                    flow_id = p_systemStateSettings->icmpFlowType;
                    break;
                case 6:
                    if (p_systemStateSettings->tcpRTportStart + p_systemStateSettings->tcpRTportEnd > 0)
                    {
                        dst_port = ipHeader.getDestinationPort();
                        if (dst_port <= p_systemStateSettings->tcpRTportEnd && dst_port >= p_systemStateSettings->tcpRTportStart)
                        {
                            flow_id = p_systemStateSettings->realtimeModeFlowId;
                        }
                    }
                    else if (p_systemStateSettings->tcpHRportStart + p_systemStateSettings->tcpHRportEnd > 0)
                    {
                        dst_port = ipHeader.getDestinationPort();
                        if (dst_port <= p_systemStateSettings->tcpHRportEnd && dst_port >= p_systemStateSettings->tcpHRportStart)
                        {
                            flow_id = p_systemStateSettings->ulDuplicateModeFlowId;
                        }
                    }
                    break; //tcp
                case 17:
                    if (p_systemStateSettings->udpRTportStart + p_systemStateSettings->udpRTportEnd > 0)
                    {
                        dst_port = ipHeader.getDestinationPort();
                        if (dst_port <= p_systemStateSettings->udpRTportEnd && dst_port >= p_systemStateSettings->udpRTportStart)
                        {
                            flow_id = p_systemStateSettings->realtimeModeFlowId;
                        }
                    }
                    else if (p_systemStateSettings->udpHRportStart + p_systemStateSettings->udpHRportEnd > 0)
                    {
                        dst_port = ipHeader.getDestinationPort();
                        if (dst_port <= p_systemStateSettings->udpHRportEnd && dst_port >= p_systemStateSettings->udpHRportStart)
                        {
                            flow_id = p_systemStateSettings->ulDuplicateModeFlowId;
                        }
                    }
                    break; //udp
                default:
                    break;
                }
        }
    
    int systemTimeMs = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
    p_systemStateSettings->currentSysTimeMs = systemTimeMs;
	
    if (flow_id == p_systemStateSettings->ulDuplicateModeFlowId || p_systemStateSettings->gDLAllOverLte || p_systemStateSettings->lteSplitFactor > 0 || p_systemStateSettings->gDlRToverLteFlag == 1)
    {
        if (systemTimeMs - p_systemStateSettings->lastReceiveLtePkt > p_systemStateSettings->lteProbeIntervalActive * 1000)
        {
            if (systemTimeMs - p_systemStateSettings->lastSendLteProbe > 60 * 1000) //do not send out probe if the last probe was sent < 1 minutes ago
            {
                p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe();
            }
        }
    }
	
    if (flow_id == p_systemStateSettings->ulDuplicateModeFlowId || !p_systemStateSettings->gDLAllOverLte)
    {
        if (systemTimeMs - p_systemStateSettings->lastReceiveWifiPkt > p_systemStateSettings->WiFiProbeIntervalActive * 1000)
        {
            if (systemTimeMs - p_systemStateSettings->lastSendWifiProbe > 60 * 1000) //do not send out probe if the last probe was sent < 1 minutes ago
                p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe();
        }
        else
        {
            //detect link failure through Tx-to-Rx gap
            if (systemTimeMs - p_systemStateSettings->lastReceiveWifiPkt > p_systemStateSettings->wifiProbeTh)
            {
                if (systemTimeMs - p_systemStateSettings->lastSendWifiProbe > 10 * 1000) //do not send out probe if the last probe was sent < 1 minutes ago
                    p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe();
            }
        }
    }

    int offset = 0;
    gmaDataHeader.init((unsigned char *)buffer, offset); //offset = 0.
   
    int timestampMs = 0;
    if (p_systemStateSettings->gStartTime >= 0)
    {
        timestampMs = (systemTimeMs + p_systemStateSettings->gStartTime) & 0x7FFFFFFF;
    }
    switch (flow_id)
    {
    case 1:
        gmaDataHeader.setUlParams((short)0x7807, p_systemStateSettings->ulDuplicateModeFlowId, (unsigned char)0, timestampMs, snNumber_dup);
        snNumber_dup = (snNumber_dup + 1) & 0x00FFFFFF;
        length += p_systemStateSettings->sizeofUlGmaDataHeader;
        sendHRPacketToServer(buffer, offset, length);
        break;
        // HR
    case 2:
        gmaDataHeader.setUlParams((short)0x7807, p_systemStateSettings->realtimeModeFlowId, (unsigned char)0, timestampMs, snNumber_realtime);
        snNumber_realtime = (snNumber_realtime + 1) & 0x00FFFFFF;
        length += p_systemStateSettings->sizeofUlGmaDataHeader;
        sendRTPacketToServer(buffer, offset, length);
        break;
        // RT
    default:
        gmaDataHeader.setUlParams((short)0x7807, p_systemStateSettings->nonRealtimelModeFlowId, (unsigned char)0, timestampMs, snNumber_default);
        snNumber_default = (snNumber_default + 1) & 0x00FFFFFF;
        length += p_systemStateSettings->sizeofUlGmaDataHeader;
        sendPacketToServer(buffer, offset, length);
        //NRT
        break;
    }
}

void DataSend::updataWifiChannel(GMASocket wifiFd)
{
    wifiudp_fd = wifiFd;
}

void DataSend::updataLteChannel(GMASocket lteFd)
{
    lteudp_fd = lteFd;
}

void DataSend::sendPacketToServer(char *data, int offset, int length)
{
    if (p_systemStateSettings->gDLAllOverLte == false)
    {
        if (wifiudp_fd != GMA_INVALID_SOCKET )
        {
            sendto(wifiudp_fd, data + offset, length, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer));
            p_systemStateSettings->wifiSendBytes += length;
        }
    }
    else // all DL traffic over LTE, uplink traffic also over LTE
    {
        if (lteudp_fd != GMA_INVALID_SOCKET )
        {
            sendto(lteudp_fd, data + offset, length, 0, (struct sockaddr *)&lteServer, sizeof(lteServer));
            p_systemStateSettings->lteSendBytes += length;
        }
    }
}

void DataSend::sendHRPacketToServer(char *data, int offset, int length)
{

    if (wifiudp_fd != GMA_INVALID_SOCKET && p_systemStateSettings->gIsWifiConnect)
    {
        sendto(wifiudp_fd, data + offset, length, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer));
        p_systemStateSettings->wifiSendBytes += length;
    }
    if (lteudp_fd != GMA_INVALID_SOCKET && p_systemStateSettings->gIsLteConnect)
    {
        sendto(lteudp_fd, data + offset, length, 0, (struct sockaddr *)&lteServer, sizeof(lteServer));
        p_systemStateSettings->lteSendBytes += length;
    }
}

void DataSend::sendRTPacketToServer(char *data, int offset, int length)
{
    if (p_systemStateSettings->gDLAllOverLte == false && p_systemStateSettings->gUlRToverLteFlag == 0)
    {
        if (wifiudp_fd != GMA_INVALID_SOCKET)
        {
            sendto(wifiudp_fd, data + offset, length, 0, (struct sockaddr *)&wifiServer, sizeof(wifiServer));
            p_systemStateSettings->wifiSendBytes += length;
        }
    }
    else // all DL traffic over LTE, uplink traffic also over LTE
    {
        if (lteudp_fd != GMA_INVALID_SOCKET)
        {
            sendto(lteudp_fd, data + offset, length, 0, (struct sockaddr *)&lteServer, sizeof(lteServer));
            p_systemStateSettings->lteSendBytes += length;
        }
    }
}

