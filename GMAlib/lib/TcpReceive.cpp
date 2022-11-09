//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : TcpReceive.cpp

#if defined(__unix__) || defined(__APPLE__)
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#elif defined(_WIN32) || defined(_WIN64) 
#define NOMINMAX
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#endif

#include "../include/TcpReceive.h"
#include "../include/SystemStateSettings.h"
#include "../include/Common.h"
#include "../include/EncryptorAesGcm.h"

#include <openssl/rand.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <cstring>



void TcpReceive::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    this->p_systemStateSettings = p_systemStateSettings;
}

bool TcpReceive::updateSettings(int cid, std::string network)
{
    socklen_t len;

    this->isTcpRunning = true;
    this->cid = cid;
    this->network = network;
    std::stringstream logs;
    
    if (this->udp != GMA_INVALID_SOCKET)
    {
        p_systemStateSettings->closegmasocket(this->udp);
    }
    this->udp = GMA_INVALID_SOCKET;
    memset(&udpInaddr, 0, sizeof(udpInaddr));
    memset(&udpAddr, 0, sizeof(udpAddr));


    memset(buf, 0, buf_size);
    memset(plainText, 0 ,plaintext_size);
    select_block = false;

    udp= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == GMA_INVALID_SOCKET)
    {
        return false;
    }
    udpInaddr.sin_family = AF_INET;
    udpInaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udpInaddr.sin_port = 0;
    if (bind(udp, (struct sockaddr*)&udpInaddr, sizeof(udpInaddr)) != 0)
        return false;
    len = sizeof(udpAddr);
    if (getsockname(udp, &udpAddr, &len) != 0)
        return false;
    if (connect(udp, &udpAddr, len) != 0)
        return false;

    this->tcpReceiveOn = true;
    return true;
}

void TcpReceive::UpdateNetwork(std::string network)
{
    this->network = network;
}

void TcpReceive::OpenTcpSocketChannel()
{
    std::stringstream logs;
    if (tcpSocketChannel ==GMA_INVALID_SOCKET && network.length() > 0)
    {
        std::string serverIp;
        if (cid == p_systemStateSettings->wifiCid)
        {
            serverIp = p_systemStateSettings->serverWifiTunnelIp;
        }
        else
        {
            serverIp = p_systemStateSettings->serverLteTunnelIp;
        }

        try
        {
            tcpSocketChannel = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcpSocketChannel == GMA_INVALID_SOCKET)
            {
                logs.str("");
                logs << "[ERROR] tcpSocketChannel == -1"<< std::endl;
                p_systemStateSettings->PrintLogs(logs);
                return;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
            tcpSocketChannel = GMA_INVALID_SOCKET;
            return;
        }

        if (tcpSocketChannel != GMA_INVALID_SOCKET)
        {
            //bind to network
            struct sockaddr_in local;
            local.sin_family = AF_INET;
            local.sin_port = htons(0);
            local.sin_addr.s_addr = inet_addr(network.c_str());
            try {
                if (bind(tcpSocketChannel, (struct sockaddr*)&local, sizeof(local)))
                {
                    logs.str("");
                    logs << "back ground service [TCP socket]channel bind false, cid: " << cid << std::endl;
                    p_systemStateSettings->PrintLogs(logs);
                    CloseTcpSocketChannel();
                    return;
                }
            }
            catch (const std::exception& e)
            {
                std::stringstream ss;
                ss << e.what() << std::endl;
                p_systemStateSettings->PrintLogs(ss);
                CloseTcpSocketChannel();
                return;
            }

        }
        else
        {
            logs.str("");
            logs << "back ground service [TCP socket] channel still null, cid:" << cid << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            return;
        }
        try
        {
            int nodelay_flag = 1;
            if (setsockopt(tcpSocketChannel, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay_flag, sizeof(int)) )
            {
                logs.str("");
                logs << "Set tcp nodelay error\n";
                p_systemStateSettings->PrintLogs(logs);
                return ;
            }
            int opt = 1;
            if (setsockopt(tcpSocketChannel, SOL_SOCKET, SO_REUSEADDR,
                           (char *)&opt, sizeof(opt)))
            {
                logs.str("");
                logs << "Set error 2\n";
                p_systemStateSettings->PrintLogs(logs);
                return ;
            }
            opt = 1;
            if (setsockopt(tcpSocketChannel, SOL_SOCKET, SO_KEEPALIVE, (char *)&opt, sizeof(opt)))
            {
                logs.str("");
                logs << "Set keep_alive error??\n";
                p_systemStateSettings->PrintLogs(logs);
                return ;
            }

            struct sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(p_systemStateSettings->serverTcpPort);
            if (inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr) <= 0)
            {
                logs.str("");
                logs << "Invalid address/ Address not supported \n";
                p_systemStateSettings->PrintLogs(logs);
                return;
            }
            // int flag = fcntl(tcpSocketChannel, F_GETFL);
            // fcntl(tcpSocketChannel, F_SETFL, flag | O_NONBLOCK); //socket non-blocking

            logs.str("");
            logs << "C/S S-check " << p_systemStateSettings->serverTcpPort << " : " << serverIp << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            logs.str("");
            logs << "C/S C-check " << network << " : " << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            if (connect(tcpSocketChannel, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
            {
                logs.str("");
                logs << "Connection Failed \n";
                p_systemStateSettings->PrintLogs(logs);
                return;
            }
        }
        catch (const std::exception &e)
        {
            logs.str("");
            logs << e.what() << '\n';
            p_systemStateSettings->PrintLogs(logs);
            tcpSocketChannel = GMA_INVALID_SOCKET;
            return;
        }

        if (tcpSocketChannel == GMA_INVALID_SOCKET)
        {
            return ;
        }

     
        if (!StartRecvMsg())
        {
            return;
        }
        
        int systemTimeMs = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
        if (cid == p_systemStateSettings->wifiCid)
        {
            p_systemStateSettings->lastReceiveWifiWakeUpReq = systemTimeMs; //ms    WiFi
        }
        else
        {
            p_systemStateSettings->lastReceiveLteWakeUpReq = systemTimeMs; //ms    LTE
        }
        //send the first wakeup request message
        // / length(2B)/ GMA header / Type (1B) / CID (1B) / Key (4B) / SN (2B) / Vender ID (2B) / Sub-type (1B) /
        //the GMA header includes, 2bytes flag and 2 bytes client id.
        memset(buf, 0, buf_size);
        memset(plainText, 0 ,plaintext_size);
        int totalBytes;
        gmaMessageHeader.init(buf, 2);
        if (p_systemStateSettings->enable_encryption)
        {
            gmaMessageHeader.setGMAMessageHeader((short)0x800F); //encrypted control
            gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
            totalBytes = 43;
        }
        else
        {
            gmaMessageHeader.setGMAMessageHeader((short)0x8000); //plain text, only client ID
            gmaMessageHeader.setGmaClientId((short)p_systemStateSettings->clientId);
            totalBytes = 15; //4 bytes gma header, 11 bytes payload. THE total transmission byte will also add 2 bytes length
        }

        buf[0] = (unsigned char)((totalBytes & 0xFF00) >> 8);
        buf[1] = (unsigned char)(totalBytes & 0x00FF);

        plainText[0] = (unsigned char)255; // type = 255
        plainText[1] = (unsigned char)cid; //CID = 0

        int keyValue = 0;
        plainText[2] = (unsigned char)((keyValue & 0xFF000000) >> 24);
        plainText[3] = (unsigned char)((keyValue & 0x00FF0000) >> 16);
        plainText[4] = (unsigned char)((keyValue & 0x0000FF00) >> 8);
        plainText[5] = (unsigned char)(keyValue & 0x000000FF);

        plainText[6] = (unsigned char)((p_systemStateSettings->controlMsgSn & 0x0000FF00) >> 8);
        plainText[7] = (unsigned char)(p_systemStateSettings->controlMsgSn & 0x000000FF);          //g sn\

        p_systemStateSettings->controlMsgSn = (p_systemStateSettings->controlMsgSn + 1) & 0x0000FFFF; //2 bytes

        int vendorId = 0;
        plainText[8] = (unsigned char)((vendorId & 0x0000FF00) >> 8);
        plainText[9] = (unsigned char)(vendorId & 0x000000FF);

        plainText[10] = (unsigned char)6; // sub-type = 6

        if (tcpSocketChannel != GMA_INVALID_SOCKET)
        {
            try
            {
                if (p_systemStateSettings->enable_encryption)
                {
                    
                    int aad_len = 4;
                    unsigned char aad[4];
                    int tag_len = 16;
                    unsigned char tags[16];
                    int iv_len = 12;
                    unsigned char iv[12];

                    memset(aad, 0, aad_len);
                    memset(tags, 0, tag_len);
                    memset(iv, 0, iv_len);

                    memcpy(aad, buf + 2, 4);

                    unsigned char cipher[256];
                    memset(cipher, 0, sizeof(cipher));

                    if (RAND_bytes(iv, iv_len))
                    {
                        EncryptorAesGcm encryptorAesGcm;

                        int ret = encryptorAesGcm.Encrypt((unsigned char*)plainText, sizeof(plainText),
                            (unsigned char*)aad, aad_len,
                            (unsigned char*)(p_systemStateSettings->aesKey.c_str()),
                            (unsigned char*)iv, iv_len, (unsigned char*)cipher, tags);
                        if (!ret)
                        {
                            printf("\n AesGCM Encryption failed \n");
                        }
                        else
                        {
                            memcpy(buf + 6, cipher, plaintext_size);
                            memcpy(buf + 6 + plaintext_size, tags, tag_len);
                            memcpy(buf + 6 + plaintext_size + tag_len, iv, iv_len);
                            if (send(tcpSocketChannel, (char*)buf, buf_size, 0) < 0)
                            {
                                logs.str("");
                                logs << "TCP send message error\n";
                                p_systemStateSettings->PrintLogs(logs);
                            }
                        }
                    }
                }
                else
                {
                    memcpy(buf + 6, plainText, plaintext_size);
                    if (send(tcpSocketChannel, (char *)buf, 6 + plaintext_size, 0) < 0)
                    {
                        logs.str("");
                        logs << "TCP send message error\n";
                        p_systemStateSettings->PrintLogs(logs);
                    }
                }
            }
            catch (const std::exception &e)
            {
                logs.str("");
                logs << e.what() << '\n';
                p_systemStateSettings->PrintLogs(logs);
            }
        }

        logs.str("");
        logs << "TcpSocektChannel, creating new one. TcpSOcketChannel: " << tcpSocketChannel
                  << " network: " << network << " cid: " << cid << std::endl;
        p_systemStateSettings->PrintLogs(logs);
        
    }
    else
    {
        logs.str("");
        logs << "TcpSocektChannel, not creating new one(existed). TcpSOcketChannel: " << tcpSocketChannel
                  << " network: " << network << " cid: " << cid << std::endl;
        p_systemStateSettings->PrintLogs(logs);
    }
}

bool TcpReceive::StartRecvMsg()
{
    std::stringstream logs;
    if (tcpSocketChannel != GMA_INVALID_SOCKET)
    {
        if (select_block)
        {
            logs << "TCP SOCKET CHANNEL, Select block =============== cid: " << cid << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            wakeUpOn = true;
            char buf[1];
            buf[0] = 'x';
            sendto(udp, (char*)buf, 1, 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
            return false;
        }
        else
        {
            try
            {
                waitforBegin.notify_one();
                logs.str("");
                logs << "TcpSocketChannel, StartRecvMsg  \n";
                p_systemStateSettings->PrintLogs(logs);
                return true;
            }
            catch (const std::exception &e)
            {
                logs.str("");
                logs << e.what() << '\n';
                p_systemStateSettings->PrintLogs(logs);
            }
        }
    }
    return false;
}

void TcpReceive::WakeupTcpSocketChannel()
{
    if (tcpSocketChannel != GMA_INVALID_SOCKET)
    {
        wakeUpOn = true;
        char buf[10];
        buf[0] = 'x';
        sendto(udp, (char*)buf, 10, 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr));
    }
}

void TcpReceive::CloseTcpSocketChannel()
{
    if (tcpSocketChannel != GMA_INVALID_SOCKET)
    {
        try
        {
            p_systemStateSettings->closegmasocket(tcpSocketChannel);
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
        tcpSocketChannel = GMA_INVALID_SOCKET;
        std::stringstream ss;
        ss << "TCP Socket Channel, STOP receive thread\n";
        p_systemStateSettings->PrintLogs(ss);
    }
}

void TcpReceive::Execute()
{
    std::stringstream logs;
    fd_set socks;
    ThreadBusy = true;
    char recvbuff[100];
    try
    {
        while (isTcpRunning)
        {
            logs.str("");
            logs << "TCP SOCKET CHANNEL, Receive thread wait --------------- cid: " << cid << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            std::unique_lock<std::mutex> waitLck(waitforBegin_mtx);
            waitforBegin.wait(waitLck); // sychronized lock

            logs.str("");
            logs << "TCP SOCKET CHANNEL, Receive thread start --------------- cid: " << cid << std::endl;
            p_systemStateSettings->PrintLogs(logs);
            select_block = true;
            while (tcpSocketChannel != GMA_INVALID_SOCKET)
            {
                //restart the wake-up socket if there is no activity in an hour
                //wait for the first msg (segment to arrive), no timeout for this case
                int systemTimeMs = (int)(p_systemStateSettings->update_current_time_params() & 0x7FFFFFFF);
                if (cid == p_systemStateSettings->wifiCid)
                {
                    p_systemStateSettings->lastReceiveWifiWakeUpReq = systemTimeMs; //ms    WiFi
                }
                else
                {
                    p_systemStateSettings->lastReceiveLteWakeUpReq = systemTimeMs; //ms    LTE
                }
                FD_ZERO(&socks);
                FD_SET(tcpSocketChannel, &socks);
                FD_SET(udp, &socks);
                GMASocket nsocks = std::max(tcpSocketChannel, udp) + 1;

                if (select(nsocks, &socks, (fd_set *)0, (fd_set *)0, 0) > 0)
                {
                    if (FD_ISSET(tcpSocketChannel, &socks))
                    {
                        //recv message
                        logs.str("");
                        logs << "TCP SOCKET CHANNEL, Start ReceiveMsg\n";
                        p_systemStateSettings->PrintLogs(logs);
                        if (!ReceiveMsg())
                            break;
                    }
                    if (FD_ISSET(udp, &socks))
                    {

                        recv(udp, recvbuff, sizeof(recvbuff), 0);
                        if (wakeUpOn)
                        {
                            wakeUpOn = false;
                            logs.str("");
                            logs << "Wake up select and break....\n";
                            p_systemStateSettings->PrintLogs(logs);
                            break;
                        }
                    }
                }
                else
                {
                    logs.str("");
                    logs << "TCP Select Error\n";
                    p_systemStateSettings->PrintLogs(logs);
                    break;
                }
            }
            select_block = false;
            CloseTcpSocketChannel();
            logs.str("");
            logs << "TCP SOCKET CHANNEL, Receive thread stop =============== cid: " << cid << std::endl;
            p_systemStateSettings->PrintLogs(logs);
        }
    }
    catch (const std::exception &e)
    {
        logs.str("");
        logs << e.what() << '\n';
        p_systemStateSettings->PrintLogs(logs);
    }
    ThreadBusy = false;
}

bool TcpReceive::ReceiveMsg()
{
    //in this function, we may receive multiple segments of a control message. For example, a 17 bytes message maybe be receive after multiple reads (when totalReadBytes = length/payload).
    //after receiving the first segment of a msg, we wait for at most MSG_SEGMENTATION_WATI_TIMEOUT before closing this connection (it will be re-opened later)
    std::stringstream logs;
    struct timeval waitTimeout;
    waitTimeout.tv_sec = (int)(p_systemStateSettings->wakeupMsgSegWaitTimeout / 1000); //wait 10 seconds for the first wakeup message;
    waitTimeout.tv_usec = (p_systemStateSettings->wakeupMsgSegWaitTimeout % 1000) * 1000;

    //step 1: receive the 2 bytes length field;
    int lengthFieldBytes = 2; //2 bytes for length field
    char *buffer = new char[lengthFieldBytes];
    memset(buffer, 0, lengthFieldBytes);
 	int readBytes = recv(tcpSocketChannel, buffer, lengthFieldBytes, 0);
    
    int totalReadBytes = readBytes;

    if (lengthFieldBytes == totalReadBytes)
    {
        int payloadBytes = buffer[0] + buffer[1] * 256;
        logs << "TCP SOCKET CHANNEL, receive a message byte: "
                  << totalReadBytes << " payload length: " << payloadBytes << std::endl;
        p_systemStateSettings->PrintLogs(logs);
        if (payloadBytes > 0)
        {
            char *buffer2 = new char[payloadBytes]; //allocate bytes for payload
            memset(buffer2, 0, payloadBytes);
            readBytes = recv(tcpSocketChannel, buffer2, payloadBytes, 0); //read first segment
          
            totalReadBytes = readBytes;
            while (totalReadBytes < payloadBytes && readBytes > 0) //the read size is smaller than expected payload, wait for more segments to come
            {
                readBytes = 0;

                fd_set socks;
                FD_ZERO(&socks);
                FD_SET(tcpSocketChannel, &socks);
                GMASocket nsocks = tcpSocketChannel + 1;
                logs.str("");
                logs << "TCP SOCKET CHANNEL, payload not complete, continue...\n";
                p_systemStateSettings->PrintLogs(logs);
                if (select(nsocks, &socks, NULL, NULL, &waitTimeout) > 0)
                {
                    readBytes = recv(tcpSocketChannel, buffer2 + totalReadBytes, payloadBytes - totalReadBytes, 0);
                    totalReadBytes += readBytes;
                }
                else
                {
                    logs.str("");
                    logs << "TCP SOCKET CHANNEL, TIMEOUT, stop waiting\n";
                    p_systemStateSettings->PrintLogs(logs);
                    break;
                }
            }

            if (payloadBytes == totalReadBytes) //received payload of the control msg
            {
                logs.str("");
                logs << "TCP SOCKET CHANNEL, receive a message byte: "
                          << totalReadBytes << " type: " << (buffer2[4] & 0x00FF)
                          << " subtype: " << (buffer2[14] & 0x00FF) << " cid: " << (buffer2[5] & 0x00FF) << std::endl;
                p_systemStateSettings->PrintLogs(logs);
                //receive successful, send probe over wifi and lte!!!
                if (cid == p_systemStateSettings->wifiCid)
                {
                    //receive from wifi, send probe over wifi
                    p_systemStateSettings->GMAIPCMessage(2,0,0,false,0); //controlManager.sendWifiProbe();
                }
                else
                {
                    //receive from lte, send probe over LTE
                    p_systemStateSettings->GMAIPCMessage(3,0,0,false,0); //controlManager.sendLteProbe();
                }
                delete[] buffer;
                delete[] buffer2;
                return true;
            }
            else
            {
                logs.str("");
                logs << "TCP SOCKET CHANNEL, Received less bytes (" << totalReadBytes
                          << ") in payload, we should close the socket and build a new one..\n";
                p_systemStateSettings->PrintLogs(logs);
                delete[] buffer2;
            }
        }
        else
        {
            logs.str("");
            logs << "TCP SOCKET CHANNEL, payload == 0 bytes, error\n";
            p_systemStateSettings->PrintLogs(logs);
        }
    }
    else
    {
        //msg receive incomplete, close the connection.
        logs.str("");
        logs << "TCP SOCKET CHANNEL, Received less bytes " << totalReadBytes << " in length field, we should close the socket and build a new one..\n";
        p_systemStateSettings->PrintLogs(logs);
    }

    delete[] buffer;
    return false;
}

void TcpReceive::ExitThread()
{
    this->isTcpRunning = false;
    while (ThreadBusy)
    {
        this->WakeupTcpSocketChannel();
        waitforBegin.notify_all();
        p_systemStateSettings->msleep(1);
    }
    if(udp != GMA_INVALID_SOCKET)
    {
        p_systemStateSettings->closegmasocket(udp);
    }
    udp = GMA_INVALID_SOCKET;
 
    this->tcpReceiveOn = false;
    this->wakeUpOn = false;
}

