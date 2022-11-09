//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : TcpReceive.h

#ifndef _TCPRECEIVE_H
#define _TCPRECEIVE_H
#include <condition_variable>
#include <mutex>
#include <string>
#include "Header.h"
#include "SystemStateSettings.h"

class TcpReceive{

public:
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void UpdateNetwork(std::string network);
    void OpenTcpSocketChannel();
    void CloseTcpSocketChannel();
    bool StartRecvMsg();
    void WakeupTcpSocketChannel();
    void Execute();
    bool ReceiveMsg();
    void ExitThread();
    bool updateSettings(int cid, std::string network);
    bool tcpReceiveOn;
    
private:
    int cid;
    GMASocket tcpSocketChannel = GMA_INVALID_SOCKET;
    GMASocket udp = GMA_INVALID_SOCKET;
    struct sockaddr_in udpInaddr;
    struct sockaddr udpAddr;

    std::mutex waitforBegin_mtx;
    std::condition_variable waitforBegin;
    std::string network = "";//Ipv4 wifi or lte address
    static const int buf_size = 45; //2 bytes length, 4 bytes gma header, 11bytes payload, 16bytes tag, 12bytes iv
    GMAMessageHeader gmaMessageHeader;
    unsigned char buf[buf_size];
    static const int plaintext_size = 11;
    unsigned char plainText[plaintext_size];
    bool select_block = false;
    bool isTcpRunning;
    int pipefd[2];//wakeup mechanism
    bool ThreadBusy = false;
    bool wakeUpOn = false;
    SystemStateSettings *p_systemStateSettings = NULL;


};

#endif