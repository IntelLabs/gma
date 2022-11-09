//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ServiceManager.h

#ifndef _SERVICE_MANAGER_H
#define _SERVICE_MANAGER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <thread>
#include <pthread.h>
#include <mutex>
#include <condition_variable>
#include "../GMAlib/include/VirtualWebsockets.h"
#include "../GMAlib/include/TcpReceive.h"
#include "../GMAlib/include/SystemStateSettings.h"
#include "../GMAlib/include/Header.h"
#include "../GMAlib/include/ControlMessage.h"
#include "../GMAlib/include/DataReceive.h"
#include "../GMAlib/include/DataSend.h"

class ServiceManager
{

public:
    char wifiInterface[100];
    char lteInterface[100];
    char serverAddress[20];
    GMASocket wifiChannel = GMA_INVALID_SOCKET;
    GMASocket lteChannel = GMA_INVALID_SOCKET;
    GMASocket udploopFd = GMA_INVALID_SOCKET;
    struct sockaddr_in udpInaddr;
    struct sockaddr udpAddr;

    struct sockaddr_in wifiServer;
    struct sockaddr_in lteServer;
    short communicateForeground;

    std::thread serviceThread;
    std::thread dataReceiveThread;
    std::thread rssiReceiverThread;
    std::thread wifiTcpReceiveThread;
    std::thread lteTcpReceiveThread;
    std::thread tunReceiveThread;
   
    std::thread::native_handle_type dataReceiveID;
    std::thread::native_handle_type rssiReceiverID;
    std::thread::native_handle_type wifiTcpReceiveThreadID;
    std::thread::native_handle_type lteTcpReceiveThreadID;

    std::mutex rssi_mtx;
    std::condition_variable rssi_cv;
    
    
    ControlManager controlManager;
    TcpReceive wifiTcpReceive;
    TcpReceive lteTcpReceive;
    DataSend dataSend;
    DataReceive dataReceive;
    VirtualWebsockets virtualWss;


    enum
    {
        sig_buildtun = 0,
        sig_terminate,
        sig_resume,
        sig_fail,
        sig_stop,
        sig_start
    };
    static bool isServiceRunning;
    bool startCloseService = false;
    bool inHandler = false;
    bool tun_thread_busy = false;
    bool rssi_thread_busy = false;
    bool start_service_busy = false;
    int last_sig = -1;
    ServiceManager();
    void initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings);
    void foreground2background();
    void updateInterface(char wifi[], char lte[], char server[]);
    void initClient();
    void setParameters();
    void handler(int signal);
    bool startService();
    void configureLteChannel();
    void configureWifiChannel();
    int configureVirtualTun();
    void cancelThread();
    bool setupUdpSocket();

    void OpenWifiTcpSocketChannel();
    void OpenLteTcpSocketChannel();
    void CloseWifiTcpSocketChannel();
    void CloseLteTcpSocketChannel();

    void updateWifiChannel();
    void updateLteChannel();

    void onAvailable(char *interfaceName);
    void onLost(char *interfaceName);
    void rssiReceiver(int interval);
    void driverRssiReceiver(int status); //0: low ; 1: high
    void Quit();

    int pipefd[2];
    void vnic_tun_read_thread();
    struct tun_server
    {
        int tun_fd;
        char tun_read_buf[10000];
        std::thread::native_handle_type server_read_tun_thread_id = 0;
    } tun;
    int tun_create(const char *dev, int flags);
    int tun_write(char *buf, int pkt_len);
    int tun_server_init(const char *vnicIp, const char *vnicMsk);
    bool config_tun_interface(unsigned char *tun_ip,
                              unsigned char *tun_mask, unsigned int tun_mtu, const char *forward_interface);
    void tun_server_exit();
    void wakeupSelect();

    void Test();
};

extern ServiceManager serviceManager;

#endif