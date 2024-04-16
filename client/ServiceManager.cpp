//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ServiceManager.cpp


#include "ServiceManager.h"
#include "root_certificates.hpp"
#include <string.h>
#include <csignal>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <iostream>
#include <csignal>
#include <climits>
#include <errno.h>

#include "Methods.h"
#include "Client.h"
#include "../GMAlib/include/SystemStateSettings.h"
#include "../GMAlib/include/DataReceive.h"
#include "../GMAlib/include/DataSend.h"
#include "../GMAlib/include/ControlMessage.h"
#include "../GMAlib/include/ReorderingManager.h"
#include "../GMAlib/include/Measurement.h"
#include "../GMAlib/include/VirtualWebsockets.h"
#include "../GMAlib/include/Common.h"

ServiceManager serviceManager;

bool ServiceManager::isServiceRunning = false;
int cntService = 0;
int restart_cnt = 0;

ServiceManager::ServiceManager()
{
    isServiceRunning = false;
    wifiServer = {0};
    lteServer = {0};
    communicateForeground = 0;
    dataReceiveID = 0;
    rssiReceiverID = 0;
    wifiTcpReceiveThreadID = 0;
    lteTcpReceiveThreadID = 0;
    wifiChannel = GMA_INVALID_SOCKET;
    lteChannel = GMA_INVALID_SOCKET;
    udploopFd = GMA_INVALID_SOCKET;
    //udpInaddr.sin_family = {};
    //udpInaddr.sin_port = 0;
    udpAddr = {0};
    udpInaddr = {0};
}

void ServiceManager::initUnitSystemStateSettings(SystemStateSettings *p_systemStateSettings)
{
    controlManager.initUnitSystemStateSettings(p_systemStateSettings);
    wifiTcpReceive.initUnitSystemStateSettings(p_systemStateSettings);
    lteTcpReceive.initUnitSystemStateSettings(p_systemStateSettings);
    dataSend.initUnitSystemStateSettings(p_systemStateSettings);
    dataReceive.initUnitSystemStateSettings(p_systemStateSettings);
    virtualWss.initUnitSystemStateSettings(p_systemStateSettings);
}

void ServiceManager::Quit()
{
    while (start_service_busy)
    {
        printf("\n wait for startService to complete \n");
        g_systemStateSettings->msleep(1000);
    }
    handler(3);
}

void ServiceManager::Test()
{
    popen_no_msg("sudo nmcli device disconnect wlan0", 35);
    popen_no_msg("sudo nmcli device disconnect usb0", 34);
}

void ServiceManager::foreground2background()
{
    start_service_busy = true;

    if (monitorNetwork.networkMonitorRunning)
    {
        LinkRouting(clientManager.lteInterface, g_systemStateSettings->serverLteTunnelIp, 1);
        LinkRouting(clientManager.wifiInterface, g_systemStateSettings->serverWifiTunnelIp, 0);
        isServiceRunning = true;
        clientManager.isForeground = false;
        g_systemStateSettings->updateSystemSettings(); 
        g_systemStateSettings->gWifiFlag = true;
        g_systemStateSettings->gLteFlag = true;
        startCloseService = false;
        g_systemStateSettings->isControlManager = true;
        initUnitSystemStateSettings(g_systemStateSettings);
        updateInterface(clientManager.wifiInterface, clientManager.lteInterface, clientManager.serverAddress);
        setParameters();
        if (!startService())
        {
            //fail to start background service
            clientManager.isForeground = true;
            g_systemStateSettings->gWifiFlag = false;
            g_systemStateSettings->gLteFlag = false;
            isServiceRunning = false;
            g_systemStateSettings->isControlManager = false;
        }
    }
    start_service_busy = false;
}

void ServiceManager::cancelThread()
{

    restart_cnt++;
    if (wifiChannel != GMA_INVALID_SOCKET)
        g_systemStateSettings->closegmasocket(wifiChannel);

    if (lteChannel != GMA_INVALID_SOCKET)
        g_systemStateSettings->closegmasocket(lteChannel);

    wifiChannel = GMA_INVALID_SOCKET;
    lteChannel = GMA_INVALID_SOCKET;

    
    controlManager.cancelThread();
   
    if (rssiReceiverID != 0)
    {
        while (rssi_thread_busy)
        {
            rssi_cv.notify_all();
            g_systemStateSettings->msleep(1);
        }
        rssiReceiverThread.join();
        rssiReceiverID = 0;
    }
    printf("close rssi receiver\n");

    if (dataReceiveID != 0)
    {
        while (dataReceive.ThreadBusy)
        {
            dataReceive.wakeupSelect();
            g_systemStateSettings->msleep(1);
        }
        dataReceiveThread.join();
        dataReceiveID = 0;
        dataReceive.ExitThread();
    }
    printf("close dataReceive\n");

    dataReceive.closeReordering();

    if (wifiTcpReceiveThreadID != 0) 
    {
        wifiTcpReceive.ExitThread();
        wifiTcpReceiveThread.join();
        wifiTcpReceiveThreadID = 0;
    }

    if (lteTcpReceiveThreadID != 0) 
    {
        lteTcpReceive.ExitThread();
        lteTcpReceiveThread.join();
        lteTcpReceiveThreadID = 0;
    }

}

void ServiceManager::handler(int signal)
{

    if (startCloseService)
        return;

    if (inHandler && signal == 0)
    {
        return;
    }

    if (inHandler && signal == last_sig)
    {
        return;
    }

    last_sig = signal;

    if (signal == 3)
        startCloseService = true;

    while (inHandler)
    {
        g_systemStateSettings->msleep(1000);
    }
    inHandler = true;

    switch (signal)
    {
    case sig_buildtun: //0
    {
        if (!g_systemStateSettings->gTunAvailable)
        {
            int tunfd = -1;

            tunfd = configureVirtualTun();

            if (tunfd < 0)
            {
                std::cout << "Config tun fd error!\n";
            }
            else
            {

                g_systemStateSettings->gTunAvailable = true;
                std::stringstream ss;
                ss << "Prepare to build virtual websockets....\n";
                g_systemStateSettings->PrintLogs(ss);

                net::io_context ioc;
                ssl::context ctx{ssl::context::tlsv13_client};
                load_root_certificates(ctx);
                virtualWss.updateSettings(ioc, ctx);
                int count = 0;
                virtualWss.sendResumeReq();
                while (count < 10 && !virtualWss.virtualWebsocketsLastMsg)
                {
                    count++;
                    virtualWss.sendResumeReq();
                    g_systemStateSettings->msleep(1000);
                }
                virtualWss.Clear();
            }

            if (!startCloseService)
            {
                if (!virtualWss.virtualWebsocketsLastMsg || tunfd < 0)
                {
                    std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
                    eventThread.detach();
                }
                else
                {
                    controlManager.notifyMRPCycle();
                }
            }
        }
        break;
    }
    
    case sig_resume: //2
    {
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv13_client};
        load_root_certificates(ctx);
        while (virtualWss.connectServerRunning)
        {
            g_systemStateSettings->msleep(1000);
        }
        g_systemStateSettings->gStartTime = -1;
        virtualWss.updateSettings(ioc, ctx);
        virtualWss.sendResumeReq();
        virtualWss.Clear();
        if (g_systemStateSettings->gStartTime < 0 && !startCloseService)
        {
            std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
            eventThread.detach();
        }

        break;
    }
    case sig_fail: //3 both link failure or TSU failure or speed < 10 && disconnect > 10 mins or virtual websockets failure
    {
        bool checkExitEnabled = false;
        
        if (isServiceRunning)
        {
            g_systemStateSettings->gLteFlag = false;
            g_systemStateSettings->gWifiFlag = false;
            if (g_systemStateSettings->gTunAvailable)
                checkExitEnabled = true;
            g_systemStateSettings->gTunAvailable = false;
            g_systemStateSettings->gIsWifiConnect = false;
            g_systemStateSettings->gIsLteConnect = false;
            g_systemStateSettings->gISVirtualWebsocket = false;
            g_systemStateSettings->isControlManager = false;
      
            if (tun.server_read_tun_thread_id != 0)
            {
                while (tun_thread_busy)
                {
                    printf("\n **** waiti for tun thread to exit **** \n");
                    wakeupSelect();
                    g_systemStateSettings->msleep(1000);
                }

                tun.server_read_tun_thread_id = 0;
                tunReceiveThread.join();
            }
            tun_server_exit();

            try
            {
                while (virtualWss.connectServerRunning)
                {
                    g_systemStateSettings->msleep(1000);
                }
            }
            catch (boost::system::system_error const &e)
            {
                std::stringstream ss;
                ss << e.what() << std::endl;
                ss << "virtual websocket closing failed\n";
                g_systemStateSettings->PrintLogs(ss);
            }
            cancelThread();
            g_systemStateSettings->aesKey.resize(g_systemStateSettings->aesKey.capacity(), '\0');
            OPENSSL_cleanse(&g_systemStateSettings->aesKey[0], g_systemStateSettings->aesKey.size());
            g_systemStateSettings->aesKey.clear();
            g_systemStateSettings->aesKeyString.resize(g_systemStateSettings->aesKeyString.capacity(), '\0');
            OPENSSL_cleanse(&g_systemStateSettings->aesKeyString[0], g_systemStateSettings->aesKeyString.size());
            g_systemStateSettings->aesKeyString.clear();
        }
        clientManager.checkExit(checkExitEnabled);
        isServiceRunning = false;
        startCloseService = false;
        break;
    }
    case sig_stop: //4: stop cellular connection  (no need as cellular is ALWAYS connected)
        break;
    case sig_start: //5: start celluar connection (not need as cellular is ALWAYS connected)
        break;
    default:
        break;
    }
    inHandler = false;
}

void ServiceManager::OpenWifiTcpSocketChannel()
{
    if (wifiTcpReceive.tcpReceiveOn)
    {
        wifiTcpReceive.OpenTcpSocketChannel();
    }
}

void ServiceManager::OpenLteTcpSocketChannel()
{
    if (lteTcpReceive.tcpReceiveOn)
    {
        lteTcpReceive.OpenTcpSocketChannel();
    }
}

void ServiceManager::CloseWifiTcpSocketChannel()
{
    if (wifiTcpReceive.tcpReceiveOn)
    {
        wifiTcpReceive.WakeupTcpSocketChannel();
    }
}

void ServiceManager::CloseLteTcpSocketChannel()
{
    if (lteTcpReceive.tcpReceiveOn)
    {
        lteTcpReceive.WakeupTcpSocketChannel();
    }
}

void ServiceManager::vnic_tun_read_thread()
{
    tun_thread_busy = true;
    unsigned int n_Bytes = 0;
    int MAX_PACKET_SIZE = 1500;
    char tmp[10000] = {0};
    char udpbuff[100];
    char *tun_buf = tmp + g_systemStateSettings->sizeofUlGmaDataHeader;
    int size = MAX_PACKET_SIZE - g_systemStateSettings->sizeofUlGmaDataHeader;
    GMASocket nsocks;
    int ret;
    fd_set rd_set;
    dataSend.updateSettings(); //init some variables of data send class
    while (tun.tun_fd >= 0 && g_systemStateSettings->isControlManager)
    {
        FD_ZERO(&rd_set);
        if (tun.tun_fd >= 0)
            FD_SET(tun.tun_fd, &rd_set);
        if (udploopFd != GMA_INVALID_SOCKET)
            FD_SET(udploopFd, &rd_set);
        nsocks = std::max(tun.tun_fd, udploopFd) + 1;
        ret = select(nsocks, &rd_set, NULL, NULL, 0);

        if (ret < 0)
        {
            continue;
        }

        if (FD_ISSET(tun.tun_fd, &rd_set))
        {
            n_Bytes = read(tun.tun_fd, tun_buf, size);
        }

        if (FD_ISSET(udploopFd, &rd_set))
        {
            ret = recv(udploopFd, udpbuff, sizeof(udpbuff), 0);
            if (ret <= 0)
            {
                g_systemStateSettings->closegmasocket(udploopFd);
                udploopFd = GMA_INVALID_SOCKET;
                setupUdpSocket(); 
            }
            std::stringstream logs;
            logs.str("");
            logs << "tun read wake up select and break....\n";
            g_systemStateSettings->PrintLogs(logs);
            continue;
        }

        if (n_Bytes <= 0)
        {
            continue;
        }
        else
        {
            if (g_systemStateSettings->gIsWifiConnect || g_systemStateSettings->gIsLteConnect)
            {
                dataSend.processPackets(tmp, n_Bytes);
            }
        }
    }
    tun_thread_busy = false;
}

int ServiceManager::tun_create(const char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    if (*dev)
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        g_systemStateSettings->closegmasocket(fd);
        return -1;
    }
    return fd;
}

int ServiceManager::tun_server_init(const char *vnic_ip, const char *vnic_mask)
{

    tun.tun_fd = tun_create("tun0", IFF_TUN | IFF_NO_PI);
    if (tun.tun_fd < 0)
    {
        return -1;
    }
    return 0;
}

bool ServiceManager::config_tun_interface(unsigned char *tun_ip,
                                          unsigned char *tun_mask, unsigned int tun_mtu, const char *forward_interface)
{
    if (!setupUdpSocket())
        return false;
   
    char conf[500] = {0};
    char ip[50] = {0};
    char mask[50] = {0};
    int mask_num = 0;
    char subnet[50] = {0};

    std::string dns = "\"" + g_systemStateSettings->serverVnicDns + "," + g_systemStateSettings->lteDnsv4Address + "\"";
    std::stringstream ss;

    sprintf(ip, "%d.%d.%d.%d", tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3]);
    sprintf(mask, "%d.%d.%d.%d", tun_mask[0], tun_mask[1], tun_mask[2], tun_mask[3]);

    unsigned char net[4];
    *(unsigned char *)net = (*(unsigned int *)tun_ip) & (*(unsigned int *)tun_mask);
    sprintf(subnet, "%d.%d.%d.%d", net[0], net[1], net[2], net[3]);

    for (int i = 0, n = *(int *)tun_mask; i < 32; i++)
    {
        if ((n & 1) == 1)
        {
            ++mask_num;
            n >>= 1;
        }
        else
        {
            break;
        }
    }
   
    memset(conf, 0, sizeof(conf));
    sprintf(conf, "ifconfig tun0 %s netmask %s up", ip, mask);
    popen_no_msg(conf, 500);

    memset(conf, 0, sizeof(conf));
    sprintf(conf, "ifconfig tun0 mtu %d", tun_mtu);
    popen_no_msg(conf, 500);

    ss.str(std::string());
    ss << "nmcli connection modify tun0 "
       << " ipv4.dns " << dns;
    popen_no_msg(ss.str().c_str(), ss.str().size());

    ss.str(std::string());
    ss << "nmcli connection down tun0 ";
    popen_no_msg(ss.str().c_str(), ss.str().size());

    ss.str(std::string());
    ss << "nmcli connection up tun0 ";
    popen_no_msg(ss.str().c_str(), ss.str().size());

    memset(conf, 0, sizeof(conf));
    sprintf(conf, "ifconfig tun0 %s netmask %s", ip, mask);
    popen_no_msg(conf, 500);

  
    return true;
}

int ServiceManager::tun_write(char *buf, int pkt_len)
{
    int nwrite = -1;
    if (serviceManager.tun.tun_fd >= 0)
    {
        nwrite = write(serviceManager.tun.tun_fd, buf, pkt_len);
    }
    if (nwrite < 0)
    {
        return -1;
    }
    else 
        return nwrite;
}

void ServiceManager::tun_server_exit(void)
{
    try
    {
        if (tun.tun_fd >= 0)
            close(tun.tun_fd);
        tun.tun_fd = -1;

        if (udploopFd != GMA_INVALID_SOCKET)
        {
            g_systemStateSettings->closegmasocket(udploopFd);
        }
        udploopFd = GMA_INVALID_SOCKET;

        popen_no_msg("ip link delete tun0", 20);
    }
    catch (const std::exception &e)
    {
        std::cout << e.what() << '\n';
    }
}

void ServiceManager::wakeupSelect()
{
    if (udploopFd != GMA_INVALID_SOCKET)
    {
        char buf[1];
        buf[0] = 'x';
        if (sendto(udploopFd, (char*)buf, 1, 0, (struct sockaddr*)&udpAddr, sizeof(udpAddr)) == -1)
         std::cout << "error" << "\n";
    }
}

bool ServiceManager::startService()
{
    g_systemStateSettings->LogFileOpen();
    g_systemStateSettings->wifiLinkRtt = 1000; //reset probe rtx timeout
    g_systemStateSettings->wifiLinkCtrlRtt = 1000;
    g_systemStateSettings->wifiLinkCtrlOwd = INT_MAX;
    g_systemStateSettings->wifiProbeTimeout = 1000;
    configureLteChannel();
    if (lteChannel != GMA_INVALID_SOCKET)
    {
        dataReceive.updataLteChannel(lteChannel);
        dataSend.updataLteChannel(lteChannel);
    }
    else
    {
        std::cout << "Error create lte udp socket\n";
        return false;
    }
    configureWifiChannel();
    if (wifiChannel != GMA_INVALID_SOCKET)
    {
        dataReceive.updataWifiChannel(wifiChannel);
        dataSend.updataWifiChannel(wifiChannel);
    }
    else
    {
        std::cout << "Error create wifi udp socket\n";
        return false;
    }

  
    dataReceive.startReordering();

    if (wifiTcpReceive.updateSettings(g_systemStateSettings->wifiCid, g_systemStateSettings->wifiIpv4Address))
    {
        try
        {
            wifiTcpReceiveThread = std::thread(&TcpReceive::Execute, &wifiTcpReceive);
            wifiTcpReceiveThreadID = (std::thread::native_handle_type)1;
        }
        catch (const std::system_error &e)
        {
            std::cout << "Caught system_error with code " << e.code()
                      << " meaning " << e.what() << '\n';
            wifiTcpReceiveThreadID = 0;
        }

        if (lteTcpReceive.updateSettings(g_systemStateSettings->lteCid, g_systemStateSettings->lteIpv4Address))
        {
            try
            {
                lteTcpReceiveThread = std::thread(&TcpReceive::Execute, &lteTcpReceive);
                lteTcpReceiveThreadID = (std::thread::native_handle_type)1; // lteTcpReceiveThread.native_handle();
            }
            catch (const std::system_error &e)
            {
                std::cout << "Caught system_error with code " << e.code()
                          << " meaning " << e.what() << '\n';
                lteTcpReceiveThreadID = 0;
            }
            if (dataReceive.updateSettings())
            {
                try
                {
                    dataReceiveThread = std::thread(std::bind(&DataReceive::listenSockets, &dataReceive));
                    dataReceiveID = (std::thread::native_handle_type)1; // dataReceiveThread.native_handle();
                }
                catch (const std::system_error &e)
                {
                    std::cout << "Caught system_error with code " << e.code()
                              << " meaning " << e.what() << '\n';
                    dataReceiveID = 0;
                }
            }
        }
    }
    controlManager.startThread();

    try
    {
        rssiReceiverThread = std::thread(&ServiceManager::rssiReceiver, this, g_systemStateSettings->rssiInterval);
        rssiReceiverID = (std::thread::native_handle_type)1; 
    }
    catch (const std::system_error &e)
    {
        std::cout << "Caught system_error with code " << e.code()
                  << " meaning " << e.what() << '\n';
        rssiReceiverID = 0;
    }
    
    std::stringstream ss;
    ss << "Notify Lte and wifi Probes now!!!!\n";
    g_systemStateSettings->PrintLogs(ss);

    controlManager.UpdateWifiParams(wifiChannel, this->wifiServer);
    controlManager.UpdateLteParams(lteChannel, this->lteServer);
    return true;
}

void ServiceManager::updateWifiChannel()
{
    configureWifiChannel();
    if (wifiChannel != GMA_INVALID_SOCKET)
    {
        dataReceive.updataWifiChannel(wifiChannel);
        dataSend.updataWifiChannel(wifiChannel);
        controlManager.UpdateWifiParams(wifiChannel, wifiServer);
    }
    else
    {
        printf("\n update Wi-Fi channel failed \n");
    }
}

void ServiceManager::updateLteChannel()
{
    configureLteChannel();
    if (lteChannel != GMA_INVALID_SOCKET)
    {
        dataReceive.updataLteChannel(lteChannel);
        dataSend.updataLteChannel(lteChannel);
        controlManager.UpdateLteParams(lteChannel, lteServer);
    }
    else
    {
        printf("\n update LTE channel failed \n");
    }
}

void ServiceManager::configureLteChannel()
{
    struct sockaddr_in local;
    try
    {
        if (lteChannel != GMA_INVALID_SOCKET)
        {
            g_systemStateSettings->closegmasocket(lteChannel);
        }
        lteChannel = socket(AF_INET, SOCK_DGRAM, 0);
        if (lteChannel == GMA_INVALID_SOCKET)
        {
            std::stringstream ss;
            ss << "[error] cannot open lte channel socket!!!!\n";
            g_systemStateSettings->PrintLogs(ss);
        }
    }
    catch (const std::exception &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        g_systemStateSettings->PrintLogs(ss);
        lteChannel = GMA_INVALID_SOCKET;
    }

    if (lteChannel == GMA_INVALID_SOCKET)
    {
        return;
    }

    int sndbuf_size = 6000000;
    int size_len = sizeof(sndbuf_size);

    int flag = fcntl(lteChannel, F_GETFL);
   
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    local.sin_addr.s_addr = inet_addr(g_systemStateSettings->lteIpv4Address.c_str()); //internal lte ip 192.168.0.9
    try
    {
        if (bind(lteChannel, (struct sockaddr *)&local, sizeof(local)))
        {
            g_systemStateSettings->closegmasocket(lteChannel);
            lteChannel = GMA_INVALID_SOCKET;
            return;
        }

        if (setsockopt(lteChannel, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, size_len) ||
            setsockopt(lteChannel, SOL_SOCKET, SO_RCVBUF, &sndbuf_size, size_len))
        {
            g_systemStateSettings->closegmasocket(lteChannel);
            lteChannel = GMA_INVALID_SOCKET;
            return;
        }
    }
    catch (const std::exception &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        g_systemStateSettings->PrintLogs(ss);
        g_systemStateSettings->closegmasocket(lteChannel);
        lteChannel = GMA_INVALID_SOCKET;
    }

    return;
}

void ServiceManager::configureWifiChannel()
{
    try
    {
        if (wifiChannel != GMA_INVALID_SOCKET)
        {
            g_systemStateSettings->closegmasocket(wifiChannel);
        }

        wifiChannel = socket(AF_INET, SOCK_DGRAM, 0);
        if (wifiChannel == GMA_INVALID_SOCKET)
        {
            std::stringstream ss;
            ss << "[error] cannot open wifi channel socket!!!!\n";
            g_systemStateSettings->PrintLogs(ss);
        }
    }
    catch (const std::exception &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        g_systemStateSettings->PrintLogs(ss);
        wifiChannel = GMA_INVALID_SOCKET;
    }

    if (wifiChannel == GMA_INVALID_SOCKET)
    {
        return;
    }
    int sndbuf_size = 6000000; //buffer size in bytes
    int size_len = sizeof(sndbuf_size);
    int flag = fcntl(wifiChannel, F_GETFL);
   
    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = htons(0);
    local.sin_addr.s_addr = inet_addr(g_systemStateSettings->wifiIpv4Address.c_str()); //internal ip:192.168.2.9
    try
    {
        if (bind(wifiChannel, (struct sockaddr *)&local, sizeof(local)))
        {
            g_systemStateSettings->closegmasocket(wifiChannel);
            wifiChannel = GMA_INVALID_SOCKET;
            return;
        }

        if (setsockopt(wifiChannel, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, size_len) ||
            setsockopt(wifiChannel, SOL_SOCKET, SO_RCVBUF, &sndbuf_size, size_len))
        {
            g_systemStateSettings->closegmasocket(wifiChannel);
            wifiChannel = GMA_INVALID_SOCKET;
            return;
        }
    }
    catch (const std::exception &e)
    {
        std::stringstream ss;
        ss << e.what() << std::endl;
        g_systemStateSettings->PrintLogs(ss);
        g_systemStateSettings->closegmasocket(wifiChannel);
        wifiChannel = GMA_INVALID_SOCKET;
    }

    return;
}

void ServiceManager::updateInterface(char wifi[], char lte[], char server[])
{
    memcpy(wifiInterface, wifi, sizeof(wifiInterface) - 1);
    wifiInterface[sizeof(wifiInterface) - 1] = '\0';
    memcpy(lteInterface, lte, sizeof(lteInterface) - 1);
    lteInterface[sizeof(lteInterface) - 1] = '\0';
    memcpy(serverAddress, server, sizeof(serverAddress) - 1);
    serverAddress[sizeof(serverAddress) - 1] = '\0';
}

void ServiceManager::initClient()
{
}

void ServiceManager::setParameters()
{
    struct sockaddr_in mwifiServer = {0};
    struct sockaddr_in mlteServer = {0};
    mwifiServer.sin_addr.s_addr = inet_addr(g_systemStateSettings->serverWifiTunnelIp.c_str());
    mwifiServer.sin_family = AF_INET;
    mwifiServer.sin_port = htons(g_systemStateSettings->serverWifiTunnelPort);

    mlteServer.sin_addr.s_addr = inet_addr(g_systemStateSettings->serverLteTunnelIp.c_str());
    mlteServer.sin_family = AF_INET;
    mlteServer.sin_port = htons(g_systemStateSettings->serverLteTunnelPort);

    wifiServer = mwifiServer;
    lteServer = mlteServer;

    controlManager.updateSystemSettings();
    dataReceive.updateReorderingAndMeasurement();
    dataSend.updateServerAddress(mwifiServer, mlteServer);

}

int ServiceManager::configureVirtualTun()
{
 
    if (tun_server_init(NULL, NULL) < 0)
        return (-1);

    bool tun_set_up = false;

    if (g_systemStateSettings->gLteMTU < g_systemStateSettings->gNetWorkInterfaceMinMTU)
    {
        g_systemStateSettings->gNetWorkInterfaceMinMTU = g_systemStateSettings->gLteMTU;
    }
    g_systemStateSettings->gVnicMTU = g_systemStateSettings->gNetWorkInterfaceMinMTU - 28 - g_systemStateSettings->sizeofDlGmaDataHeader;

    unsigned char g_vnic_gateway[4], g_vnic_mask[4];
    std::vector<std::string> splitGateway, splitMask;
    std::string tmp;
    std::istringstream s_gate(g_systemStateSettings->serverVnicIp);
    std::istringstream s_mask(g_systemStateSettings->serverVnicMsk);
    while (std::getline(s_gate, tmp, '.'))
    {
        splitGateway.push_back(tmp);
    }
    while (std::getline(s_mask, tmp, '.'))
    {
        splitMask.push_back(tmp);
    }

    for (int i = 0; i < 4; i++)
    {
        g_vnic_gateway[i] = atoi(splitGateway[i].c_str());
        g_vnic_mask[i] = atoi(splitMask[i].c_str());
    }
    //
    std::stringstream log;
    log << g_systemStateSettings->serverVnicGw << std::endl;
    g_systemStateSettings->PrintLogs(log);
    log.str("");
    log << g_systemStateSettings->serverVnicIp << std::endl;
    g_systemStateSettings->PrintLogs(log);
    tun_set_up = config_tun_interface(g_vnic_gateway, g_vnic_mask,
                                      g_systemStateSettings->gVnicMTU, NULL);
    if (tun_set_up)
    {

        try
        {
            tunReceiveThread = std::thread(&ServiceManager::vnic_tun_read_thread, this);
            tun.server_read_tun_thread_id = (std::thread::native_handle_type)1;
        }
        catch (const std::system_error &e)
        {
            std::cout << "Caught system_error with code " << e.code()
                      << " meaning " << e.what() << '\n';
            tun.server_read_tun_thread_id = 0;
        }
   
        if (tun.server_read_tun_thread_id == 0)
        {
            close(tun.tun_fd);
            tun.tun_fd = -1;
            return (-1);
        }
        else
        {
            TunRouting(g_systemStateSettings->serverVnicGw);
            std::stringstream ss;
            ss << "Successfully build tun now ..\n";
            g_systemStateSettings->PrintLogs(ss);
            return tun.tun_fd;
        }
    }
    else
        return (-1);
   
}

void ServiceManager::onAvailable(char *interface)
{
    if (startCloseService || !g_systemStateSettings->gTunAvailable || !g_systemStateSettings->isControlManager)
        return;

    if (strcmp(interface, lteInterface) == 0) // Lte onAvailable
    {
        if (g_systemStateSettings->gLteFlag)
        {
            return;
        }

        if (LinkRouting(lteInterface, g_systemStateSettings->serverLteTunnelIp, 1))
        {
            clientManager.lteNetworkConnected = true;
            std::cout << "on Available lte \n";
            g_systemStateSettings->gLteFlag = true;
            g_systemStateSettings->stopLterequest = true;
            if (lteTcpReceive.tcpReceiveOn)
            {
                lteTcpReceive.UpdateNetwork(g_systemStateSettings->lteIpv4Address);
            }
            configureLteChannel();
            if (lteChannel != GMA_INVALID_SOCKET)
            {
                if (dataReceive.updataLteChannel(lteChannel))
                {
                    //controlManager.sendWifiProbe(); //trigger to add LTE socket to select in dataReceive

                    dataSend.updataLteChannel(lteChannel);
                    controlManager.UpdateLteParams(lteChannel, lteServer);
              
                    if (g_systemStateSettings->gWifiFlag && !g_systemStateSettings->gIsWifiConnect && wifiChannel > 0)
                    {
                        dataReceive.updataWifiChannel(wifiChannel);
                        dataSend.updataWifiChannel(wifiChannel);
                        controlManager.UpdateWifiParams(wifiChannel, wifiServer);
                        controlManager.notifyLRPCycle(true, (unsigned char)1); //1: connect event
                    }
                }
                else
                {
                    g_systemStateSettings->gLteFlag = false;
                    g_systemStateSettings->stopLterequest = false;
                }
            }
            else
            {
                std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
                eventThread.detach();
            }
        }
    }
    else if (strcmp(interface, wifiInterface) == 0) //Wifi onAvailable
    {
        if (g_systemStateSettings->gWifiFlag)
        {
            return;
        } 
        
        if (LinkRouting(wifiInterface, g_systemStateSettings->serverWifiTunnelIp, 0))
        {
            clientManager.wifiNetworkConnected = true;
            std::cout << "on Available wifi \n";
            g_systemStateSettings->gWifiFlag = true;
            g_systemStateSettings->wifiLinkRtt = 1000; //reset probe rtx timeout
            g_systemStateSettings->wifiLinkCtrlRtt = 1000;
            g_systemStateSettings->wifiLinkCtrlOwd = INT_MAX;

            g_systemStateSettings->wifiProbeTimeout = 1000;
            if (wifiTcpReceive.tcpReceiveOn)
            {
                wifiTcpReceive.UpdateNetwork(g_systemStateSettings->wifiIpv4Address);
            }
            configureWifiChannel();
            if (wifiChannel == GMA_INVALID_SOCKET)
            {
                std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
                eventThread.detach();
            }
            if (g_systemStateSettings->gLteFlag)
            {
                dataReceive.updataWifiChannel(wifiChannel);
                //controlManager.sendLteProbe(); //trigger to add LTE socket to select in dataReceive
                dataSend.updataWifiChannel(wifiChannel);
                controlManager.UpdateWifiParams(wifiChannel, wifiServer);
                controlManager.notifyLRPCycle(true, (unsigned char)1);
            }
            else
            {
            }
        }
    }
}

void ServiceManager::onLost(char *interface)
{

    if (startCloseService || !g_systemStateSettings->gTunAvailable || !g_systemStateSettings->isControlManager)
        return;

    if (strcmp(interface, wifiInterface) == 0)
    {
        clientManager.wifiNetworkConnected = false;
        g_systemStateSettings->gIsWifiConnect = false;
        g_systemStateSettings->gWifiFlag = false;
        g_systemStateSettings->numOfWifiLinkFailure++;
        g_systemStateSettings->wifiRssi = 0;
        dataSend.updataWifiChannel(-1);
        dataReceive.closeWifiChannel();
        controlManager.UpdateWifiParams(-1, wifiServer);
        if (!g_systemStateSettings->gLteFlag)
        {
            std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
            eventThread.detach();
            std::cout << "onLost : lte & wifi\n";
        }
        else
        {
            g_systemStateSettings->gIsLteConnect = true;
            if (wifiChannel != GMA_INVALID_SOCKET)
            {
                try
                {
                    g_systemStateSettings->closegmasocket(wifiChannel);
                }
                catch (const std::exception &e)
                {
                    std::cerr << e.what() << '\n';
                }
                wifiChannel = GMA_INVALID_SOCKET;
            }

            if (wifiTcpReceive.tcpReceiveOn)
            {
                wifiTcpReceive.WakeupTcpSocketChannel();
            }
            {
                g_systemStateSettings->wifiSplitFactor = 0;
                g_systemStateSettings->lteSplitFactor = g_systemStateSettings->paramL;
                g_systemStateSettings->gDLAllOverLte = true;
                controlManager.sendTSUMsg();
                controlManager.sendLteProbe(); //reset Lte probe interval
            }

            controlManager.notifyLRPCycle(false, (unsigned char)0); //0: disconnect event

            g_systemStateSettings->gDisconnectWifiTime = (int)(g_systemStateSettings->update_current_time_params() & 0x7FFFFFFF); //update only if Wi-Fi link is lost
            std::cout << "onLost : wifi\n";
        }
    }
    else if (strcmp(interface, lteInterface) == 0)
    {
        clientManager.lteNetworkConnected = false;
        g_systemStateSettings->gIsLteConnect = false;
        g_systemStateSettings->gLteFlag = false;
        g_systemStateSettings->numOfLteLinkFailure++;
        g_systemStateSettings->lteRssi = 0;
        dataSend.updataLteChannel(-1);
        dataReceive.closeLteChannel();
        controlManager.UpdateLteParams(-1, lteServer);
        if (!g_systemStateSettings->gIsWifiConnect)
        {
            std::thread eventThread(&ServiceManager::handler, &serviceManager, 3);
            eventThread.detach();
            std::cout << "onLost : lte & wifi\n";
        }
        else
        {
            if (lteChannel != GMA_INVALID_SOCKET)
            {
                try
                {
                    g_systemStateSettings->closegmasocket(lteChannel);
                }
                catch (const std::exception &e)
                {
                    std::cerr << e.what() << '\n';
                }
                lteChannel = GMA_INVALID_SOCKET;
            }
            if (lteTcpReceive.tcpReceiveOn)
            {
                lteTcpReceive.WakeupTcpSocketChannel();
            }
            {
                g_systemStateSettings->wifiSplitFactor = g_systemStateSettings->paramL;
                g_systemStateSettings->lteSplitFactor = 0;
                g_systemStateSettings->gDLAllOverLte = false;
                controlManager.sendTSUMsg();
                controlManager.sendWifiProbe(); //reset WiFi probe interval
            }
            g_systemStateSettings->gDisconnectLteTime = (int)(g_systemStateSettings->update_current_time_params() & 0x7FFFFFFF); //update only if Wi-Fi link is lost
        }
        std::cout << "onLost: lte\n";
        g_systemStateSettings->wifiProbeTh = INT_MAX;
        g_systemStateSettings->wifiProbeTimeout = 1000;
    }
}

void ServiceManager::driverRssiReceiver(int status)
{
    if (startCloseService)
        return;

    if (status == 0 && g_systemStateSettings->gIsLteConnect && !g_systemStateSettings->gDLAllOverLte)
    {
        g_systemStateSettings->wifiSplitFactor = 0;
        g_systemStateSettings->lteSplitFactor = g_systemStateSettings->paramL;
        controlManager.sendTSUMsg();
        g_systemStateSettings->wifiIndexChangeAlpha = 0;
        g_systemStateSettings->gDLAllOverLte = true;
        controlManager.sendLteProbe(); //reset LTE probe timer
    }
    else if (status == 1 && g_systemStateSettings->gIsWifiConnect && g_systemStateSettings->gDLAllOverLte)
    {
        g_systemStateSettings->gDLAllOverLte = false;
        g_systemStateSettings->wifiSplitFactor = g_systemStateSettings->paramL;
        g_systemStateSettings->lteSplitFactor = 0;
        controlManager.sendTSUMsg();
        controlManager.sendWifiProbe(); //reset WiFi probe interval
        g_systemStateSettings->wifiIndexChangeAlpha = 0;
    }
}

void ServiceManager::rssiReceiver(int interval)
{
    rssi_thread_busy = true;
    FILE *fp = NULL;
    char buffer[200] = {0};
    //wifi device
    std::unique_lock<std::mutex> lck(rssi_mtx);
    std::string cmd = "iw dev " + std::string(wifiInterface) + " link |grep signal ";
    // Link Quality=xx/xx  Signal level=-xx dBm
    while (g_systemStateSettings->isControlManager)
    {
        fp = popen_with_return(cmd.c_str(), cmd.size());
        if (fp == NULL)
        {
            rssi_cv.wait_for(lck, std::chrono::seconds(interval));
            continue;
        }
        fgets(buffer, sizeof(buffer), fp);
        pclose(fp);

        if (strlen(buffer) > 0) //Wifi is closed...
        {
            std::istringstream iss(buffer);
            std::vector<std::string> tokens{std::istream_iterator<std::string>(iss),
                                            std::istream_iterator<std::string>()};
            g_systemStateSettings->wifiRssi = std::stoi(tokens[1]);
            iss.clear();

            if (g_systemStateSettings->wifiRssi < g_systemStateSettings->wifiHighRssi && !g_systemStateSettings->gLteFlag)
            {
            }
            else if (g_systemStateSettings->wifiRssi < g_systemStateSettings->wifiLowRssi && g_systemStateSettings->gIsLteConnect && !g_systemStateSettings->gDLAllOverLte)
            {
                g_systemStateSettings->wifiSplitFactor = 0;
                g_systemStateSettings->lteSplitFactor = g_systemStateSettings->paramL;
                controlManager.sendTSUMsg();
                g_systemStateSettings->wifiIndexChangeAlpha = 0;
                g_systemStateSettings->gDLAllOverLte = true;
                controlManager.sendLteProbe(); //reset LTE probe timer
            }
            else if (g_systemStateSettings->wifiRssi > g_systemStateSettings->wifiHighRssi && g_systemStateSettings->gIsWifiConnect && g_systemStateSettings->gDLAllOverLte)
            {
                g_systemStateSettings->gDLAllOverLte = false;
                g_systemStateSettings->wifiSplitFactor = g_systemStateSettings->paramL;
                g_systemStateSettings->lteSplitFactor = 0;
                controlManager.sendTSUMsg();
                controlManager.sendWifiProbe(); //reset WiFi probe interval
                g_systemStateSettings->wifiIndexChangeAlpha = 0;
            }
        }
        rssi_cv.wait_for(lck, std::chrono::seconds(interval));
    }

    rssi_thread_busy = false;
}

bool ServiceManager::setupUdpSocket()
{
    unsigned int len;
    udploopFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udploopFd == GMA_INVALID_SOCKET)
    {
        return false;
    }
    udpInaddr.sin_family = AF_INET;
    udpInaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udpInaddr.sin_port = 0;
    if (bind(udploopFd, (struct sockaddr *)&udpInaddr, sizeof(udpInaddr)) != 0)
    {
        close(udploopFd);
        udploopFd = GMA_INVALID_SOCKET;
        return false;
    }

    len = sizeof(udpAddr);
    if (getsockname(udploopFd, &udpAddr, &len) != 0)
    {
        close(udploopFd);
        udploopFd = GMA_INVALID_SOCKET;
        return false;
    }

    if (connect(udploopFd, &udpAddr, len) != 0)
    {
        close(udploopFd);
        udploopFd = GMA_INVALID_SOCKET;
        return false;
    } 
    return true;
}
