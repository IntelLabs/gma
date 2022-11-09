//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Methods.cpp

#include "Methods.h"
#include "../GMAlib/include/SystemStateSettings.h"
#include "Client.h"
#include "ServiceManager.h"

#include <sys/time.h>
#include <cstddef>
#include <iostream>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <errno.h>
#include <thread>

#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024


void GetIPAddress(char wifiInterface[], char lteInterface[])
{
    FILE *fp;
    char wifiBuffer[100];
    char lteBuffer[100];
    std::string wifiCmd = "ip -4 -o addr show " + std::string(wifiInterface) + " | awk \'{print $4}\' | cut -d \"/\" -f 1";
    fp = popen_with_return(wifiCmd.c_str(), wifiCmd.size());

    if (fp == NULL)
    {
        return;
    }
    fgets(wifiBuffer, sizeof(wifiBuffer), fp);
    g_systemStateSettings->wifiIpv4Address = std::string(wifiBuffer);
    pclose(fp);
    std::string lteCmd = "ip -4 -o addr show " + std::string(lteInterface) + " | awk \'{print $4}\' | cut -d \"/\" -f 1";
    fp = popen_with_return(lteCmd.c_str(), lteCmd.size());
    if (fp == NULL)
    {
        return;
    }
    fgets(lteBuffer, sizeof(lteBuffer), fp);
    g_systemStateSettings->lteIpv4Address = std::string(lteBuffer);
    pclose(fp);
}

std::string findLoopback()
{
    FILE *fp;
    char buffer[100];
    std::string res = "";
    std::string cmd = "ifconfig lo | grep \"inet \"";
    fp = popen_with_return(cmd.c_str(), cmd.size());
    if (fp != NULL)
    {
        try
        {
            fgets(buffer, sizeof(buffer), fp);
            pclose(fp);
            std::istringstream iss(buffer);
            std::vector<std::string> data;
            std::string item;
            std::copy(std::istream_iterator<std::string>(iss),
                      std::istream_iterator<std::string>(),
                      std::back_inserter(data));
            res = data[1];
        }
        catch (const std::exception &e)
        {
            std::cerr << e.what() << '\n';
        }
    }
    return res;
}


std::string getDNS(char interface[])
{
    std::string dns = "";
    FILE *fp = NULL;
    char buffer[200] = {0};
    //nmcli device show wlan0 | grep IP4.DNS
    std::string dnscmd = "nmcli device show " + std::string(interface) + " | grep IP4.DNS";
    fp = popen_with_return(dnscmd.c_str(), dnscmd.size());
    if(fp != NULL)
    {
        fgets(buffer, sizeof(buffer), fp);
		pclose(fp);
        if(strlen(buffer) > 0)
        {
            //IP4.DNS[n]       x.x.x.x
            std::istringstream iss(buffer);
            std::vector<std::string> data;
            std::copy(std::istream_iterator<std::string>(iss),
                      std::istream_iterator<std::string>(),
                      std::back_inserter(data));
            dns = data[1];
            std::stringstream dnsLog;
            dnsLog << "Find dns for interface " << std::string(interface) << " : " << dns << std::endl;
            g_systemStateSettings->PrintLogs(dnsLog);
        }
    }

    return dns;
}

int getMtu(char interface[])
{
    std::stringstream ss;
    int mtu = 1500;
    std::ifstream fin;
    ss.str(std::string());
    ss << "/sys/class/net/" << interface << "/mtu";
    fin.open(ss.str().c_str());
    std::string line;
    if (std::getline(fin, line))
    {
        char *lineStr = (char *)line.c_str();
        mtu = atoi(lineStr);
        std::cout << ss.str() << ":" << mtu << std::endl;
    }
    fin.close();
    return (mtu);
}


bool LinkRouting(char interface[], std::string serverIP, int ifFlag)  //0: wifi ; 1: lte
{
    try
    {
        char buffer[200] = { 0 };
        char ip[20] = { 0 };
        FILE* fp;

        std::string fetchIP = "ip -4 -o addr show " + std::string(interface) + " | awk \'{print $4}\' | cut -d \"/\" -f 1";
        std::string gateway; 
        fp = popen_with_return(fetchIP.c_str(), fetchIP.size());
        if (fp == NULL)
            return false;

        fgets(ip, sizeof(ip), fp);
        pclose(fp);

        if (strlen(ip) <= 0)
            return false;
        //pclose(fp);
        std::stringstream lteLog;
        if (ifFlag == 1)
            lteLog << "Lte routing..............\n";
        else
            lteLog << "WiFi routing..............\n";

        g_systemStateSettings->PrintLogs(lteLog);
        std::stringstream ss;
        ss << "ip route | grep default | grep " << interface;
        fp = popen_with_return(ss.str().c_str(), ss.str().size());
        if (fp == NULL)
            return false;
        fgets(buffer, sizeof(buffer), fp);
        pclose(fp);

        if (strlen(buffer) <= 0)
        {
            int gwlen = 0;
            if (ifFlag == 1)
                gwlen = clientManager.lastLteRouteGateway.length();
            else
                gwlen = clientManager.lastWifiRouteGateway.length();

            if (gwlen <= 0)
            {
                lteLog.str("");
                lteLog << "Error Wifi(LTE) Gateway\n";
                g_systemStateSettings->PrintLogs(lteLog);
                return false;
            }
           
        }
        else
        {
            std::istringstream iss(buffer);
            std::vector<std::string> data;
            std::string item;
            while (std::getline(iss, item, ' '))
            {
                data.push_back(item);
            }

            if (ifFlag == 1)
                clientManager.lastLteRouteGateway = std::string(data[2].c_str());
            else
                clientManager.lastWifiRouteGateway = std::string(data[2].c_str());
           
        }

        std::string ipstr(ip);
        ipstr.erase(std::remove(ipstr.begin(), ipstr.end(), '\n'), ipstr.end());
        if (ifFlag == 1)
        {
            g_systemStateSettings->lteIpv4Address = ipstr;
            g_systemStateSettings->gLteMTU = getMtu(interface);         //get LTE MTU size
            g_systemStateSettings->lteDnsv4Address = getDNS(interface); //get LTE DNS server ip address
        }
        else
            g_systemStateSettings->wifiIpv4Address = ipstr;
 
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip route delete default via " << clientManager.lastLteRouteGateway.c_str() << " dev " << interface;
        else
            ss << "ip route delete default via " << clientManager.lastWifiRouteGateway.c_str() << " dev " << interface;
       popen_no_msg(ss.str().c_str(), ss.str().size());
   
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip route delete " << serverIP.c_str() << " via " << clientManager.lastLteRouteGateway.c_str() << " dev " << interface;
        else
            ss << "ip route delete " << serverIP.c_str() << " via " << clientManager.lastWifiRouteGateway.c_str() << " dev " << interface;
        popen_no_msg(ss.str().c_str(), ss.str().size());
        
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip rule delete table 6661";
        else
            ss << "ip rule delete table 6660";
       popen_no_msg(ss.str().c_str(), ss.str().size());
        
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip route delete 0.0.0.0/0 table 6661";
        else
            ss << "ip route delete 0.0.0.0/0 table 6660";
        popen_no_msg(ss.str().c_str(), ss.str().size());
        
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip rule add from " << ipstr.c_str() << "/32 table 6661";
        else
            ss << "ip rule add from " << ipstr.c_str() << "/32 table 6660";
        popen_no_msg(ss.str().c_str(), ss.str().size());
        
        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip route add 0.0.0.0/0 via " << clientManager.lastLteRouteGateway.c_str() << " dev " << interface << " table 6661";
        else
            ss << "ip route add 0.0.0.0/0 via " << clientManager.lastWifiRouteGateway.c_str() << " dev " << interface << " table 6660";
        popen_no_msg(ss.str().c_str(), ss.str().size());
        

        ss.str(std::string());
        if (ifFlag == 1)
            ss << "ip route add " << serverIP.c_str() << " via " << clientManager.lastLteRouteGateway.c_str() << " dev " << interface << " metric 666";
        else
            ss << "ip route add " << serverIP.c_str() << " via " << clientManager.lastWifiRouteGateway.c_str() << " dev " << interface << " metric 777";
        popen_no_msg(ss.str().c_str(), ss.str().size());
        
        if (ifFlag == 1)
        {
            ss.str(std::string());
            ss << "ip route add default via " << clientManager.lastLteRouteGateway.c_str() << " dev " << interface << " metric 10";
            popen_no_msg(ss.str().c_str(), ss.str().size());

        }
    }
    catch (const std::exception& e)
    {
        std::stringstream ssError;
        ssError << e.what() << '\n';
        g_systemStateSettings->PrintLogs(ssError);
        return false;
    }

    
    std::stringstream out;
    if (ifFlag == 1)
        out << "Lte routing done ...\n";
    else
        out << "Wifi routing done ...\n";
    g_systemStateSettings->PrintLogs(out);

    return true;
}

void TunRouting(std::string gateway)
{
    std::string dev = "tun0";
    std::stringstream ss;
    ss.str(std::string());
    
    
    ss << "ip route delete default dev tun0";
    popen_no_msg(ss.str().c_str(), ss.str().size());
    
    ss.str(std::string());
    ss << "ip route add default via " << gateway << " dev " << dev << " onlink metric 1";
    popen_no_msg(ss.str().c_str(), ss.str().size());
    
    std::stringstream out;
    out << "Tun routing  done ...\n";
    g_systemStateSettings->PrintLogs(out);
}

void addLteDefaultRoute(char interface[])
{
    FILE *fp;
    char buffer[100] = {0};
    std::stringstream ss;
    ss << "ip route | grep default | grep " << interface;
    fp = popen_with_return(ss.str().c_str(), ss.str().size());
    if (fp == NULL)
    {
        return;
    }
    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);
    if (strlen(buffer) <= 0)
        return;
    std::istringstream iss(buffer);
    std::vector<std::string> data;
    std::string item;

    while (std::getline(iss, item, ' '))
    {
        data.push_back(item);
    }
    const char *gateway = data[2].c_str(); // may catch exception?

    ss.str(std::string());
    ss << "ip route add default via " << gateway << " dev " << interface << " metric 10";
    popen_no_msg(ss.str().c_str(), ss.str().size());
    //std::cout << ss.str() << std::endl;
}

bool WifiCheck(char interface[])
{
    char buffer[200] = {0};
    char ip[20] = {0};
    FILE *fp;

    //verify IPv4 address first?
    std::string fetchIP = "ip -4 -o addr show " + std::string(interface) + " | awk \'{print $4}\' | cut -d \"/\" -f 1";
    fp = popen_with_return(fetchIP.c_str(), fetchIP.size());
    if (fp == NULL)
        return false;
    fgets(ip, sizeof(ip), fp);
    pclose(fp);

    if (strlen(ip) <= 0)
        return false;

    std::stringstream ss;
    ss << "ip route | grep default | grep " << interface;
    fp = popen_with_return(ss.str().c_str(), ss.str().size());

    if (fp == NULL)
        return false;
    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);

    if (strlen(buffer) <= 0)
        return false;

    std::string ipstr(ip); //ip is valid
    ipstr.erase(std::remove(ipstr.begin(), ipstr.end(), '\n'), ipstr.end());
    g_systemStateSettings->wifiIpv4Address = ipstr;
    std::stringstream out;
    out << "Check wifi link ...  ok.." << g_systemStateSettings->wifiIpv4Address << "\n";
    g_systemStateSettings->PrintLogs(out);
    return true;
}

bool LteCheck(char interface[])
{
    char buffer[200] = {0};
    char ip[20] = {0};
    FILE *fp;

    //verify IPv4 address first?
    std::string fetchIP = "ip -4 -o addr show " + std::string(interface) + " | awk \'{print $4}\' | cut -d \"/\" -f 1";
    fp = popen_with_return(fetchIP.c_str(), fetchIP.size());
    if (fp == NULL)
        return false;
    fgets(ip, sizeof(ip), fp);
    pclose(fp);
    if (strlen(ip) <= 0)
        return false;

    std::stringstream ss;
    ss << "ip route | grep default | grep " << interface;
    fp = popen_with_return(ss.str().c_str(), ss.str().size());
    if (fp == NULL)
        return false;

    fgets(buffer, sizeof(buffer), fp);
    pclose(fp);

    if (strlen(buffer) <= 0)
        return false;

    std::string ipstr(ip); //ip is valid
    ipstr.erase(std::remove(ipstr.begin(), ipstr.end(), '\n'), ipstr.end());
    g_systemStateSettings->lteIpv4Address = ipstr;
    g_systemStateSettings->gLteMTU = getMtu(interface);
    std::stringstream out;
    out << "Check lte link ...  ok..." << g_systemStateSettings->lteIpv4Address << "\n";
    g_systemStateSettings->PrintLogs(out);
    return true;
}

void popen_no_msg(const char *cmd, u_int size)
{
    if (size > 500)
    {
        printf("[error] cmd too long: %s", cmd);
    }
    else
    {
        char dst[501] = "";
        strncpy(dst, cmd, 500); /* OK ... but `dst` needs to be NUL terminated */
        dst[500] = '\0';
        std::array<char, 128> buffer;
        std::string result;
        std::shared_ptr<FILE> pipe(popen(dst, "r"), pclose);
        if (!pipe)
            throw std::runtime_error("popen() failed!");
        while (!feof(pipe.get()))
        {
            if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
                result += buffer.data();
        }
        if (!result.empty())
        {
            std::cout << result << "\n";
        }
    }
}

FILE *popen_with_return(const char *cmd, u_int size)
{
    if (size > 500)
    {
        printf("[error] cmd too long: %s", cmd);
        return NULL;
    }
    else
    {
        char dst[501] = "";
        strncpy(dst, cmd, 500); /* OK ... but `dst` needs to be NUL terminated */
        dst[500] = '\0';
        FILE *fp;
        fp = popen(dst, "r");
        return fp;
    }
}


MonitorNetwork::MonitorNetwork()
{
    driverFd = -1;
    nlfd = -1;
    driverThreadId = 0;
}

void MonitorNetwork::DriverMonitor()
{
    driverMonitorRunning = true;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int state;
    int retval;
    int state_smg = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (nlh == NULL)
    {
        std::cout << "Create user netlink socket error: nlh is NULL!\n";
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = 1000; // getpid()
    nlh->nlmsg_flags = 0;

    while (monitorNetwork.networkMonitorRunning)
    {
        driverFd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
        if (driverFd < 0)
        {
            std::cout << "Create user netlink socket error!\n";
            g_systemStateSettings->msleep(1000 * 60);
            continue;
        }
        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = 1000; /* self pid getpid()*/
        src_addr.nl_groups = 0;

        retval = bind(driverFd, (struct sockaddr *)&src_addr, sizeof(src_addr));
        if (retval < 0)
        {
            std::cout << "User netlink socket bind failed\n";
            g_systemStateSettings->closegmasocket(driverFd);
            driverFd = -1;
            g_systemStateSettings->msleep(1000 * 60);
            continue;
        }

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;    //For Linux Kernel
        dest_addr.nl_groups = 0; /* unicast */

        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;

        memset(&msg, 0, sizeof(msg));
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(dest_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        while (monitorNetwork.networkMonitorRunning)
        {
            state = recvmsg(driverFd, &msg, 0);
            if (state < 0)
            {
                g_systemStateSettings->msleep(1000 * 60);
                break;
            }
            char buf[1024] = {0};
            strncpy(buf, (char *)NLMSG_DATA(nlh), 1023);
            buf[1023] = '\0';
            struct kernelMsg *kMsg = (struct kernelMsg *)buf;

            if (!clientManager.isForeground)
            {
                serviceManager.driverRssiReceiver((int)kMsg->flag);
            }
        }
        g_systemStateSettings->closegmasocket(driverFd);
        driverFd = -1;
    }

    free(nlh);

    driverMonitorRunning = false;
}

void MonitorNetwork::OpenDriverMonitor(bool flag)
{
    if (flag && !driverMonitorRunning)
    {
        driverThread = std::thread(&MonitorNetwork::DriverMonitor, this);
        driverThreadId = driverThread.native_handle();
    }
}

void MonitorNetwork::quit()
{
    if (nlfd > 0)
        g_systemStateSettings->closegmasocket(nlfd); // close socket
}

void MonitorNetwork::CloseDriverMonitor(bool flag)
{
    if (flag && driverMonitorRunning)
    {
        g_systemStateSettings->terminateThread(driverThreadId);
        driverThread.join();
        if (driverFd >= 0)
        {
            g_systemStateSettings->closegmasocket(driverFd);
            driverFd = -1;
        }
    }
}

void MonitorNetwork::parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));

    while (RTA_OK(rta, len))
    { 
        if (rta->rta_type <= max)
        {
            tb[rta->rta_type] = rta; // read attr
        }
        rta = RTA_NEXT(rta, len); // get next attr
    }
}

void MonitorNetwork::DriverReset()
{
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;

    int lowRssi = g_systemStateSettings->wifiLowRssi;
    int highRssi = g_systemStateSettings->wifiHighRssi;
    int threshold = 10; //pkt number ;
    struct userInputs input = {lowRssi, highRssi, threshold};
    int state;
    int retval;
    int state_smg = 0;

    if (!driverMonitorRunning)
        return;

    if (driverFd < 0)
    {
        std::cout << "netlink socket error!\n";
        return;
    }
  
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;    //For Linux Kernel
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (nlh == NULL)
    {
        std::cout << "netlink socket error: nlh is NULL!\n";
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = 1000; // getpid()
    nlh->nlmsg_flags = 0;

    strcpy((char *)(NLMSG_DATA(nlh)), (char *)(&input));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    state_smg = sendmsg(driverFd, &msg, 0);
    if (state_smg == -1)
    {
        //printf("Get error sendmsg\n");
    }
    free(nlh);

    return;
}

void MonitorNetwork::monitor()
{
    //netlink example: https://www.arl.wustl.edu/~jdd/NDN/NDN/OSPFN/zebra/rt_netlink.c
    nlfd = -1;
    struct sockaddr_nl local;  // local addr struct
    char buf[8192];            // message buffer
    struct iovec iov;          // message structure
    iov.iov_base = buf;        // set message buffer as io
    iov.iov_len = sizeof(buf); // set size

   
    memset(&local, 0, sizeof(local));

    local.nl_family = AF_NETLINK; // set protocol family
    local.nl_groups = RTMGRP_IPV4_IFADDR;
    local.nl_pid = getpid(); // set out id using current process id

    // initialize protocol message header
    struct msghdr msg;
    {
        msg.msg_name = &local;           // local address
        msg.msg_namelen = sizeof(local); // address size
        msg.msg_iov = &iov;              // io vector
        msg.msg_iovlen = 1;              // io size
    }
    ssize_t status = -1;
    int k = 0;
    
    while (1)
    {
        if (!networkMonitorRunning)
        {
            break;
        }
        status = -1;
        if (nlfd > 0)
        {
            status = recvmsg(nlfd, &msg, 0); 
        }
        if (status <= 0)
        {
            if (nlfd > 0)
                g_systemStateSettings->closegmasocket(nlfd); // close socket
            nlfd = -1;

            while (nlfd < 0)
            {
                nlfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE); // create netlink socket
                if (nlfd < 0)
                {
                    g_systemStateSettings->msleep(5);
                    continue;
                }
                else
                {
                    struct timeval tv;
                    tv.tv_sec = 3600; //3600s rcv timeout
                    tv.tv_usec = 0;
                    setsockopt(nlfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
                    if (bind(nlfd, (struct sockaddr *)&local, sizeof(local)) < 0)
                    { // bind socket
                        g_systemStateSettings->closegmasocket(nlfd);
                        nlfd = -1;
                        continue;
                    }
                    else
                    {
                        k = 0;
                        break;
                    }
                }
            }
            continue;
        }

        if (msg.msg_namelen != sizeof(local))
        {
            g_systemStateSettings->closegmasocket(nlfd); // close socket
            nlfd = -1;
            continue;
        }

        struct nlmsghdr *h;
        int len = 0;
        int l;
        char *ifName;
        struct ifinfomsg *ifi; // structure for network interface info
        struct rtattr *ifn_rta;
        struct rtattr *tmp_rta;

        for (h = (struct nlmsghdr *)buf; status > (ssize_t)sizeof(struct nlmsghdr);)
        {
            h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len)); // get next message
            len = h->nlmsg_len;
            l = len - sizeof(*h);
            if ((l <= 0) || (len > status))
            {
                break;
            }
            status -= NLMSG_ALIGN(len);

            // now we can check message type
            if ((h->nlmsg_type == RTM_NEWADDR) || (h->nlmsg_type == RTM_DELADDR))
            {
                ifi = (struct ifinfomsg *)NLMSG_DATA(h); // get information about changed network interface
                tmp_rta = IFLA_RTA(ifi);
                ifn_rta = NULL;
                while (RTA_OK(tmp_rta, len))
                {
                    if (tmp_rta->rta_type == IFLA_IFNAME)
                    {
                        ifn_rta = tmp_rta;
                        break;
                    }
                    tmp_rta = RTA_NEXT(tmp_rta, len); // get next attr
                }
                if (ifn_rta)
                {                                       // validation
                    ifName = (char *)RTA_DATA(ifn_rta); // get network interface name
                    switch (h->nlmsg_type)
                    {
                    case RTM_DELADDR:
                    {
                        FILE *fp = NULL;
                        std::string cmd = "ip -4 -o addr show " + std::string(ifName);
                        char cmdbuf[100] = {0};
                        int i = 0;
                        fp = popen_with_return(cmd.c_str(), cmd.size());
                        while (fp == NULL && i < 3)
                        {
                            i++;
                            fp = popen_with_return(cmd.c_str(), cmd.size());
                        }
                        if (fp == NULL)
                            break;
                        else
                        {
                            fgets(cmdbuf, sizeof(cmdbuf), fp);
                            pclose(fp);
                        }

                        if (strlen(cmdbuf) > 0) //error delete
                        {
                            break;
                        }
                        if (strcmp(ifName, clientManager.wifiInterface) == 0)
                        {

                            DriverReset();

                            if (clientManager.isForeground)
                            {
                                clientManager.onLost(clientManager.wifiInterface);
                            }
                            else
                            {
                                serviceManager.onLost(serviceManager.wifiInterface);
                            }
                        }
                        else if (strcmp(ifName, clientManager.lteInterface) == 0)
                        {
                            if (clientManager.isForeground)
                            {
                                clientManager.onLost(clientManager.lteInterface);
                            }
                            else
                            {
                                serviceManager.onLost(serviceManager.lteInterface);
                            }
                        }
                        else
                        {
                        }
                    }
                    break;
                    case RTM_NEWADDR:
                    {   g_systemStateSettings->msleep(1000); //To make sure the address is added?
                        FILE *fp = NULL;
                        std::string cmd = "ip -4 -o addr show " + std::string(ifName);
                        char cmdbuf[100] = {0};
                        fp = popen_with_return(cmd.c_str(), cmd.size());
                        if (fp != NULL)
                        {
                            fgets(cmdbuf, sizeof(cmdbuf), fp);
                            pclose(fp);
                        }
                        else
                            break;

                        if (strlen(cmdbuf) == 0) //error new addr
                        {
                            break;
                        }
                        if (strcmp(ifName, clientManager.wifiInterface) == 0)
                        {
                            if (clientManager.isForeground)
                            {
                                clientManager.onAvailable(clientManager.wifiInterface);
                            }
                            else
                            {
                                serviceManager.onAvailable(serviceManager.wifiInterface);
                            }
                        }
                        else if (strcmp(ifName, clientManager.lteInterface) == 0)
                        {
                            if (clientManager.isForeground)
                            {
                                clientManager.onAvailable(clientManager.lteInterface);
                            }
                            else
                            {
                                serviceManager.onAvailable(serviceManager.lteInterface);
                            }
                        }
                        else
                        {
                        }
                    }
                    break;
                    default:
                        break;
                    }
                }
            }
        }
    }

    if (nlfd > 0)
        g_systemStateSettings->closegmasocket(nlfd); // close socket
}

MonitorNetwork monitorNetwork;