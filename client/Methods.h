//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Methods.h
#ifndef _METHODS_H
#define _METHODS_H
#include <string>
#include <vector>
#include <pthread.h>
#include <thread>
#include <linux/rtnetlink.h>

#include "Client.h"

struct Message
{
    std::string host;
    std::string port;
    std::string text;
};

std::string findLoopback();

void PrintLogs(std::stringstream& ss, bool enabled);
void GetIPAddress(char wifiInterface[], char lteInterface[]);
bool LinkRouting(char interface[], std::string serverIp, int ifFlag);
int getMtu(char interface[]);
std::string getDNS(char interface[]);
bool WifiCheck(char wifiInterface[]);
bool LteCheck(char lteInterface[]);
void addLteDefaultRoute(char lteInterface[]);
void TunRouting(std::string gateway);

void popen_no_msg(const char* cmd, u_int size);
FILE * popen_with_return(const char* cmd, u_int size);


struct userInputs{
  int lowRssi;
  int highRssi;
  int threshold;

};

struct kernelMsg{
  int rssi;
  short flag; // flag=1 high state, flag=0 low state
};



class MonitorNetwork{

public:
    std::thread driverThread;
    std::thread::native_handle_type driverThreadId;
    bool driverMonitorRunning = false;
    bool networkMonitorRunning = false;
    int driverFd;
    int nlfd;
    MonitorNetwork();
    void DriverMonitor();
    void OpenDriverMonitor(bool flag);
    void CloseDriverMonitor(bool flag);
    void monitor();
    void quit();
    void DriverReset();
    void parseRtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
};

extern MonitorNetwork monitorNetwork;

#endif