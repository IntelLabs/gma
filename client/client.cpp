//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : client.cpp


#include "root_certificates.hpp"

#include <cstdlib>
#include <cstdint>
#include <functional>
#include <iostream>
#include <fstream>
#include <regex>

#include <vector>
#include <chrono>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "../GMAlib/include/SystemStateSettings.h"
#include "../GMAlib/include/ConnectServer.h"
#include "../GMAlib/include/Common.h"
#include "Client.h"
#include "ServiceManager.h"
#include "Methods.h"


namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;
using address = boost::asio::ip::address;
using ptree = boost::property_tree::ptree;
namespace pt = boost::property_tree;

ClientManager clientManager;

SystemStateSettings* g_systemStateSettings;

void load_config()
{
    std::ifstream fin;
    fin.open("/home/gmaclient/config.txt");
    std::string line;
    while (std::getline(fin, line))
    {
        char *type;
        char *value;
        char *lineStr = (char *)line.c_str();
        type = strtok(lineStr, "=");
        if(type == NULL)
        {
            std::cout << "Load config file error: type=NULL!\n";
            return;
        }
        value = strtok(NULL, ";");
        if(value == NULL)
        {
            std::cout << "Load config file error: value=NULL!\n";
            return;
        }
        if (strcmp(type, "SERVER_NCM_IP") == 0 && strlen(value) < 20)
        {
            memcpy(g_systemStateSettings->server_ncm_ip, value, strlen(value));
            g_systemStateSettings->server_ncm_ip[strlen(value)] = '\0';
        }
        else if (strcmp(type, "SERVER_NCM_PORT") == 0)
        {
            g_systemStateSettings->server_ncm_port = atoi(value);
        }
        else if (strcmp(type, "WIFI_INTERFACE") == 0 && strlen(value) < 100)
        {
            memcpy(g_systemStateSettings->wifi_interface, value, strlen(value));
            g_systemStateSettings->wifi_interface[strlen(value)] = '\0';
        }
        else if (strcmp(type, "LTE_INTERFACE") == 0 && strlen(value) < 100)
        {
            memcpy(g_systemStateSettings->lte_interface, value, strlen(value));
            g_systemStateSettings->lte_interface[strlen(value)] = '\0';
        }
        else if (strcmp(type, "SERVER_DNS") == 0 && strlen(value) < 100)
        {
            memcpy(g_systemStateSettings->domain, value, strlen(value));
            g_systemStateSettings->domain[strlen(value)] = '\0';
        }
        else if (strcmp(type, "RSSI_INTERVAL") == 0)
        {
            g_systemStateSettings->rssiInterval = atoi(value);
        }
        else if (strcmp(type, "LOGS_ENABLED") == 0)
        {
            g_systemStateSettings->logsEnabled = atoi(value); 
        }
        else if (strcmp(type, "RTT_TH_LOW") == 0)
        {
            g_systemStateSettings->rttThLow = atoi(value);
        }
        else if (strcmp(type, "RTT_TH_HIGH") == 0)
        {
            g_systemStateSettings->rttThHigh = atoi(value);
        }
        else if (strcmp(type, "FLOW_MEASUREMENT_ON") == 0)
        {
            int r = atoi(value);
            g_systemStateSettings->ENABLE_FLOW_MEASUREMENT = (r == 1) ? true : false;
        }
        else if (strcmp(type, "DRIVER_MONITOR_ON") == 0)
        {
            int r = atoi(value);
            g_systemStateSettings->driverMonitorOn = (r == 1) ? true : false;
        }
        else if (strcmp(type, "HR_RX_BUFFER_SIZE") == 0)
        {
            g_systemStateSettings->HRBufferSize = atoi(value);
        }
        else if (strcmp(type, "HR_RX_TIMEOUT") == 0)
        {
            g_systemStateSettings->HRreorderingTimeout = atoi(value);
        }

    }
    std::stringstream ss;
    ss << "Load config files completed\n";
    fin.close();
    g_systemStateSettings->PrintLogs(ss);
}

bool ClientManager::bindlte = true;

void ClientManager::updateDevicesInterface(char wifi[], char lte[], char server[])
{
    //Load our multiple interface names
    memcpy(wifiInterface, wifi, sizeof(wifiInterface)-1);
    wifiInterface[sizeof(wifiInterface)-1] = '\0';
    memcpy(lteInterface, lte, sizeof(lteInterface)-1);
    lteInterface[sizeof(lteInterface)-1] = '\0';
    memcpy(serverAddress, server, sizeof(serverAddress)-1);
    serverAddress[sizeof(serverAddress)-1] = '\0';

    try {
        connThread = std::thread(&ClientManager::ConnectThread, this);
        conn_ID = (std::thread::native_handle_type)1;
    }
    catch (const std::system_error& e) {
        std::cout << "Caught system_error with code " << e.code()
            << " meaning " << e.what() << '\n';
        conn_ID = 0;
    }


}


void ClientManager::Quit()
{
    while(ThreadBusy)
    {
        conn_cv.notify_all();
        g_systemStateSettings->msleep(1000);
    }

    connThread.join();
}

void ClientManager::ConnectThread()
{
    
    int count = 0;
    ThreadBusy = true;

    std::unique_lock<std::mutex> lck(conn_mtx);
    while (monitorNetwork.networkMonitorRunning)
    {
        printf("\n waiting to start connect \n");
        conn_cv.wait(lck);
        if (!monitorNetwork.networkMonitorRunning)
            break;
        count = 0;
        while(serviceManager.isServiceRunning && count < 10)
        {
            printf("\n the background service already started, wait**\n");
            g_systemStateSettings->msleep(1000);
            count++;
        }
        if (serviceManager.isServiceRunning)
        {
            continue;
        }

        connectRunning = true;
        count = 0;
        
        while (checkRoutes() && count < maxConnNum)
        {
            count++;
            //route is ok, reconnect immediately
            g_systemStateSettings->vnicInit = false;
            std::stringstream ss;
            ss << "Valid both routes, start connecting \n";
            g_systemStateSettings->PrintLogs(ss);
            ss.str("");

            load_root_certificates(ctx);
            getServerIp(g_systemStateSettings->domain);

            pConnect = new ConnectServer(ioc, ctx, g_systemStateSettings);
            pConnect->Execute();
            delete pConnect;
            pConnect = NULL;

            monitorNetwork.DriverReset();
            if (g_systemStateSettings->vnicInit)
            {
                serviceManager.foreground2background();
                break;
            }

            if (count < maxConnNum)
                g_systemStateSettings->msleep(1000 * 60); //sleep 60s and restart
        }

        if (!WifiCheck(wifiInterface))
        {
            wifiNetworkConnected = false;
        }
        if (!LteCheck(lteInterface))
        {
            lteNetworkConnected = false;
        }

        connectRunning = false;


    }

    ThreadBusy = false;
}


ClientManager::ClientManager()
{
}



void ClientManager::getServerIp(char servername[])
{
    g_systemStateSettings->serverlteIpv4Address = std::string(g_systemStateSettings->server_ncm_ip);
    g_systemStateSettings->edgeDNS = 0;
    std::string domainName = std::string(servername);
    try
    {
        std::stringstream ss;
        ss << "Finding DNS: " << domainName << std::endl;
        g_systemStateSettings->PrintLogs(ss);

        struct hostent* host_info = gethostbyname(domainName.c_str());
        int xx = 0;
        while (!host_info && xx < 3)
        {
            host_info = gethostbyname(domainName.c_str());
            xx++;
        }
        
        if (host_info == NULL)
        {
            std::stringstream ss;
            ss << "Not Find DNS: " << domainName << std::endl;
            g_systemStateSettings->PrintLogs(ss);
        }
        else
        {
            if (host_info->h_addrtype == AF_INET)
            {
                for (int i = 0; host_info->h_addr_list[i]; i++)
                {
                    std::string temphost(inet_ntoa(*(struct in_addr*)host_info->h_addr_list[i]));
                    std::string lo = findLoopback();
                    if (temphost != lo)
                    {
                        g_systemStateSettings->serverlteIpv4Address = temphost;
                        g_systemStateSettings->edgeDNS = 1;
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        std::stringstream ss;
        ss << e.what() << '\n';
        g_systemStateSettings->PrintLogs(ss);
    }
    return;
}

void ClientManager::onAvailable(char *interface)
{
    if (connectRunning || serviceManager.isServiceRunning)
        return;

    if (strcmp(interface, wifiInterface) == 0) // wifi avaliable
    {
        if (wifiNetworkConnected)
        {
            return; //Wi-Fi is already connected
        }
        if (WifiCheck(wifiInterface))
        {
            wifiNetworkConnected = true;
            if (lteNetworkConnected)
            {
                Connect();
            }
        }
    }
    else if (strcmp(interface, lteInterface) == 0) // lte avaliable
    {
        if (lteNetworkConnected)
        {
            return; // LTE is already connected
        }
        if (LteCheck(lteInterface))
        {
            addLteDefaultRoute(lteInterface);
            lteNetworkConnected = true;
            std::stringstream ss;
            if (bindlte)
            {
                std::string host = g_systemStateSettings->lteIpv4Address;

                ss << "bind the discovery websocket to LTE: success\n";
                g_systemStateSettings->PrintLogs(ss);
            }
            else
            {
                if (!wifiNetworkConnected)
                    return;
                std::string host = g_systemStateSettings->wifiIpv4Address;

                ss << "bind the discovery websocket to WiFi: success\n";
                g_systemStateSettings->PrintLogs(ss);
            }
            if (wifiNetworkConnected)
            {
                Connect();
             }
        }
    }
    else
    {
        std::stringstream ss;
        ss << "Error Interface Name\n"
           << std::endl;
        g_systemStateSettings->PrintLogs(ss);
    }
}

void ClientManager::onLost(char *interface)
{
    if (strcmp(interface, wifiInterface) == 0)
    {
        wifiNetworkConnected = false;
    }
    else if (strcmp(interface, lteInterface) == 0)
    {
        lteNetworkConnected = false;
    }
}

void ClientManager::Connect()
{
    
    if (!connectRunning)
    {
        maxConnNum = 3;
        conn_cv.notify_all();
    }
    return;

}

bool ClientManager::checkRoutes()
{
    char wifiBuf[100] = {0};
    char lteBuf[100] = {0};
    std::stringstream ss;
    ss << "check both links........\n";
    g_systemStateSettings->PrintLogs(ss);
    FILE *fp;
    std::string wifiCmd = "ip route | grep dev | grep " + std::string(this->wifiInterface) + " | grep metric";
    fp = popen_with_return(wifiCmd.c_str(), wifiCmd.size());
    if (fp == NULL)
    {
        return false;
    }
    fgets(wifiBuf, sizeof(wifiBuf), fp);
    pclose(fp);

    if (strlen(wifiBuf) == 0)
    {
        this->wifiNetworkConnected = false;
        return false;
    }

    std::string lteCmd = "ip route | grep dev | grep " + std::string(this->lteInterface) + " | grep metric";
    fp = popen_with_return(lteCmd.c_str(), lteCmd.size());
    if (fp == NULL)
    {
        return false;
    }
    fgets(lteBuf, sizeof(lteBuf), fp);
    pclose(fp);

    if (strlen(lteBuf) == 0)
    {
        this->lteNetworkConnected = false;
        return false;
    }
    return true;
}

void ClientManager::checkExit(bool restart)
{
    isForeground = true;
    if (!connectRunning && restart)
    {
        maxConnNum = 10;
        conn_cv.notify_all();
    }

}

int main()
{
    int ret;
    g_systemStateSettings = new SystemStateSettings();
    if(!g_systemStateSettings->LogFileOpen())
		return -1;

    load_config();
    monitorNetwork.networkMonitorRunning = true;

    clientManager.updateDevicesInterface(g_systemStateSettings->wifi_interface, 
        g_systemStateSettings->lte_interface, g_systemStateSettings->server_ncm_ip);
    
    if (clientManager.conn_ID == 0)
    {
        printf("\n failed to start the connect thread \n");
        return EXIT_FAILURE;
    }
    
    std::thread monitorNetworkThread(std::bind(&MonitorNetwork::monitor, &monitorNetwork));
    std::thread::native_handle_type monitorID = monitorNetworkThread.native_handle();
    if (WifiCheck(clientManager.wifiInterface))
        clientManager.wifiNetworkConnected = true;
    if (LteCheck(clientManager.lteInterface))
    {
        clientManager.lteNetworkConnected = true;
        try {
            addLteDefaultRoute(clientManager.lteInterface);
        }
        catch (std::exception &e) {
		 std::cout<<"Caught exception: "<<e.what()<<"\n";
	    }

    }
    monitorNetwork.OpenDriverMonitor(g_systemStateSettings->driverMonitorOn);
    if (clientManager.wifiNetworkConnected && clientManager.lteNetworkConnected)
    {
        clientManager.Connect();
    }
    else
    {
        std::stringstream ss;
        ss << "Need both two links connected.....wait now.....\n";
        g_systemStateSettings->PrintLogs(ss);
    }


    char buf[100];

    while (1)
    {
        fgets(buf, 100, stdin);
        buf[strlen(buf) - 1] = '\0';
        if (strlen(buf) == 4 && buf[0] == 'q' && buf[1] == 'u' && buf[2] == 'i' && buf[3] == 't')
        {
            g_systemStateSettings->terminateThread(monitorID);
            monitorNetworkThread.join();
            monitorNetwork.quit();

            monitorNetwork.networkMonitorRunning = false;
            clientManager.Quit();
            try {
                serviceManager.Quit();
            }

            catch(std::exception const&  e)
            {
                std::cout << "std overflow error " <<  e.what() << "\n";
            }


            monitorNetwork.CloseDriverMonitor(g_systemStateSettings->driverMonitorOn);
            g_systemStateSettings->LogFileClose();
            break; 
        }
        else
        {
            memset(buf, 0, sizeof(buf));
        }
    }
    printf("\n Exit \n");

    delete g_systemStateSettings;
    return EXIT_SUCCESS;
}
