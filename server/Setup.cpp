//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Setup.cpp
//Description : c++ file for Generic Multi-Access Network Virtualization

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <unistd.h>

#include "Setup.h"
#include "IFOMServer.h"

struct network_info	net_cfg;
char	wlan_interface[16]; // one char for null terminator
char    forward_interface[16];

int     g_lte_mtu = 0;
int	g_wlan_mtu = 0;
int	g_vnic_mtu = 0;

u_int	lte_T;
u_int	fiveG_D;
int	Tun_num = 1;

char	local_addr_ip[20];
u_short	local_addr_port;
char	ncm_addr_ip[20];
u_short  ncm_addr_port;
char    wifi_interface_ip[21];
u_short wifi_interface_port;
char    lte_interface_ip[21];
u_short lte_interface_port;
u_short measure_report_port;
u_short rt_flow_dscp;
u_short hr_flow_dscp;

char measure_report_nic[16];
char measure_report_ip[21];

char  vnic_ip[21];
char  vnic_gateway[21];
char  vnic_mask[21];
char  vnic_dns[21];

u_short MAX_TX_BUFFER_SIZE = 1000;
u_short MAX_RX_BUFFER_SIZE = 1000;
u_short CLIENT_RX_BUFFER_SIZE = 100;
u_short REORDERING_TIMEOUT = 1000;

u_int WIFI_RATE_MBPS = 200;
u_int WIFI_NRT_RATE_MBPS = 50;
u_int WIFI_DELAY_MS = 100;
u_int LTE_RATE_MBPS = 200;
u_int LTE_NRT_RATE_MBPS = 50;
u_int LTE_DELAY_MS = 100;

u_int MAX_RATE_MBPS = 1000;
u_int SLEEP_TIME_UNIT_US = 1;
u_int PKT_BURST_SIZE_KB = 100;

u_short MEASURE_INTERVAL_S = 10;
u_short SERVER_REPORT_CYCLE = 10;
bool ENABLE_DL_QOS = 1;
bool ENABLE_MEASUREMENT = 1;
bool ENABLE_MEASURE_REPORT = 1;
bool ENABLE_UL_REORDERING = 1;
bool ENABLE_UL_ENCRYPT = 1;

u_short WIFI_WAKEUP_TIMEOUT_S = 600;
u_short LTE_WAKEUP_TIMEOUT_S = 600;
u_short WIFI_TCP_KEEP_ALIVE_S = 7200;
u_short LTE_TCP_KEEP_ALIVE_S = 7200;

const char Server_Config_Key[END_INDEX][32] =
{
	"LOCAL_ADDR_IP_CONFIG",
	"LOCAL_ADDR_PORT_CONFIG",
	"NCM_ADDR_IP_CONFIG",
	"NCM_ADDR_PORT_CONFIG"
};

int IFOM_Config_Load(const char* filename)
{
	FILE* pfile;
	char	buff[2048];
	char	key_config_str[END_INDEX][CONFIG_STR_MAX_LEN];
	char* pbuff;
	char* pnewline;
	int	index = 0;

	if ((pfile = fopen(filename, "rb")) != NULL)
	{
		if (fread(buff, 1, sizeof(buff), pfile) > 0)
		{
			pbuff = buff;
			while ((index != END_INDEX) && (pbuff = strstr(pbuff, Server_Config_Key[index])))
			{
				pbuff = strstr(pbuff, "=");
				if(pbuff == NULL)
				{
					break;
				}
				pnewline = strstr(pbuff, ";");
				if(pnewline == NULL)
				{
					break;
				}
				memcpy(key_config_str[index], pbuff + 1, pnewline - pbuff - 1);
				key_config_str[index][pnewline - pbuff - 1] = '\0';
				index++;
				pbuff++;
			}

			if (index != END_INDEX)
			{
				printf("Load server config file error %d\n", index);
				fclose(pfile);
				return 0;
			}

			memcpy(local_addr_ip, key_config_str[LOCAL_ADDR_IP_INDEX], 20);
			local_addr_port = atoi(key_config_str[LOCAL_ADDR_PORT_INDEX]);
			memcpy(ncm_addr_ip, key_config_str[NCM_ADDR_IP_INDEX], 20);
			ncm_addr_port = atoi(key_config_str[NCM_ADDR_PORT_INDEX]);

			fclose(pfile);
			return 1;
		}
		else
		{
			printf("Read server_config.txt error\n");
			fclose(pfile);
			return 0;
		}
	}

	printf("Open server_config.txt error\n");

	return 0;

}

int load_receive_parameters(char* recv_buf)
{
	char	buff[2048];
	char	key_config_str[STOP_INDEX][CONFIG_STR_MAX_LEN];
	char* pbuff;
	char* pnewline;
	int	index = 0;
	char* split_symbol = (char* )";";
	pbuff = strtok(recv_buf, split_symbol);
	while (pbuff != NULL && index != STOP_INDEX)
	{
		if (strlen(pbuff) < CONFIG_STR_MAX_LEN)
		{
			memcpy(key_config_str[index], pbuff, strlen(pbuff));
			key_config_str[index][strlen(pbuff)] = '\0';
		}
		pbuff = strtok(NULL, split_symbol);
		index++;
	}
	
	if (index != STOP_INDEX)
	{
		printf("receive parameters error = %d\n", index);
		return 0;
	}

	memcpy(wlan_interface, key_config_str[WLAN_INTERFACE_CONFIG_INDEX], 16);
	wlan_interface[15] = '\0';  // one char for null terminator
	memcpy(net_cfg.lte_interface, key_config_str[LTE_INTERFACE_CONFIG_INDEX], 16);
	net_cfg.lte_interface[15] = '\0';  // one char for null terminator
	memcpy(forward_interface, key_config_str[FORWARD_INTERFACE_CONFIG_INDEX], 16);
	forward_interface[15] = '\0';  // one char for null terminator
	printf("wlan_interface: %s, lte_interface: %s, forward interface: %s\n",
		wlan_interface, net_cfg.lte_interface, forward_interface);

	g_lte_mtu = atoi(key_config_str[LTE_INTERFACE_MTU_CONFIG_INDEX]);
	g_wlan_mtu = atoi(key_config_str[WLAN_INTERFACE_MTU_CONFIG_INDEX]);
	g_vnic_mtu = atoi(key_config_str[VNIC_INTERFACE_MTU_CONFIG_INDEX]);
	printf("lte mtu: %d, wlan mtu: %d, vnic mtu: %d\n",
		g_lte_mtu, g_wlan_mtu, g_vnic_mtu);

	memcpy(wifi_interface_ip, key_config_str[WIFI_INTERFACE_IP_ADDRESS_INDEX], 20);
	wifi_interface_ip[20] = '\0';  // one char for null terminator
	wifi_interface_port = atoi(key_config_str[WIFI_INTERFACE_IP_PPORT_INDEX]);
	memcpy(lte_interface_ip, key_config_str[LTE_INTERFACE_IP_ADDRESS_INDEX], 20);
	lte_interface_ip[20] = '\0';  // one char for null terminator

	lte_interface_port = atoi(key_config_str[LTE_INTERFACE_IP_PORT_INDEX]);
	printf("wifi_interface_ip = %s, wifi_interface_port = %d, lte_interface_ip = %s, lte_interface_port = %d\n",
		wifi_interface_ip, wifi_interface_port, lte_interface_ip, lte_interface_port);

	memcpy(vnic_ip, key_config_str[SERVER_VNIC_IP_INDEX], 20); //client vnic ip
	vnic_ip[20] = '\0';  // one char for null terminator
	memcpy(vnic_gateway, key_config_str[SERVER_VNIC_GW_INDEX], 20); //server vnic ip
	vnic_gateway[20] = '\0';  // one char for null terminator
	memcpy(vnic_mask, key_config_str[SERVER_VNIC_MSK_INDEX], 20);
	vnic_mask[20] = '\0';  // one char for null terminator
	memcpy(vnic_dns, key_config_str[SERVER_VNIC_DNS_INDEX], 20);
	vnic_dns[20] = '\0';  // one char for null terminator
	server_udp_port = atoi(key_config_str[UDP_PORT_INDEX]);
	server_tcp_port = atoi(key_config_str[TCP_PORT_INDEX]);
	max_keep_client_time = atoi(key_config_str[MAX_KEEP_CLIENT_TIME_INDEX]);
	max_client_num = atoi(key_config_str[MAX_CLIENT_NUM_INDEX]);
	printf("vnic_ip = %s, vnic_gateway = %s, vnic_mask = %s, vnic_dns = %s\n",
		vnic_ip, vnic_gateway, vnic_mask, vnic_dns);

	in_addr addr;
	if (inet_pton(AF_INET, vnic_ip, &addr))
	{
		*(u_int*)g_vnic_ip = addr.s_addr;
	}
	if (inet_pton(AF_INET, vnic_gateway, &addr))
	{
		*(u_int*)g_vnic_gateway = addr.s_addr;
	}
	if (inet_pton(AF_INET, vnic_mask, &addr))
	{
		*(u_int*)g_vnic_mask = addr.s_addr;
	}
	if (inet_pton(AF_INET, vnic_dns, &addr))
	{
		*(u_int*)g_vnic_dns = addr.s_addr;
	}

	printf("server_udp_port = %d, server_tcp_port = %d, max_keep_client_time = %d, max_keep_client_time = %d\n", server_udp_port, server_tcp_port, max_keep_client_time, max_client_num);

	MAX_TX_BUFFER_SIZE = atoi(key_config_str[MAX_TX_BUFFER_SIZE_CONFIG_INDEX]);
	MAX_RX_BUFFER_SIZE = atoi(key_config_str[MAX_RX_BUFFER_SIZE_CONFIG_INDEX]);
	CLIENT_RX_BUFFER_SIZE = atoi(key_config_str[CLIENT_RX_BUFFER_SIZE_CONFIG_INDEX]);
	REORDERING_TIMEOUT = atoi(key_config_str[REORDERING_TIMEOUT_CONFIG_INDEX]);
	WIFI_RATE_MBPS = atoi(key_config_str[WIFI_RATE_MBPS_CONFIG_INDEX]);
	WIFI_NRT_RATE_MBPS = atoi(key_config_str[WIFI_NRT_RATE_MBPS_CONFIG_INDEX]);
	WIFI_DELAY_MS = atoi(key_config_str[WIFI_DELAY_MS_CONFIG_INDEX]);
	LTE_RATE_MBPS = atoi(key_config_str[LTE_RATE_MBPS_CONFIG_INDEX]);
	LTE_NRT_RATE_MBPS = atoi(key_config_str[LTE_NRT_RATE_MBPS_CONFIG_INDEX]);
	LTE_DELAY_MS = atoi(key_config_str[LTE_DELAY_MS_CONFIG_INDEX]);
	MAX_RATE_MBPS = atoi(key_config_str[MAX_RATE_MBPS_CONFIG_INDEX]);
	SLEEP_TIME_UNIT_US = atoi(key_config_str[SLEEP_TIME_UNIT_US_CONFIG_INDEX]);
	PKT_BURST_SIZE_KB = atoi(key_config_str[PKT_BURST_SIZE_KB_CONFIG_INDEX]);
	MEASURE_INTERVAL_S = atoi(key_config_str[MEASURE_INTERVAL_S_CONFIG_INDEX]);
	SERVER_REPORT_CYCLE = atoi(key_config_str[SERVER_REPORT_CYCLE_CONFIG_INDEX]);
	ENABLE_DL_QOS = atoi(key_config_str[ENABLE_DL_QOS_CONFIG_INDEX]);
	ENABLE_MEASUREMENT = atoi(key_config_str[ENABLE_MEASUREMENT_CONFIG_INDEX]);
	ENABLE_MEASURE_REPORT = atoi(key_config_str[ENABLE_MEASURE_REPORT_CONFIG_INDEX]);
	ENABLE_UL_REORDERING = atoi(key_config_str[ENABLE_UL_REORDERING_CONFIG_INDEX]);
	ENABLE_UL_ENCRYPT = atoi(key_config_str[ENABLE_UL_ENCRYPT_CONFIG_INDEX]);
	WIFI_WAKEUP_TIMEOUT_S = atoi(key_config_str[WIFI_WAKEUP_TIMEOUT_S_CONFIG_INDEX]);
	LTE_WAKEUP_TIMEOUT_S = atoi(key_config_str[LTE_WAKEUP_TIMEOUT_S_CONFIG_INDEX]);
	WIFI_TCP_KEEP_ALIVE_S = atoi(key_config_str[WIFI_TCP_KEEP_ALIVE_S_CONFIG_INDEX]);
	LTE_TCP_KEEP_ALIVE_S = atoi(key_config_str[LTE_TCP_KEEP_ALIVE_S_CONFIG_INDEX]);
	printf("MAX_TX_BUFFER_SIZE = %d, MAX_RX_BUFFER_SIZE = %d, CLIENT_RX_BUFFER_SIZE = %d, REORDERING_TIMEOUT = %d\n",
		MAX_TX_BUFFER_SIZE, MAX_RX_BUFFER_SIZE, CLIENT_RX_BUFFER_SIZE, REORDERING_TIMEOUT);
	printf("WIFI_RATE_MBPS = %d, WIFI_NRT_RATE_MBPS = %d, WIFI_DELAY_MS = %d\n",
		WIFI_RATE_MBPS, WIFI_NRT_RATE_MBPS, WIFI_DELAY_MS);
	printf("LTE_RATE_MBPS = %d, LTE_NRT_RATE_MBPS = %d, LTE_DELAY_MS = %d\n",
		LTE_RATE_MBPS, LTE_NRT_RATE_MBPS, LTE_DELAY_MS);
	printf("MAX_RATE_MBPS = %d, SLEEP_TIME_UNIT_US = %d, PKT_BURST_SIZE_KB = %d\n",
		MAX_RATE_MBPS, SLEEP_TIME_UNIT_US, PKT_BURST_SIZE_KB);
	printf("MEASURE_INTERVAL_S = %d, SERVER_REPORT_CYCLE = %d, ENABLE_DL_QOS = %d, ENABLE_MEASUREMENT = %d, ENABLE_MEASURE_REPORT = %d\n",
		MEASURE_INTERVAL_S, SERVER_REPORT_CYCLE, ENABLE_DL_QOS, ENABLE_MEASUREMENT, ENABLE_MEASURE_REPORT);
	printf("ENABLE_UL_REORDERING = %d, ENABLE_UL_ENCRYPT = %d, WIFI_WAKEUP_TIMEOUT_S = %d, LTE_WAKEUP_TIMEOUT_S = %d, WIFI_TCP_KEEP_ALIVE_S = %d, LTE_TCP_KEEP_ALIVE_S = %d\n",
		ENABLE_UL_REORDERING, ENABLE_UL_ENCRYPT, WIFI_WAKEUP_TIMEOUT_S, LTE_WAKEUP_TIMEOUT_S, WIFI_TCP_KEEP_ALIVE_S, LTE_TCP_KEEP_ALIVE_S);
	measure_report_port = atoi(key_config_str[MEASURE_REPORT_PORT_INDEX]);
	printf("measure_report_port = %d\n",measure_report_port);
	memcpy(measure_report_nic, key_config_str[MEASURE_REPORT_NIC_INDEX], 16);
	measure_report_nic[15] = '\0';
	printf("measure_report_nic = %s", measure_report_nic);
	rt_flow_dscp = atoi(key_config_str[RT_FLOW_DSCP_INDEX]);
	printf("RT flow DSCP  = %d\n", rt_flow_dscp);
	hr_flow_dscp = atoi(key_config_str[HR_FLOW_DSCP_INDEX]);
	printf("HR flow DSCP  = %d\n", hr_flow_dscp);
	return 1;

}

int getNetworkAddr(char* keyword, char* ip, u_char* mac)
{
	int		fd;
	struct ifreq	ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	int name_len = strlen(keyword);
	memcpy(ifr.ifr_name, keyword, name_len);
	ifr.ifr_name[name_len] = '\0';

	if (ioctl(fd, SIOCGIFADDR, &ifr))
	{
		close(fd);
		return -1;
	}
	strcpy(ip, inet_ntoa(((struct sockaddr_in*)(&ifr.ifr_addr))->sin_addr));

	printf("net: %s, ip: %8.8x\n", keyword, *(u_int*)ip);

	if (mac)
	{
		if (ioctl(fd, SIOCGIFHWADDR, &ifr))
		{
			close(fd);
			return -1;
		}
		memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	}
	close(fd);

	return 0;
}













