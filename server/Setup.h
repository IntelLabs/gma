//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Setup.h
//Description : c++ header file for Generic Multi-Access Network Virtualization
#ifndef __SETUP_H_
#define __SETUP_H_

#define	CONFIG_STR_MAX_LEN	50
#define	SERVER_CONFIG_FILE	"/home/ncm_ws/server_config.txt"

typedef enum SERVER_CONFIG_INDEX
{
	LOCAL_ADDR_IP_INDEX,
	LOCAL_ADDR_PORT_INDEX,
	NCM_ADDR_IP_INDEX,
	NCM_ADDR_PORT_INDEX,
	END_INDEX
}CONFIG_INDEX;

typedef enum RECEIVE_CONFIG_INDEX
{
	WLAN_INTERFACE_CONFIG_INDEX,
	LTE_INTERFACE_CONFIG_INDEX,
	FORWARD_INTERFACE_CONFIG_INDEX,
	LTE_INTERFACE_MTU_CONFIG_INDEX,
	WLAN_INTERFACE_MTU_CONFIG_INDEX,
	VNIC_INTERFACE_MTU_CONFIG_INDEX,
	WIFI_INTERFACE_IP_ADDRESS_INDEX,
	WIFI_INTERFACE_IP_PPORT_INDEX,
	LTE_INTERFACE_IP_ADDRESS_INDEX,
	LTE_INTERFACE_IP_PORT_INDEX,
	SERVER_VNIC_IP_INDEX,
	SERVER_VNIC_GW_INDEX,
	SERVER_VNIC_MSK_INDEX,
	SERVER_VNIC_DNS_INDEX,
	UDP_PORT_INDEX,
	TCP_PORT_INDEX,
	MAX_KEEP_CLIENT_TIME_INDEX,
	MAX_CLIENT_NUM_INDEX,
	MAX_TX_BUFFER_SIZE_CONFIG_INDEX,
	MAX_RX_BUFFER_SIZE_CONFIG_INDEX,
	CLIENT_RX_BUFFER_SIZE_CONFIG_INDEX,
	REORDERING_TIMEOUT_CONFIG_INDEX,
	WIFI_RATE_MBPS_CONFIG_INDEX,
	WIFI_NRT_RATE_MBPS_CONFIG_INDEX,
	WIFI_DELAY_MS_CONFIG_INDEX,
	LTE_RATE_MBPS_CONFIG_INDEX,
	LTE_NRT_RATE_MBPS_CONFIG_INDEX,
	LTE_DELAY_MS_CONFIG_INDEX,
	MAX_RATE_MBPS_CONFIG_INDEX,
	SLEEP_TIME_UNIT_US_CONFIG_INDEX,
	PKT_BURST_SIZE_KB_CONFIG_INDEX,
	MEASURE_INTERVAL_S_CONFIG_INDEX,
	SERVER_REPORT_CYCLE_CONFIG_INDEX,
	ENABLE_DL_QOS_CONFIG_INDEX,
	ENABLE_DL_OWD_OFFSET_CONFIG_INDEX,
	ENABLE_MEASUREMENT_CONFIG_INDEX,
	ENABLE_MEASURE_REPORT_CONFIG_INDEX,
	ENABLE_UL_REORDERING_CONFIG_INDEX,
	ENABLE_UL_ENCRYPT_CONFIG_INDEX,
	WIFI_WAKEUP_TIMEOUT_S_CONFIG_INDEX,
	LTE_WAKEUP_TIMEOUT_S_CONFIG_INDEX,
	WIFI_TCP_KEEP_ALIVE_S_CONFIG_INDEX,
	LTE_TCP_KEEP_ALIVE_S_CONFIG_INDEX,
	MEASURE_REPORT_PORT_INDEX,
    MEASURE_REPORT_NIC_INDEX,
	RT_FLOW_DSCP_INDEX,
	HR_FLOW_DSCP_INDEX,
	STOP_INDEX
}RECEIVE_PARAMETERS_INDEX;


struct network_info
{
	char	lte_interface[16];
	char	gw_interface[16];
	int	Tun_num;
	u_short	ctl_port;
};

struct dl_virtual_message_header {
	char flag[2];
	u_short client_id;
}__attribute__((packed));


struct virtual_message_header {
	char flag[2];
}__attribute__((packed));

struct encrypted_message_header {
	char flag[2];
	u_short client_id;
}__attribute__((packed));



struct virtual_ul_data_header {
	char flag[2];
	char flow_id;
	char ppp;
	u_int sn;  // B0 (MSB): l_sn,  B1~B3: g_sn;
	u_int time_stamp;

}__attribute__((packed));

struct virtual_dl_data_header {
	char flag[2];
	char client_id[2];
	char flow_id;
	char ppp;
	u_int sn;  // B0 (MSB): l_sn,  B1~B3: g_sn;
	u_int time_stamp;

}__attribute__((packed));

#define VIRTUAL_DL_MESSAGE 4
#define VIRTUAL_DL_DATA 14
#define VIRTUAL_UL_DATA 11

#define GMA_HEADER_OFFSET 14

extern struct network_info	net_cfg;
extern char 	wlan_interface[16];
extern char     forward_interface[16];

extern int      g_lte_mtu;
extern int	g_wlan_mtu;
extern int	g_vnic_mtu;

extern u_int	lte_T;
extern u_int	fiveG_D;
extern int	Tun_num;

extern unsigned short AGG_usDelay;
extern unsigned short AGG_usAggMax;
extern unsigned short AGG_usPktNumMax;
extern unsigned short AGG_ucFlags;

extern char	local_addr_ip[20];
extern u_short	local_addr_port;
extern char	ncm_addr_ip[20];
extern u_short  ncm_addr_port;
extern char    wifi_interface_ip[21];
extern u_short wifi_interface_port;
extern char    lte_interface_ip[21];
extern u_short lte_interface_port;
extern u_short measure_report_port;
extern u_short rt_flow_dscp;
extern u_short hr_flow_dscp;

extern char measure_report_nic[16];
extern char measure_report_ip[21];

extern u_short MAX_TX_BUFFER_SIZE; //TX ring buffer size. If the buffer is full, drop packets.
extern u_short MAX_RX_BUFFER_SIZE; //RX ring buffer size. If the buffer is full, deliver all reordering packets from the client that transmits the last packet.
extern u_short CLIENT_RX_BUFFER_SIZE; //RX index queue size per client. If the index queue is full, deliver all packets in the queue.
extern u_short REORDERING_TIMEOUT; //ms.

extern u_int WIFI_RATE_MBPS;
extern u_int WIFI_NRT_RATE_MBPS;
extern u_int WIFI_DELAY_MS;
extern u_int LTE_RATE_MBPS;
extern u_int LTE_NRT_RATE_MBPS;
extern u_int LTE_DELAY_MS;

extern u_int MAX_RATE_MBPS;
extern u_int SLEEP_TIME_UNIT_US;
extern u_int PKT_BURST_SIZE_KB;

extern u_short WIFI_WAKEUP_TIMEOUT_S; //if no packet is received from WIFI after timeout, send a TCP wakeup msg.
extern u_short LTE_WAKEUP_TIMEOUT_S; //if no packet is received from LTE after timeout, send a TCP wakeup msg.

extern u_short WIFI_TCP_KEEP_ALIVE_S; //for setup the WIFI tcp socket.
extern u_short LTE_TCP_KEEP_ALIVE_S; //for setup the LTE tcp socket.
extern u_short MEASURE_INTERVAL_S; // the interval to report measurement results, unit seconds.
extern u_short SERVER_REPORT_CYCLE; // the interval to compute average or max of measure results.
extern bool ENABLE_DL_QOS; //enable qos queues, based on HTB qdiscs
extern bool ENABLE_DL_OWD_OFFSET; //enable qos queues, based on HTB qdiscs
extern bool ENABLE_MEASUREMENT; //enable uplink measurements.
extern bool ENABLE_MEASURE_REPORT; //print measurements
extern bool ENABLE_UL_REORDERING; //If it is false, we won’t do any reordering for uplink traffic or allocate any (per-client) reordering buffer. 
extern bool ENABLE_UL_ENCRYPT; //If it is ture, ul probe, tsu and tcp control msgs will be encrypted. 

int IFOM_Config_Load(const char * filename);
int getNetworkAddr(char * keyword, char * ip, u_char * mac);
int load_receive_parameters(char* recv_buf);

#endif
