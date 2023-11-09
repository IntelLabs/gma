//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : IFOMServer.h
//Description : c++ header file for Generic Multi-Access Network Virtualization

#ifndef _IFOM_SERVER_H_
#define _IFOM_SERVER_H_

#include <hash_map>
#include "Setup.h"
#include "LinuxTun.h"
#include <queue>
#include <mutex>              // std::mutex, std::unique_lock
#include <condition_variable> // std::condition_variable
#include <linux/ip.h>
#include <linux/udp.h>
#include <climits>


using namespace __gnu_cxx;
extern int	ncm_send_sockfd;
extern sockaddr_in	ncm_addr;

extern bool	g_bServerRun;
extern bool g_send_measurement_to_winapp;
extern struct itimerspec fiveG_probe_ts;
extern struct itimerspec LTE_stay_ts;

extern unsigned short g_websock_port;
extern unsigned int   g_websock_ip;
extern unsigned char  g_vnic_ip[4];
extern unsigned char  g_vnic_gateway[4];
extern unsigned char  g_vnic_mask[4];
extern unsigned char  g_vnic_dns[4];
extern u_short server_udp_port;
extern u_short server_tcp_port;
extern unsigned int max_keep_client_time;
extern unsigned int max_client_num;

extern int  g_vnic_ctl_sockfd;
extern int  g_measure_report_sockfd;

extern int g_lte_tunnel_sockfd;
extern int g_wifi_tunnel_sockfd;

extern unsigned int g_time_param_s;
extern unsigned int g_time_param_ms;


//jiazhuang: add a new netlink socket for control message received from UE IP 6.6.6.6




#define DATA_PACKET			0

#define RECONFIGURATION_INIT_MSG	1
#define RECONFIGURATION_INIT_ACK	2
#define FIVEG_RECONFIGURATION_REQ	3
#define FIVEG_RECONFIGURATION_ACK	4
#define FIVEG_PROBE_REQ		5
#define FIVEG_PROBE_ACK		6
#define FIVEG_TO_LTE_SWITCH_REQ	7	
#define FIVEG_TO_LTE_SWITCH_RSP	8
#define LTE_TO_FIVEG_SWITCH_REQ	9
#define LTE_TO_FIVEG_SWITCH_RSP	10
#define LTE_TO_FIVEG_SWITCH_ACK	11
#define LTE_KEEP_ALIVE_MSG	12
#define WLAN_KEEP_ALIVE_MSG	13
#define REORDERING_REQ          14 
#define REORDERING_RSP          15 

#define ACTIVE_WIFI_MNITOR	16 
#define SET_ROUTE		17 
#define SET_ANCHOR_MODE		18 
#define CREATE_CLIENT_REQ	19 
#define CREATE_CLIENT_ACK	20 
#define CLOSE_CLIENT_REQ	21
#define USER_PLAN_SETUP_CNF	22

#define LTE_RECONFIGURATION_REQ	23
#define LTE_RECONFIGURATION_ACK	24

#define TUN_SETUP_ACK	25
#define CLIENT_SUSPEND_REQ	26
#define TUN_SETUP_REQUEST 27
#define CLIENT_RESUME_REQ	28

#define TSC_MESSAGE_REQ	29
#define TSC_MESSAGE_ACK	30
#define CCU_MESSAGE_REQ	31
#define CCU_MESSAGE_ACK	32
#define SCU_MESSAGE_REQ	33
#define SCU_MESSAGE_ACK	34
#define TXC_MESSAGE_REQ 37
#define TXC_MESSAGE_ACK 38
#define TFC_MESSAGE_REQ 39
#define TFC_MESSAGE_ACK 40


#define SERVER_AESKEY_REQ 41
#define WINAPP_RESTART_ACK 42
#define RESTART_TO_NCM 43

#define PROBE_VNIC			1
#define TSU_VNIC			5
#define MEASURE_REPORT		255
#define ACK_VNIC			6
#define TSA_VNIC            7

#define MAX_PACKET_SIZE 2500
#define LTE_SOCKET 0
#define WIFI_SOCKET 1

#define MRP_REPORT 0
#define LRP_REPORT 1
#define URP_REPORT 2
#define SRP_REPORT 3

#define WIN_APP_KEY 1234
#define MEASURE_REPORT_HEADER 3

#define WIFI_CID 0
#define LTE_CID 3

#define NON_REALTIME_FLOW_ID 3 //downlink, we perform splitting; ul: wifi only if it is available
#define REALTIME_FLOW_ID 2 //downlink and uplink, switching only
#define DUPLICATE_FLOW_ID 1 //uplink
#define FHDR_FSN_NUM_MASK	0x00FFFFFF //3 bytes for data SN
#define FHDR_CSN_NUM_MASK	0x0000FFFF //2 bytes for control SN

#define WAKEUP_MSG_LENGTH 17

bool lte_data_available();//check if lte has data (index queue not empty)
bool wifi_data_available(); //check if wifi has data (index queue not empty)

class ClientManager
{
public:
	ClientManager();
	~ClientManager();

	/*
	*PrepareTxBuffer function is called to update the ringbuffer index to the next empty slot
	*If the buffer is not ready (all slots are occupied), it retuns a false pointer; otherwise returns true.
	*/
	bool PrepareTxBuffer();

	/*
	*GetTxBuffer function is called to get the tx buffer for storing the next packet.
	*/
	char * GetTxBuffer(); 

	/*
	*If a new packet is read from the TUN, ProcessPacket function is called to process this packet and schedule it to LTE/WiFi index queue.
	*If the queue is already full, it returns without any packet processing.
	*/
	void ProcessPacket(u_int bytes);

	/*
	*AddToWifiBuffer function add GMA header to the packet, update information related to the virtual index queue
	*/
	void AddToWifiBuffer (u_int index, u_int pkt_len, u_int flowId, char pkt_pri, u_int flow_sn, u_char tos);

	/*
	*AddToLteBuffer function add GMA header to the packet, update information related to the virtual index queue
	*/
	void AddToLteBuffer (u_int index, u_int pkt_len, u_int flowId, char pkt_pri, u_int flow_sn, u_char tos);

	/*
	*NotifyTransmitThreads function is called at the end of packet processing.
	*It add the current index to WiFi/LTE index queue (which triggers LTE/WiFiTransmitThread to send packet over LTE/WiFi)
	*/
	void NotifyWifiTransmitThreads();
	void NotifyLteTransmitThreads();

	/*
	*LteTransmitThread function is a always run thread that transmit queued packets to LTE whenever the LTE index queue is not empty
	*/
	void * LteTransmitThread();

	/*
	*WifiTransmitThread function is a always run thread that transmit queued packets to WiFi whenever the WiFi index queue is not empty
	*/
	void * WifiTransmitThread();

private:
    ClientManager(const ClientManager& src){ /* do not create copies */ }
	ClientManager& operator=(const ClientManager&){ return *this;}

public:
	char ** m_tx_buffer; //store packets in the ring buffer

	char * m_tx_tmp_buffer;

	bool * m_tx_buffer_occupied_by_lte; //For each item, flase stands for empty, ture means it is occupited
	bool*  m_tx_buffer_occupied_by_wifi; //For each item, false stands for empty, ture means it is occupited

	u_int * m_tx_buffer_pkt_len; // the packet length of each buffer item.
	u_char * m_tx_buffer_pkt_tos; // the packet length of each buffer item.
	u_short * m_tx_buffer_client_index; // the client index of each buffer item.
	u_short * m_wifi_index_list; //virtual wifi index queue (keep one slot empty for end pointer, otherwise both empty and full case , start = end pointer)
	u_short * m_lte_index_list; //virtual lte index queue (keep one slot empty for end pointer, otherwise both empty and full case , start = end pointer)

	u_short m_wifi_index_start;
	u_short m_wifi_index_end;

	u_short m_lte_index_start;
	u_short m_lte_index_end;

	u_short m_tx_buffer_index_end; //the index for next available slot of the ring buffer

	bool m_send_to_lte_flag;// current packet is scheduled to LTE
	bool m_send_to_wifi_flag;//current packet is chedule to WiFi

	bool m_lte_transmitting_flag; //true if lte is transmitting
	bool m_wifi_transmitting_flag; //true if wifi is transmitting

	/* the following params are for thread wait and notify*/
	std::mutex m_lte_mtx;
	std::mutex m_wifi_mtx;

	std::condition_variable m_lte_cond;
	std::condition_variable m_wifi_cond;

private:
};

extern ClientManager * g_cManager;

struct wake_up_req {
	u_char type;
	u_char cid;
	u_int key;
	u_short sn;
	u_short venderId;
	u_char subType;
}__attribute__((packed));


struct encrypted_vnic {
	u_char	aad[4];
	u_char	msg[1000];// ip + udp + payload
}__attribute__((packed));

struct encrypted_vnic_trailer {
	u_char	tag[16];
	u_char	iv[12];
}__attribute__((packed));


struct vnic_probe_req {
	u_char	type;
	u_char	cid;
	u_int   key;
	u_short	seq_num;
	u_char  link_bitmap;
	u_char	flag;
	u_char	rcid;
	u_int   time_stamp;
}__attribute__((packed));

struct vnic_tsu_req {
	u_char	type;
	u_char	cid;
	u_int   key;
	u_short seq_num;
	u_char  link_bitmap;
	u_char  flow_id1;
	u_char	K1;
	u_char	K2;
	u_char	L1;
	u_char  flow_id2;
	u_char	K3;
	u_char	K4;
	u_char	L2;
}__attribute__((packed));

struct measure_report_req {
	u_char	type;
	u_char	cid;
	u_int   key;
	u_short seq_num;
	u_short vendor_id;
	u_char  sub_type;
}__attribute__((packed));

struct vnic_ack {
	u_char	type;
	u_char	cid;
	u_int   key;
	u_short	seq_num;
	u_int   time_stamp;
	u_char  reqType;
}__attribute__((packed));

struct traffic_split_ack {
	u_char	type;
	u_char	cid;
	u_int   key;
	u_short	seq_num;
	u_int   time_stamp;
	u_char	flow_id1;
	u_int	start_sn1;//MSB is lsn, 3LSB are gsn
	u_char	flow_id2;
	u_int	start_sn2;//MSB is lsn, 3LSB are gsn
}__attribute__((packed));

struct tsc_msg_header {
	u_char	type;
	u_short vendor_id;
	u_char  sub_type;
	u_short len;
	u_char  ul_duplication_enable;
	u_char  dl_dynamic_split_enable;
	u_char  flow_id;
	u_char	K1;
	u_char	K2;
	u_char	L1;
}__attribute__((packed));

struct tfc_msg {
	u_char  flow_id; //1: HR; 2: RT; 3: NRT
	u_char  proto_type; //0: tcp, 1: udp, 2: icmp;
	u_short port_start;
	u_short port_end;
	u_char  flag;  //0: acked 1: non-acked 
}__attribute__((packed));

struct tsc_msg {
	u_char  ul_duplication_enable;
	u_char  dl_dynamic_split_enable;
	u_char  flow_id;
	u_char	K1;
	u_char	K2;
	u_char	L1;
	u_char  flag;  //0: acked 1: non-acked 
}__attribute__((packed));


struct tfc_msg_header {
	u_char	type; //255
	u_short vendor_id; //0 
	u_char  sub_type;
	u_char  flow_id; //1: HR; 2: RT; 3: NRT
	u_char  proto_type; //0: tcp, 1: udp, 2: icmp;
	u_short port_start;
	u_short port_end;
}__attribute__((packed));


struct ccu_msg_header {
	u_char	type;
	u_short vendor_id;
	u_char  sub_type;
	u_short len;
}__attribute__((packed));

struct ctl_msg_info
{
	u_short	len;
	u_char	seq_num;
	u_char	type;
	u_short	client_index;
};

struct ctl_msg_fmt
{
	struct ctl_msg_info info;
	u_char reserved[6];
};

struct winapp_ctl_msg
{
	u_int  key;
	u_int  flag;
}__attribute__((packed));

struct measure_report_to_winapp_header
{
	u_char  type;
	u_short UE_index;
}__attribute__((packed));


//struct *_params are defined to store measurement data, which will be used to compute the final measurement report
struct link_params
{
	int min_owd = INT_MAX;
	int max_owd = INT_MIN;
	int total_owd = 0; //ave owd = total_owd/packet_num
	u_int total_bytes = 0;
	u_int packet_num = 0;

	u_int packet_in_order = 0;
	u_int packet_out_of_order = 0;
	u_int packet_missing = 0;

}__attribute__((packed));

struct flow_params
{
	struct link_params lte;
	struct link_params wifi;
	struct link_params all; //only for hr flow

}__attribute__((packed));


struct measure_params
{
	struct flow_params rt;
	struct flow_params nrt;
	struct flow_params hr;

	u_int buffer_overflow = 0;
	u_int client_index_queue_overflow = 0;
	u_int reordering_timeout = 0;

}__attribute__((packed));

//struct *_report are the structures to store the report results.
struct link_report
{
	char owd_range = -1; //max - min (-1 ~ 127)
	char neg_log_loss = -1; // -(log(PLR)) -1 stands for no loss (-1 ~ 127)
	u_char outorder_packet_per_s = 0; //out of order packet per second (0 ~ 255)

}__attribute__((packed));

struct flow_report 
{
	u_short total_rate = 0; //Bps (0 ~ 65535)
	u_char  wifi_rate_per = 0; //0 - 100%
	char    ave_owd_diff = 0; //wifi owd - lte owd (-127 ~ 127)
	struct link_report lte;
	struct link_report wifi;
}__attribute__((packed));

struct hr_flow_report
{
	u_short total_rate = 0; //KBps (0 ~ 65535)
	char    ave_owd_diff = 0; //wifi owd - lte owd
	char    all_ave_owd_diff = 0; //all owd - lte owd
	struct link_report lte;
	struct link_report wifi;
	struct link_report all;//after reordering packets from both links
}__attribute__((packed));

struct measure_report
{
	int timestamp_s = 0;//timestamp (seconds) when the report is generated.
	struct flow_report nrt;//non-realtime flow
	struct flow_report rt;//realtime flow
	struct hr_flow_report hr;//high reliability flow
	u_int buffer_overflow = 0;
	u_int client_index_queue_overflow = 0;
	u_int reordering_timeout = 0;

}__attribute__((packed));

struct server_measure_params
{
	u_long dl_wifi_bytes = 0;
	u_long dl_lte_bytes = 0;
	u_long ul_wifi_bytes = 0;
	u_long ul_lte_bytes = 0;

	u_int dl_ring_buffer_overflow = 0;
	u_int ul_ring_buffer_overflow = 0;
	u_int ul_client_index_queue_overflow = 0; //all users combined

}__attribute__((packed));


struct server_measure_report
{
	u_int interval_index = 0; //range from 0 to SERVER_REPORT_CYLE
	int timestamp_s = 0;//timestamp (seconds) when the report is generated.
	u_int client_num = 0;
	u_int client_num_max = 0;
	u_int client_num_last_cycle_max = 0;

	//throughput kbps
	u_int dl_throughput = 0.0;
	u_int dl_throughput_max = 0.0;
	u_int dl_throughput_last_cycle_max = 0.0;

	u_int ul_throughput = 0.0;
	u_int ul_throughput_max = 0.0;
	u_int ul_throughput_last_cycle_max = 0.0;

	u_int total_throughput = 0.0;
	u_int total_throughput_max = 0.0;
	u_int total_throughput_last_cycle_max = 0.0;

	u_long dl_wifi_bytes_sum = 0;
	u_long dl_lte_bytes_sum = 0;
	double dl_wifi_ratio = 0.0;
	double dl_wifi_ratio_mean = 0.0;
	double dl_wifi_ratio_last_cycle_mean = 0.0;

	u_long ul_wifi_bytes_sum = 0;
	u_long ul_lte_bytes_sum = 0;
	double ul_wifi_ratio = 0.0;
	double ul_wifi_ratio_mean = 0.0;
	double ul_wifi_ratio_last_cycle_mean = 0.0;

	double total_wifi_ratio = 0.0;
	double total_wifi_ratio_mean = 0.0;
	double total_wifi_ratio_last_cycle_mean = 0.0;

	u_int dl_ring_buffer_overflow = 0;
	u_int dl_ring_buffer_overflow_max = 0;
	u_int dl_ring_buffer_overflow_last_cycle_max = 0;

	u_int ul_ring_buffer_overflow = 0;
	u_int ul_ring_buffer_overflow_max = 0;
	u_int ul_ring_buffer_overflow_last_cycle_max = 0;

	u_int ul_client_index_queue_overflow = 0; //all users combined
	u_int ul_client_index_queue_overflow_max = 0;
	u_int ul_client_index_queue_overflow_last_cyle_max = 0;

}__attribute__((packed));

struct client_info {
	u_int		client_index = 0;
	u_int		req_sn = 0; //create client msg SN
	u_int     session_id = 0;
	u_char aes_key[32]  = {};

	u_int   dl_sn = 0;  //sn only for non realtime
	u_int	dl_rt_sn = 0;//sn only for realtime traffic
	u_int	dl_hr_sn = 0;//sn only for duplicating traffic

	u_char  dl_lsn_lte = 0;
	u_char  dl_lsn_wifi = 0;

	u_char linkStatusBitmap = 0;

	unsigned short client_wifi_adapt_port  = 0;
	unsigned short client_lte_adapt_port  = 0;
	unsigned short client_probe_port  = 0;
	unsigned char  client_wifi_adapt_ip[4]  = {0};
	unsigned char  client_lte_adapt_ip[4]  = {0};
	bool	       lte_link_ok  = false;
	bool	       wifi_link_ok  = false;
	bool           client_suspend  = false;
	bool           lte_link_used  = false;
	bool           wifi_link_used  = false;
	int            keep_alive_wifi_socket  = 0;
	int            keep_alive_lte_socket  = 0;
	unsigned int	last_wifi_keep_alive_sent_time  = 0;
	unsigned int	last_lte_keep_alive_sent_time  = 0;
	bool		   qos_queue_configured = false; // we use htb queue dis to provide per client per class per flow type QoS

	unsigned short last_control_msg_sn = 0;

	unsigned char tsu_lte_split_size = 0;
	unsigned char tsu_wifi_split_size = 0;
	unsigned char tsu_traffic_split_threshold = 0;
	unsigned char tsu_split_count = 0;
	unsigned short last_tsu_sn = 0;

	bool          rt_traffic_over_lte = false;

	int	split_total = 0;
	int	split_lte = 0;
	char	split_on = 0;

	bool		fiveG_probe_thread_flag = 0;
	bool		lte_probe_thread_flag = 0;
	bool		fiveG_probe_ack_flag = 0;
	bool		LTE_stay_flag = 0;

	struct sockaddr_in  client_lte_addr = {};
	struct sockaddr_in  client_wifi_addr = {};
	struct sockaddr_in	client_vnic_addr = {};

	u_short	ul_next_sn = 0;
	u_short	ul_last_sn = 0;
	u_short	g_sn = 0;

	unsigned int start_time = 0;
	unsigned int ul_packet_sn = 0;
	unsigned int ul_packet_sn_last = 0;
	
	unsigned int last_recv_msg_time = 0;
	unsigned int last_recv_wifi_msg_time = 0;
	unsigned int last_recv_lte_msg_time = 0;

	u_short* m_shared_rx_index_list = NULL; //virtual wifi index queue
	u_short m_rx_index_start = 0;
	u_short m_rx_index_end = 0;

	unsigned int nrt_inorder_sn = 0;//this sn is only for non-realtime packet measurement
	unsigned int rt_inorder_sn = 0;//this sn is only for realtime packet measurement

	unsigned int hr_wifi_inorder_sn = 0;//this sn is only for hr packet measurement, before reordering
	unsigned int hr_lte_inorder_sn = 0;//this sn is only for hr packet measurement, before reordering

	unsigned int hr_output_inorder_sn = 0;//this sn is only for hr measurement of output index queue, after reordering

	measure_params m_measure_info = {};
	measure_report m_measure_report = {};

	tfc_msg tfcmsg = {};
	tsc_msg tscmsg = {};

}__attribute__((packed));

struct ul_measurement //urp main message
{
	u_short UE_index;
	u_short time_stamp;
	u_char num_of_output_bufferoverflows;
	u_char num_of_reordering_bufferoverflows;
	u_char reordering_timeout;
	u_char	flag; // bit 0: rt, bit 1: nrt, bit 2: hr
}__attribute__((packed));

struct ul_measurement_ext_a //urp extention format a: for nrt and rt flow
{
	u_short total_throughput;
	u_char  wifi_percent; //wifi/total*100
	char    ave_owd_diff; //wifi - lte
	char    wifi_owd_range; // max - min
	char	lte_owd_range; //max - min
	u_char  wifi_neg_log_loss; //-log(LRP)
	u_char  lte_neg_log_loss;//-log(LRP)
	u_char  wifi_outoforder;
	u_char lte_outoforder;
}__attribute__((packed));

struct ul_measurement_ext_b //urp extention format b: for nrt and rt flow
{
	u_short total_throughput;
	char    ave_owd_diff; //wifi - lte
	char    all_ave_owd_diff; //all - lte
	char    wifi_owd_range; // max - min
	char	lte_owd_range; //max - min
	char	all_owd_range; //max - min
	u_char  wifi_neg_log_loss; //-log(LRP)
	u_char  lte_neg_log_loss;//-log(LRP)
	u_char  all_neg_log_loss;//-log(LRP)
	u_char  wifi_outoforder;
	u_char lte_outoforder;
	u_char all_outoforder;//for realtime flow, the outoforder number is alreay 0, because it is dropped due to reordering

}__attribute__((packed));


struct server_measurement //srp
{
	u_short time_stamp;
	u_short num_of_active_clients_last;
	u_short num_of_active_clients_current_max;
	u_short num_of_active_clients_last_max;
	u_short dl_throughput_last;
	u_short dl_throughput_current_max;
	u_short dl_throughput_last_max;
	u_short ul_throughput_last;
	u_short ul_throughput_current_max;
	u_short ul_throughput_last_max;
	u_short total_throughput_last;
	u_short total_throughput_current_max;
	u_short total_throughput_last_max;
	u_char dl_wifi_ratio_last;
	u_char dl_wifi_ratio_current_average;
	u_char dl_wifi_ratio_last_average;
	u_char ul_wifi_ratio_last;
	u_char ul_wifi_ratio_current_average;
	u_char ul_wifi_ratio_last_average;
	u_char total_wifi_ratio_last;
	u_char total_wifi_ratio_current_average;
	u_char total_wifi_ratio_last_average;
	u_short num_of_dl_tx_ringbufferoverflow_last;
	u_short num_of_dl_tx_ringbufferoverflow_current_max;
	u_short num_of_dl_tx_ringbufferoverflow_last_max;
	u_short num_of_ul_rx_ringbufferoverflow_last;
	u_short num_of_ul_rx_ringbufferoverflow_current_max;
	u_short num_of_ul_rx_ringbufferoverflow_last_max;
	u_short num_of_ul_ue_rx_ringbufferoverflow_last;
	u_short num_of_ul_ue_rx_ringbufferoverflow_current_max;
	u_short num_of_ul_ue_rx_ringbufferoverflow_last_max;
}__attribute__((packed));

#define CTL_MSG_FMT_LEN		sizeof(struct ctl_msg_fmt)
#define CTL_MSG_INFO_LEN	sizeof(struct ctl_msg_info)
#define CLIENT_INFO_LEN		sizeof(struct client_info)

extern int N_total;
extern int N_lte;
extern char split_on;
extern client_info* client_info_arrays;
extern u_int max_client_num;
int send_tun_setup_ack_to_ncm();
int send_aeskey_to_ncm();
extern void send_measurement_report_to_winapp(u_char type, int client_index, char* buf, int len);
#endif