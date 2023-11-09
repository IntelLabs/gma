//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : IFOMServer.cpp
//Description : c++ file for Generic Multi-Access Network Virtualization

#include <fstream>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include "IFOMServer.h"
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>

#include <errno.h> 
#include <arpa/inet.h> //close 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include <sstream>      // std::stringstream

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace std;

u_int max_client_num = 0;// the max num of client, it's value will be sent to server by NCM
int client_info_arrays_index = 0;//index for new client
client_info* client_info_arrays = NULL; //vector to store all client info
int last_client_session_id = -1; //last client session id

bool	g_bServerRun = true;
bool    g_bQuit = true;
bool    g_send_measurement_to_winapp = false;
bool	g_bInsmod = false;
bool	g_flag = false;
bool	print_flag = false;
bool    tun_set_up = false;
u_long	total_ul_fiveG_bytes = 0;

int	ncm_send_sockfd; 
struct	sockaddr_in ncm_addr;
struct	sockaddr_in winapp_addr;

int g_lte_tunnel_sockfd = -1; //socket will return -1 when error happens
int g_wifi_tunnel_sockfd = -1; //socket will return -1 when error happens
int g_vnic_ctl_sockfd = -1; //socket will return -1 when error happens
int g_measure_report_sockfd = -1; //socket will return -1 when error happens
int g_lte_tcp_socktfd = -1;
int g_wifi_tcp_socktfd = -1;

//unsigned short  g_websock_port = 0;
//unsigned int    g_websock_ip   = 0;
unsigned char  g_vnic_ip[4];
unsigned char  g_vnic_gateway[4];
unsigned char  g_vnic_mask[4];
unsigned char  g_vnic_dns[4];
u_short server_udp_port;
u_short server_tcp_port;
unsigned int max_keep_client_time;

char	fiveG_buf[1514];
struct sockaddr_in	ifom_lte_addr;
struct sockaddr_in	ifom_wifi_addr;
struct sockaddr_in	ifom_virtual_addr;
struct sockaddr_in	GW_addr;
struct itimerspec fiveG_probe_ts;
struct itimerspec LTE_stay_ts;

std::mutex wait_command_mtx;
std::condition_variable wait_command_cond;

pthread_t		send_data_packets_thread_id;
pthread_t		send_data_packets_thread_prerouting_id;	
pthread_t		talk_with_ncm_thread_id; 
pthread_t		read_command_line_input_thread_id;

pthread_t   lte_wifi_tunnel_recv_thread_id;
pthread_t   lte_wifi_keep_alive_thread_id;
pthread_t   lte_wifi_keep_alive_thread2_id;
pthread_t	vnic_ctl_recv_thread_id;
pthread_t	receive_winapp_control_message_thread_id;
pthread_t	m_lte_transmit_thread_id; 
pthread_t	m_wifi_transmit_thread_id; 
pthread_t 	m_rx_buffer_ouput_thread_id; 
pthread_t 	m_measurement_thread_id;

static const int REVERSE_BITS_INDEX32[32] = {0, 16,  8, 24,  4, 20, 12, 28,  2, 18, 10, 26,  6, 22, 14, 30,  1, 17,
  9, 25,  5, 21, 13, 29,  3, 19, 11, 27,  7, 23, 15, 31}; //reversed index for 32 bits

typedef void * (*THREADFUNCPTR)(void *);


ClientManager * g_cManager;

char ** m_rx_buffer;
u_short m_rx_buffer_index_end = 0;
bool * m_rx_buffer_occupied;

u_short * m_rx_buffer_packet_len;
char * m_wifi_wakeup_msg;
char * m_lte_wakeup_msg;

u_short * m_rx_buffer_header_size;
u_int * m_rx_buffer_packet_sn;
u_short m_wr_len;
u_int * m_rx_buffer_rx_timestamp; // receive timestamp, ms.

u_short * m_rx_buffer_output_list; //this list size can be smaller or equal RX ring buffer size
u_short m_rx_buffer_output_start = 0;
u_short m_rx_buffer_output_end = 0;

bool m_output_running_flag = false;

std::mutex m_output_mtx;
std::condition_variable m_output_cond;

bool * m_client_active_check = NULL;//true if a user receives at least one packet per measure interval
std::queue<u_int> m_client_active_list; //store the index of active clients.

server_measure_params m_server_measure;
server_measure_report m_server_report;

unsigned int g_time_param_s = 0;
unsigned int g_time_param_ms = 0;
unsigned int g_time_param_us = 0;

unsigned int g_total_bytes = 0;
unsigned int g_time_param_us_last = 0;
unsigned int g_time_param_s_last = 0;

EVP_CIPHER_CTX* g_ctx;

u_char g_ncm_aeskey[32];
bool encrypted_ncm = false;

void update_current_time_params()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	g_time_param_s = (unsigned int)(tv.tv_sec);
	g_time_param_us = (unsigned int)(tv.tv_usec);
	g_time_param_ms = (unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}


void reset_server_parameters()
{
	g_send_measurement_to_winapp = false;
	client_info_arrays_index = 0;

	memset(&winapp_addr, 0, sizeof(winapp_addr));

	g_lte_tunnel_sockfd = -1;
	g_wifi_tunnel_sockfd = -1;
	g_vnic_ctl_sockfd = -1;
	g_measure_report_sockfd = -1;
	g_lte_tcp_socktfd = -1;
	g_wifi_tcp_socktfd = -1;

	m_rx_buffer_index_end = 0;
	m_wr_len = 0;
	m_rx_buffer_output_start = 0;
	m_rx_buffer_output_end = 0;
	m_output_running_flag = false;

	while (!m_client_active_list.empty())
		m_client_active_list.pop();

	m_server_measure = server_measure_params();
	m_server_report = server_measure_report();
}

bool lte_data_available()
{
	//ture if lte index queue not empy
	return g_cManager->m_lte_index_end != g_cManager->m_lte_index_start;
}

bool wifi_data_available()
{
	//true if wifi index queue not empty
	return g_cManager->m_wifi_index_end != g_cManager->m_wifi_index_start;
}

ClientManager::ClientManager()
{
	//for tx buffer
	m_tx_buffer_index_end = 0; //the index for next available slot

	m_wifi_index_start = 0;
	m_wifi_index_end = 0;

	m_lte_index_start = 0;
	m_lte_index_end = 0;

	m_send_to_lte_flag = false;

	m_send_to_wifi_flag = false;

	m_lte_transmitting_flag = false;
	m_wifi_transmitting_flag = false;

	m_tx_buffer = new char * [MAX_TX_BUFFER_SIZE];

	m_tx_tmp_buffer = new char[MAX_PACKET_SIZE];

	for (int i = 0; i < MAX_TX_BUFFER_SIZE; i++)
	{
		m_tx_buffer[i] = new char[MAX_PACKET_SIZE];
	}
	m_tx_buffer_occupied_by_lte = new bool[MAX_TX_BUFFER_SIZE]; //For each item, flase stands for empty, ture means it is occupited
	m_tx_buffer_occupied_by_wifi = new bool[MAX_TX_BUFFER_SIZE]; //For each item, false stands for empty, ture means it is occupited
	for (unsigned int ind = 0; ind < MAX_TX_BUFFER_SIZE; ind++)
	{
		m_tx_buffer_occupied_by_lte[ind] = false;
		m_tx_buffer_occupied_by_wifi[ind] = false;
	}

	m_tx_buffer_pkt_len = new u_int[MAX_TX_BUFFER_SIZE]; // the packet length of each buffer item.
	m_tx_buffer_pkt_tos = new u_char[MAX_TX_BUFFER_SIZE];
 	m_tx_buffer_client_index = new u_short[MAX_TX_BUFFER_SIZE]; // the client index of each buffer item.
	m_wifi_index_list = new u_short[MAX_TX_BUFFER_SIZE + 1]; //virtual wifi index queue (keep one slot empty for end pointer, otherwise both empty and full case , start = end pointer)
	m_lte_index_list = new u_short[MAX_TX_BUFFER_SIZE + 1]; //virtual lte index queue (keep one slot empty for end pointer, otherwise both empty and full case , start = end pointer)
};

ClientManager::~ClientManager()
{
	for(int i = 0; i < MAX_TX_BUFFER_SIZE; i++)
	{
		delete[] m_tx_buffer[i];
	}
	delete[] m_tx_buffer;
	delete[] m_tx_tmp_buffer;
	delete[] m_tx_buffer_occupied_by_lte;
	delete[] m_tx_buffer_occupied_by_wifi;
	delete[] m_tx_buffer_pkt_len;
	delete[] m_tx_buffer_pkt_tos;
	delete[] m_tx_buffer_client_index;
	delete[] m_wifi_index_list;
	delete[] m_lte_index_list;

};

bool ClientManager::PrepareTxBuffer()
{
	for(u_short counter = 0; counter < MAX_TX_BUFFER_SIZE; counter++) // find the next available slot, if no available slot, return null
	{
		u_short slot = (m_tx_buffer_index_end + counter) % MAX_TX_BUFFER_SIZE;

		if(!m_tx_buffer_occupied_by_lte[slot] && !m_tx_buffer_occupied_by_wifi[slot])//empty slot
		{
			m_tx_buffer_index_end = slot;
			return true;
		}
	}

	if (ENABLE_MEASUREMENT)
	{
		m_server_measure.dl_ring_buffer_overflow++;
	}
	printf("BUFFER FULL!!! wifi size: %d lte size: %d \n", 
		(m_wifi_index_end + MAX_TX_BUFFER_SIZE + 1 - m_wifi_index_start) % (MAX_TX_BUFFER_SIZE + 1), (m_lte_index_end + MAX_TX_BUFFER_SIZE + 1 - m_lte_index_start) % (MAX_TX_BUFFER_SIZE + 1));
	return false;
};

char* ClientManager::GetTxBuffer()
{
	return m_tx_buffer[m_tx_buffer_index_end] + GMA_HEADER_OFFSET;
}

void * ClientManager::LteTransmitThread()
{
	int ret;
	int t;
	char *l_sn;
	u_short txCounter = 0;
	m_lte_index_start = 0;
	m_lte_index_end = 0;
	u_char tos_local = 255;
	while (g_bServerRun)
	{
    	std::unique_lock<std::mutex> lck(m_lte_mtx);
    	m_lte_cond.wait(lck,lte_data_available);//wait until lte has data
  		m_lte_transmitting_flag = true;//flag the lte is in transmitting state.
		if(!g_bServerRun)
			break;
  		while(m_lte_index_end != m_lte_index_start)//lte index queue not empty
			{
				if(m_lte_index_start < MAX_TX_BUFFER_SIZE + 1)
				{
					t = 0;
					u_short buff_index = m_lte_index_list[m_lte_index_start];//first index in the lte index queue
				
					u_int array_index = m_tx_buffer_client_index[buff_index];// the client information
					if (client_info_arrays[array_index].client_lte_addr.sin_port > 0)
					{
						int i = 0;
						while(m_tx_buffer_occupied_by_wifi[buff_index] == true && i< 10)
						{
							usleep(1);
							i++;
						}

						//add per-packet ToS marking
						if (tos_local != m_tx_buffer_pkt_tos[buff_index])
						{
							tos_local = m_tx_buffer_pkt_tos[buff_index];
							setsockopt(g_lte_tunnel_sockfd, IPPROTO_IP, IP_TOS, &tos_local, sizeof(tos_local));
						}
						///////////////////////////				

						if (m_tx_buffer_occupied_by_wifi[buff_index] == false)//if wifi already sent, no need to copy
						{
							//for nrt data packets change LSN
							if (*(char*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 4) == NON_REALTIME_FLOW_ID) {//change lsn for non-realtime traffic
								//struct virtual_dl_data_header* header = (struct virtual_dl_data_header*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA);
								l_sn = (char*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 6);
								*l_sn = client_info_arrays[array_index].dl_lsn_lte;
								client_info_arrays[array_index].dl_lsn_lte = (client_info_arrays[array_index].dl_lsn_lte + 1) & 0xFF;
					
							}

							ret = sendto(g_lte_tunnel_sockfd, m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA,
								m_tx_buffer_pkt_len[buff_index] + VIRTUAL_DL_DATA, 0,
								(struct sockaddr*)&client_info_arrays[array_index].client_lte_addr, sizeof(client_info_arrays[array_index].client_lte_addr));
							
							if (ret < 0)
								printf("[err] send_pkt_to_client_through_lte %d,\n", ret);
							
						}
						else
						{
							//this is a duplicated data packet, cannot overwrite the header directly. Make a copy
							if (*(char*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 4) == NON_REALTIME_FLOW_ID)
							{
								memcpy(m_tx_tmp_buffer, m_tx_buffer[buff_index], MAX_PACKET_SIZE);
								l_sn = (char*)(m_tx_tmp_buffer + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 6);
								*l_sn = client_info_arrays[array_index].dl_lsn_lte;
								client_info_arrays[array_index].dl_lsn_lte = (client_info_arrays[array_index].dl_lsn_lte + 1) & 0xFF;
								ret = sendto(g_lte_tunnel_sockfd, m_tx_tmp_buffer + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA,
								m_tx_buffer_pkt_len[buff_index] + VIRTUAL_DL_DATA, 0,
								(struct sockaddr*)&client_info_arrays[array_index].client_lte_addr, sizeof(client_info_arrays[array_index].client_lte_addr));
							
							}
							else
							{
								ret = sendto(g_lte_tunnel_sockfd, m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA,
								m_tx_buffer_pkt_len[buff_index] + VIRTUAL_DL_DATA, 0,
								(struct sockaddr*)&client_info_arrays[array_index].client_lte_addr, sizeof(client_info_arrays[array_index].client_lte_addr));

							}

							if (ret < 0)
								printf("[err] send_pkt_to_client_through_lte \n");

						}
					}

					m_tx_buffer_occupied_by_lte[buff_index] = false;
				}
				m_lte_index_start = (m_lte_index_start + 1) % (MAX_TX_BUFFER_SIZE + 1);//update lte index queue start pointer

			}
		m_lte_transmitting_flag = false; //lte transmiting end
	}
	return NULL;
};

void * ClientManager::WifiTransmitThread()
{
	int ret;
	int t;
	u_short txCounter = 0;
	char * l_sn;
	m_wifi_index_start = 0;
	m_wifi_index_end = 0;
	u_char tos_local = 255;
	while (g_bServerRun)
	{
    	std::unique_lock<std::mutex> lck(m_wifi_mtx);
    	m_wifi_cond.wait(lck,wifi_data_available);//wait until wifi has data
    	m_wifi_transmitting_flag = true;//flat is currently transmitting data
		if(!g_bServerRun)
			break;
    	while(m_wifi_index_end != m_wifi_index_start)// wifi index queue not empty
			{
				if(m_wifi_index_start < MAX_TX_BUFFER_SIZE + 1)
				{
					t = 0;
					u_short buff_index = m_wifi_index_list[m_wifi_index_start];//get the first index from wifi index queue
					u_int array_index = m_tx_buffer_client_index[buff_index];//get client information

					if (client_info_arrays[array_index].client_wifi_addr.sin_port > 0)
					{

						if (*(char*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 4) == NON_REALTIME_FLOW_ID) {//change lsn for non-realtime traffic
							l_sn = (char*)(m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA + 6);
							*l_sn = client_info_arrays[array_index].dl_lsn_wifi;
							client_info_arrays[array_index].dl_lsn_wifi = (client_info_arrays[array_index].dl_lsn_wifi + 1) & 0xFF;
						}

						//add per-packet ToS marking
						if (tos_local != m_tx_buffer_pkt_tos[buff_index])
						{
							tos_local = m_tx_buffer_pkt_tos[buff_index];
							setsockopt(g_wifi_tunnel_sockfd, IPPROTO_IP, IP_TOS, &tos_local, sizeof(tos_local));
						}
						///////////////////////////				

						ret = sendto(g_wifi_tunnel_sockfd, m_tx_buffer[buff_index] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA,
							m_tx_buffer_pkt_len[buff_index] + VIRTUAL_DL_DATA, 0,
							(struct sockaddr*)&client_info_arrays[array_index].client_wifi_addr, sizeof(client_info_arrays[array_index].client_wifi_addr));

					}
					m_tx_buffer_occupied_by_wifi[buff_index] = false;
				}
				m_wifi_index_start = (m_wifi_index_start + 1) % (MAX_TX_BUFFER_SIZE + 1);//update wifi index queue start pointer

			}
		m_wifi_transmitting_flag = false;//flag wifi end transmitting
	}
	return NULL;
};


void WakeupMsgOverLte(u_int array_index) {

	//timestamp updated at the beginning of ProcessPacket function.
	if (LTE_WAKEUP_TIMEOUT_S != 0 && 
		((g_time_param_s - client_info_arrays[array_index].last_lte_keep_alive_sent_time) > LTE_WAKEUP_TIMEOUT_S) && 
		((g_time_param_s - client_info_arrays[array_index].last_recv_lte_msg_time) > LTE_WAKEUP_TIMEOUT_S))
	{//send TCP wakeup message if the last sent wakeup msg and last received message is more than timeout, (0 timeout stands for disable wakeup msg)
		client_info_arrays[array_index].last_lte_keep_alive_sent_time = g_time_param_s;

		//send TCP to client
		int clientSocket = client_info_arrays[array_index].keep_alive_lte_socket;

		if (clientSocket != 0)
		{
			// / length(2B)/ Virtual IP (4B) / Type (1B) / CID (1B) / Key (4B) / SN (2B) / Vender ID (2B) / Sub-type (1B) /

			m_lte_wakeup_msg[1] = 0;
			m_lte_wakeup_msg[0] = 15;

			m_lte_wakeup_msg[5] = 0;
			m_lte_wakeup_msg[4] = 0;
			m_lte_wakeup_msg[3] = 0;
			m_lte_wakeup_msg[2] = 0;

			m_lte_wakeup_msg[6] = 255;

			m_lte_wakeup_msg[7] = 0;

			m_lte_wakeup_msg[11] = 0;
			m_lte_wakeup_msg[10] = 0;
			m_lte_wakeup_msg[9] = 0;
			m_lte_wakeup_msg[8] = 0;

			m_lte_wakeup_msg[13] = 0;
			m_lte_wakeup_msg[12] = 0;

			m_lte_wakeup_msg[15] = 0;
			m_lte_wakeup_msg[14] = 0;

			m_lte_wakeup_msg[16] = 6;

			if (send(clientSocket, m_lte_wakeup_msg, WAKEUP_MSG_LENGTH, MSG_NOSIGNAL) != -1)
			  printf("send keep alive message over LTE. current time %d, last lte msg time %d\n", g_time_param_s, client_info_arrays[array_index].last_recv_lte_msg_time);
			else
			  printf("\n send keep alive message over LTE failed");
			
		}
		else
		{
			printf("no keep alive socket connected to LTE, array_index: %d\n", array_index);
		}
	}
}

void WakeupMsgOverWifi(u_int array_index) {
	//timestamp updated at the beginning of ProcessPacket function.
	
	if (WIFI_WAKEUP_TIMEOUT_S != 0 &&
		((g_time_param_s - client_info_arrays[array_index].last_wifi_keep_alive_sent_time) > WIFI_WAKEUP_TIMEOUT_S) &&
		((g_time_param_s - client_info_arrays[array_index].last_recv_wifi_msg_time) > WIFI_WAKEUP_TIMEOUT_S))
	{//send TCP wakeup message if the last sent wakeup msg and last received message is more than timeout, (0 timeout stands for disable wakeup msg)
		client_info_arrays[array_index].last_wifi_keep_alive_sent_time = g_time_param_s;

		//send TCP to client
		int clientSocket = client_info_arrays[array_index].keep_alive_wifi_socket;
		if (clientSocket != 0)
		{
			// / length(2B)/ Virtual IP (4B) / Type (1B) / CID (1B) / Key (4B) / SN (2B) / Vender ID (2B) / Sub-type (1B) /

			//I will put only type = 255, subtype = 6 and cid = 0, other fields are empty
			//int msgLength = 17;

			//char* message = new char[msgLength];
			m_wifi_wakeup_msg[1] = 0;
			m_wifi_wakeup_msg[0] = 15;

			m_wifi_wakeup_msg[5] = 0;
			m_wifi_wakeup_msg[4] = 0;
			m_wifi_wakeup_msg[3] = 0;
			m_wifi_wakeup_msg[2] = 0;

			m_wifi_wakeup_msg[6] = 255;

			m_wifi_wakeup_msg[7] = 0;

			m_wifi_wakeup_msg[11] = 0;
			m_wifi_wakeup_msg[10] = 0;
			m_wifi_wakeup_msg[9] = 0;
			m_wifi_wakeup_msg[8] = 0;

			m_wifi_wakeup_msg[13] = 0;
			m_wifi_wakeup_msg[12] = 0;

			m_wifi_wakeup_msg[15] = 0;
			m_wifi_wakeup_msg[14] = 0;

			m_wifi_wakeup_msg[16] = 6;

			if (send(clientSocket, m_wifi_wakeup_msg, WAKEUP_MSG_LENGTH, MSG_NOSIGNAL) == -1)
				printf("Keep alive over Wi-Fi failed\n");
		
		}
		else
		{
			printf("no keep alive socket connected to wifi, array_index: %d\n", array_index);
		}
	}
}


void ClientManager::ProcessPacket(u_int bytes)
{
	update_current_time_params();//this function will update the global variable g_current_time_s and g_current_time_ms
	//find lte index from ip address
	struct iphdr * ip_h = (struct iphdr *)(m_tx_buffer[m_tx_buffer_index_end] + GMA_HEADER_OFFSET);
	
	u_int flowId = NON_REALTIME_FLOW_ID;
	char pkt_pri = 0x00;

	if(ip_h->version!=0x04)
	{
		//not ipv4 packets
		return;
	}
	else
	{
		/* per-packet priority marking example
		if (ip_h->protocol == 17) //UDP
		{
			flowId = REALTIME_FLOW_ID;
			int udp_payload_len = bytes - 28;
			switch (udp_payload_len) {
			case 1001: pkt_pri = 0x01; break;
			case 1002: pkt_pri = 0x02; break;
			case 1003: pkt_pri = 0x03; break;
			case 1004: pkt_pri = 0x04; break;
			case 1005: pkt_pri = 0x05; break;
			case 1006: pkt_pri = 0x06; break;
			case 1007: pkt_pri = 0x07; break;
			default: break;
			}
		}*/
	
	}
	
	u_int client_index;
	u_int array_index;
	
	client_index = (u_int)(ntohl(ip_h->daddr) & 0x0000FFFF);

	
	if (client_index >= 2 && client_index < max_client_num + 2) {
		array_index = client_index - 2;
	}
	else{
		printf("[err] send ctl ack, no client\n");
		return;
	}

	if (ip_h->tos == hr_flow_dscp) //HR_FLOW TBD: TOS Configurable
	{
		flowId = DUPLICATE_FLOW_ID;
	} 
	else if (ip_h->tos == rt_flow_dscp) //RT_FLOW
	{
		flowId = REALTIME_FLOW_ID;
	}

	if (client_info_arrays[array_index].last_recv_msg_time !=0) {

		if (ENABLE_MEASUREMENT)
		{
			if(!m_client_active_check[array_index])//store this client index into active list
			{
				m_client_active_list.push(array_index);
				m_client_active_check[array_index] = true;
			}
		}

		//data packet operations below:
		switch (flowId) {
		case REALTIME_FLOW_ID:
			client_info_arrays[array_index].dl_rt_sn = ((client_info_arrays[array_index].dl_rt_sn) + 1) & FHDR_FSN_NUM_MASK;
			//real time flow
			if (client_info_arrays[array_index].rt_traffic_over_lte) {
				WakeupMsgOverLte(array_index);//duplicate mode, wakeup msg over wifi
				AddToLteBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_rt_sn, ip_h->tos);
			}
			else {
				WakeupMsgOverWifi(array_index);//duplicate mode, wakeup msg over wifi
				AddToWifiBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_rt_sn, ip_h->tos);
			}
			break;
		
		case DUPLICATE_FLOW_ID: 
			client_info_arrays[array_index].dl_hr_sn = ((client_info_arrays[array_index].dl_hr_sn) + 1) & FHDR_FSN_NUM_MASK;
			if (client_info_arrays[array_index].lte_link_ok)
			{
				WakeupMsgOverLte(array_index);//duplicate mode, wakeup msg over wifi
				AddToLteBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_hr_sn, ip_h->tos);
			}
			if (client_info_arrays[array_index].wifi_link_ok)
			{
				WakeupMsgOverWifi(array_index);//duplicate mode, wakeup msg over wifi
				AddToWifiBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_hr_sn, ip_h->tos);
			}
			break;
		default:
			//non realtime flow
			client_info_arrays[array_index].dl_sn = ((client_info_arrays[array_index].dl_sn) + 1) & FHDR_FSN_NUM_MASK;
				// split on, split traffic to wifi and lte, for L packets, first K1 packets send over WiFi, last K2 packets send over LTE.
				//e.g., L = 3, k1 = 2, k2 = 2. packet 1 over Wi-Fi, packet 2 over LTE and Wi-Fi, packet 3 over LTE

				if (client_info_arrays[array_index].tsu_traffic_split_threshold > 0) {

					if (client_info_arrays[array_index].tsu_wifi_split_size > 0)
					{
						WakeupMsgOverWifi(array_index);//wifi split ratio > 0, wakeup msg over wifi
					}
					else
					{
						WakeupMsgOverLte(array_index);//wifi split ratio = 0, wakeup msg over lte
					}

					if (client_info_arrays[array_index].tsu_traffic_split_threshold == 32) {//L = 32, use randomized index
						if (REVERSE_BITS_INDEX32[client_info_arrays[array_index].tsu_split_count] < client_info_arrays[array_index].tsu_wifi_split_size) {//first k1 over WiFI, randomized
							AddToWifiBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_sn, ip_h->tos);
							//printf("wifi send: %d\n",client_info_arrays[array_index].tsu_split_count);
						}

						if (client_info_arrays[array_index].tsu_traffic_split_threshold - REVERSE_BITS_INDEX32[client_info_arrays[array_index].tsu_split_count] <= client_info_arrays[array_index].tsu_lte_split_size) {//K2 over LTE, randomized
							AddToLteBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_sn, ip_h->tos);
							//printf("lte send: %d\n", client_info_arrays[array_index].tsu_split_count);
						}

					}
					else {//don't use randomized index
						if (client_info_arrays[array_index].tsu_split_count < client_info_arrays[array_index].tsu_wifi_split_size) {//first k1 over WiFI
							AddToWifiBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_sn, ip_h->tos);
							//printf("wifi send: %d\n",client_info_arrays[array_index].tsu_split_count);
						}

						if (client_info_arrays[array_index].tsu_traffic_split_threshold - client_info_arrays[array_index].tsu_split_count <= client_info_arrays[array_index].tsu_lte_split_size) {//last K2 over LTE
							AddToLteBuffer(array_index, bytes, flowId, pkt_pri, client_info_arrays[array_index].dl_sn, ip_h->tos);
							//printf("lte send: %d\n", client_info_arrays[array_index].tsu_split_count);
						}
					}

					client_info_arrays[array_index].tsu_split_count++;// from 0 to L-1.
					if (client_info_arrays[array_index].tsu_split_count >= client_info_arrays[array_index].tsu_traffic_split_threshold) {// if counter == L, set it to 0
						client_info_arrays[array_index].tsu_split_count = 0;
					}
					
				}
				else {
					printf("[err] split threshold <= 0\n");
				}

	
			break;
		}
	}
}

void ClientManager::AddToLteBuffer(u_int array_index, u_int pkt_len, u_int flowId, char pkt_pri, u_int flow_sn, u_char tos) {

	if(ENABLE_MEASUREMENT)
	{
		m_server_measure.dl_lte_bytes += pkt_len;
	}
	//add header

	struct virtual_dl_data_header* header = (struct virtual_dl_data_header*)(m_tx_buffer[m_tx_buffer_index_end] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA);
	*(u_short*)header->flag = htons(0xF807);
	*(u_short*)header->client_id = htons(array_index+2);//client index


	header->flow_id = flowId;
	header->ppp = pkt_pri;
	header->sn = htonl(flow_sn);//3 LSB are gsn
	
	//current time updated at the begining of ProcessPacket function.
	unsigned int last_tx_timestamp_lte = (client_info_arrays[array_index].start_time == 0 ? 0 : (g_time_param_ms + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);
	header->time_stamp = htonl(last_tx_timestamp_lte);
	
	m_tx_buffer_pkt_len[m_tx_buffer_index_end] = pkt_len; //store packet length
	m_tx_buffer_pkt_tos[m_tx_buffer_index_end] = tos;
	m_tx_buffer_client_index[m_tx_buffer_index_end] = array_index; // store client index.
	m_send_to_lte_flag = true;// indicate this packet is scheduled for LTE

	NotifyLteTransmitThreads();

}

void ClientManager::AddToWifiBuffer(u_int array_index, u_int pkt_len, u_int flowId, char pkt_pri, u_int flow_sn, u_char tos) {

	if(ENABLE_MEASUREMENT)
	{
		m_server_measure.dl_wifi_bytes += pkt_len;
	}
	//add header

	struct virtual_dl_data_header* header = (struct virtual_dl_data_header*)(m_tx_buffer[m_tx_buffer_index_end] + GMA_HEADER_OFFSET - VIRTUAL_DL_DATA);
	*(u_short*)header->flag = htons(0xF807);
	*(u_short*)header->client_id = htons(array_index + 2);//client index

	header->flow_id = flowId;
	header->ppp = pkt_pri;
	header->sn = htonl(flow_sn);

	//current time updated at the begining of ProcessPacket function.
	unsigned int last_tx_timestamp_wifi = (client_info_arrays[array_index].start_time == 0 ? 0 : (g_time_param_ms + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);
	header->time_stamp = htonl(last_tx_timestamp_wifi);

	

	m_tx_buffer_pkt_len[m_tx_buffer_index_end] = pkt_len;//store packet length
	m_tx_buffer_pkt_tos[m_tx_buffer_index_end] = tos;
	m_tx_buffer_client_index[m_tx_buffer_index_end] = array_index;// store client index.

	m_send_to_wifi_flag = true;// indicate this packet is scheduled for LTE

	NotifyWifiTransmitThreads();
}

void ClientManager::NotifyLteTransmitThreads()
{
	if (m_send_to_lte_flag)
	{
		m_tx_buffer_occupied_by_lte[m_tx_buffer_index_end] = true;
		m_lte_index_list[m_lte_index_end] = m_tx_buffer_index_end; //add current index to LTE virtual index queue
		m_lte_index_end = (m_lte_index_end + 1) % (MAX_TX_BUFFER_SIZE + 1); //move the lte virtual index queue end pointer to next slot
		m_send_to_lte_flag = false;
		if (m_lte_transmitting_flag == false)//lte not transmitting
		{
			m_lte_cond.notify_one();//notify lte to transmit
		}
	}
};

void ClientManager::NotifyWifiTransmitThreads()
{

	if (m_send_to_wifi_flag)
	{
		m_tx_buffer_occupied_by_wifi[m_tx_buffer_index_end] = true;
		m_wifi_index_list[m_wifi_index_end] = m_tx_buffer_index_end;//add current index to wifi virtual index queue
		m_wifi_index_end = (m_wifi_index_end + 1) % (MAX_TX_BUFFER_SIZE + 1);//move the wifi virtual index queue end pointer to next slot
		m_send_to_wifi_flag = false;
		if (m_wifi_transmitting_flag == false)//wifi not transmitting
		{
			m_wifi_cond.notify_one();//notify wifi to transmit
		}
	}
};

static void* LteTransmitThreadEntry(void* self) {
	return static_cast<ClientManager*>(self)->LteTransmitThread();
}

static void* WifiTransmitThreadEntry(void* self) {
	return static_cast<ClientManager*>(self)->WifiTransmitThread();
}


void send_ctl_mesage_to_client(int array_index, char * send_buf, int len)
{
	int vsock = -1;
	struct sockaddr_in receiver_addr;

	if (client_info_arrays[array_index].wifi_link_ok)
	{
		vsock = g_wifi_tunnel_sockfd;
		receiver_addr = client_info_arrays[array_index].client_wifi_addr;
	}
	else if (client_info_arrays[array_index].lte_link_ok)
	{
		vsock = g_lte_tunnel_sockfd;
		receiver_addr = client_info_arrays[array_index].client_lte_addr;
	}
	else
	{
		return;
	}
	
	int ret = 0;
	int t = 0;
	ret = sendto(vsock, send_buf, len, 0, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(vsock, send_buf, len, 0, (struct sockaddr*)&receiver_addr, sizeof(receiver_addr));
	}
	if (ret < 0) {
		printf("[err] send_ctl_mesage_to_client\n");
	}
}

void send_measurement_report_to_winapp(u_char type, int client_index, char* buf, int len)
{
	char send_buf[1500];
	int ret = 0;
	int t = 0;
	measure_report_to_winapp_header* measure_report_to_winapp = (measure_report_to_winapp_header*)send_buf;
	measure_report_to_winapp->type = type;
	measure_report_to_winapp->UE_index = htons((u_short)(client_index & 0x0000FFFF));

	memcpy(send_buf + sizeof(measure_report_to_winapp_header), buf, len);

	ret = sendto(g_measure_report_sockfd, send_buf, len + sizeof(struct measure_report_to_winapp_header), 0, (struct sockaddr*) & winapp_addr, sizeof(winapp_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(g_measure_report_sockfd, send_buf, len + sizeof(struct measure_report_to_winapp_header), 0, (struct sockaddr*) & winapp_addr, sizeof(winapp_addr));
	}
	if (ret < 0) {
		printf("[err] send_measurement_report_to_winapp\n");
	}
}

void send_measurement_report_to_winapp1(char* buf, int len)
{
	int ret = 0;
	int t = 0;
	if (g_send_measurement_to_winapp)
	{
		ret = sendto(g_measure_report_sockfd, buf, len, 0, (struct sockaddr*) & winapp_addr, sizeof(winapp_addr));
		while (ret == -1 && ++t < 3) {
			usleep(1);
			ret = sendto(g_measure_report_sockfd, buf, len, 0, (struct sockaddr*) & winapp_addr, sizeof(winapp_addr));
		}
		if (ret < 0) {
			printf("[err] send_measurement_report_to_winapp\n");
		}
	}
}


//random 4 bytes session id
int random_session_id()
{
	srand((unsigned)time(NULL));
	int session_id = rand();
	while (session_id == last_client_session_id) {
		session_id = rand();
	}
	last_client_session_id = session_id;
	return session_id;
}

void config_per_user_queue(int array_index)
{
	int clientId = array_index + 2;

	//configure qos queue
	//int wifiLinkBit = 0;

	int wifiRtFlowBit = 16384;
	int wifiNrtFlowBit = 24576;

	int lteLinkBit = 32768;
	int lteRtFlowBit = 49152;
	int lteNrtFlowBit = 57344;
	//int burstsize = 0 ;
	//Add : tc class add dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k
	//Change : tc class change dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k

	//set wifi parent class, it includes two queues, realtime queue and non-realtime queue
	std::stringstream ss;
	//burstsize = max((u_int)10, (u_int)(WIFI_RATE_MBPS * 10 / 8));
	//ss << "tc class add dev " << wlan_interface << " parent 1:0001 classid 1:" << hex << clientId << dec << " htb rate " << WIFI_RATE_MBPS << "mbit ceil " << WIFI_RATE_MBPS << "mbit";//per link per client
	ss << "tc class add dev " << wlan_interface << " parent 1:0001 classid 1:" << hex << clientId << dec << " htb rate " << WIFI_RATE_MBPS << "mbit ceil " << WIFI_RATE_MBPS << "mbit";//per link per client
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());


	//set lte parent class, it includes two queues, realtime queue and non-realtime queue
	ss.str(std::string());
	//burstsize = max((u_int)10, (u_int)(LTE_RATE_MBPS * 10 / 8));
	ss << "tc class add dev " << net_cfg.lte_interface << " parent 1:0001 classid 1:" << hex << (lteLinkBit + clientId) << dec << " htb rate " << LTE_RATE_MBPS << "mbit ceil " << LTE_RATE_MBPS << "mbit";//per link per client
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//set wifi realtime queue
	ss.str(std::string());
	//burstsize = max((u_int)10, (u_int)(WIFI_RATE_MBPS * 10 / 8));
	ss << "tc class add dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiRtFlowBit + clientId) << dec << " htb rate " << WIFI_RATE_MBPS - WIFI_NRT_RATE_MBPS << "mbit ceil " << WIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 2)
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//set wifi non-realtime queue
	ss.str(std::string());
	ss << "tc class add dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiNrtFlowBit + clientId) << dec << " htb rate " << (WIFI_NRT_RATE_MBPS) << "mbit ceil " << WIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 3)
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//set lte realtime queue
	ss.str(std::string());
	//burstsize = max((u_int)10, (u_int)(LTE_RATE_MBPS * 10 / 8));
	ss << "tc class add dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteRtFlowBit + clientId) << dec << " htb rate " << LTE_RATE_MBPS - LTE_NRT_RATE_MBPS << "mbit ceil " << LTE_RATE_MBPS << "mbit";//per client per flow/class (class id = 2)
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//set lte non-realtime queue;
	ss.str(std::string());
	ss << "tc class add dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteNrtFlowBit + clientId) << dec << " htb rate " << (LTE_NRT_RATE_MBPS) << "mbit ceil " << LTE_RATE_MBPS << "mbit";//per client per flow/class (class id = 3)
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	int wifiQueueLimit = max((u_int)10, WIFI_DELAY_MS); //use pfifo and the unit is pkt (not bytes)

	//set the queue size, WIFI_DELAY_MS controls the queue size
	ss.str(std::string());
	ss << "tc qdisc add dev " << wlan_interface << " parent 1:" << hex << (wifiRtFlowBit + clientId) << " handle " << (wifiRtFlowBit + clientId) << dec << ":0 pfifo limit " << wifiQueueLimit;
	popen_no_msg(ss.str().c_str(), ss.str().size());

	ss.str(std::string());
	ss << "tc qdisc add dev " << wlan_interface << " parent 1:" << hex << (wifiNrtFlowBit + clientId) << " handle " << (wifiNrtFlowBit + clientId) << dec << ":0 pfifo limit " << wifiQueueLimit;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	int lteQueueLimit = max((u_int)10, LTE_DELAY_MS);

	ss.str(std::string());
	ss << "tc qdisc add dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteRtFlowBit + clientId) << " handle " << (lteRtFlowBit + clientId) << dec << ":0 pfifo limit " << lteQueueLimit;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	ss.str(std::string());
	ss << "tc qdisc add dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteNrtFlowBit + clientId) << " handle " << (lteNrtFlowBit + clientId) << dec << ":0 pfifo limit " << lteQueueLimit;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	int startNum = 256; //0x100
	int msByte = (clientId >> 8) & 0x000000FF;
	int lsByte = clientId & 0x000000FF;

	//Flow Filtering: Flow ID (=2, wifi)
	ss.str(std::string());
	ss << "tc filter add dev " << wlan_interface << " parent 1: prio 5 handle ::1 protocol ip u32 ht " << hex << startNum + msByte << ":" << lsByte << " match \\" << "\n";
	ss << "ip sport 10021 0xffff match \\" << "\n";
	ss << "u8 0x02 0xff at 32 flowid 1:" << hex << (wifiRtFlowBit + clientId) << dec;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//Flow Filtering: Flow ID (=3, wifi)
	ss.str(std::string());
	ss << "tc filter add dev " << wlan_interface << " parent 1: prio 5 handle ::2 protocol ip u32 ht " << hex << startNum + msByte << ":" << lsByte << " match \\" << "\n";
	ss << "ip sport 10021 0xffff match \\" << "\n";
	ss << "u8 0x03 0xff at 32 flowid 1:" << hex << (wifiNrtFlowBit + clientId) << dec;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//Flow Filtering: Flow ID (=2, lte)
	ss.str(std::string());
	ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 handle ::3 protocol ip u32 ht " << hex << startNum + msByte << ":" << lsByte << " match \\" << "\n";
	ss << "ip sport 10020 0xffff match \\" << "\n";
	ss << "u8 0x02 0xff at 32 flowid 1:" << hex << (lteRtFlowBit + clientId) << dec;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());

	//Flow Filtering: Flow ID (=3, lte)
	ss.str(std::string());
	ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 handle ::4 protocol ip u32 ht " << hex << startNum + msByte << ":" << lsByte << " match \\" << "\n";
	ss << "ip sport 10020 0xffff match \\" << "\n";
	ss << "u8 0x03 0xff at 32 flowid 1:" << hex << (lteNrtFlowBit + clientId) << dec;
	//printf("[QOS] %s\n", ss.str().c_str());
	popen_no_msg(ss.str().c_str(), ss.str().size());
}

void set_client_parameters(int array_index) 
{
	//timestamp updated at create_new_client function
	//reset client parameters
	if (client_info_arrays[array_index].last_recv_msg_time != 0)
	{
		if (client_info_arrays[array_index].keep_alive_wifi_socket >= 0)
			close(client_info_arrays[array_index].keep_alive_wifi_socket);
		if (client_info_arrays[array_index].keep_alive_lte_socket >= 0)
			close(client_info_arrays[array_index].keep_alive_lte_socket);
	}

	client_info_arrays[array_index].last_recv_msg_time = g_time_param_s; //recv ctl msg time
	client_info_arrays[array_index].last_recv_wifi_msg_time = g_time_param_s; //recv ctl msg time
	client_info_arrays[array_index].last_recv_lte_msg_time = g_time_param_s; //recv ctl msg time

	client_info_arrays[array_index].dl_sn = 0;
	client_info_arrays[array_index].dl_rt_sn = 0;
	client_info_arrays[array_index].dl_hr_sn = 0;
	client_info_arrays[array_index].g_sn = 0;
	client_info_arrays[array_index].dl_lsn_lte = 0;
	client_info_arrays[array_index].dl_lsn_wifi = 0;

	client_info_arrays[array_index].lte_link_ok = true;
	client_info_arrays[array_index].wifi_link_ok = false;
	client_info_arrays[array_index].client_suspend = false;
	client_info_arrays[array_index].lte_link_used = true;
	client_info_arrays[array_index].wifi_link_used = true;
	client_info_arrays[array_index].keep_alive_wifi_socket = -1;
	client_info_arrays[array_index].keep_alive_lte_socket = -1;
	client_info_arrays[array_index].last_wifi_keep_alive_sent_time = g_time_param_s;
	client_info_arrays[array_index].last_lte_keep_alive_sent_time = g_time_param_s;

	client_info_arrays[array_index].last_control_msg_sn = 0;

	client_info_arrays[array_index].tsu_traffic_split_threshold = 1;
	client_info_arrays[array_index].tsu_lte_split_size = 0;
	client_info_arrays[array_index].tsu_wifi_split_size = 1;
	client_info_arrays[array_index].tsu_split_count = 0;
	client_info_arrays[array_index].last_tsu_sn = 0;

	client_info_arrays[array_index].rt_traffic_over_lte = false;

	client_info_arrays[array_index].split_total = 0;
	client_info_arrays[array_index].split_lte = 0;
	client_info_arrays[array_index].split_on = 0;

	client_info_arrays[array_index].ul_packet_sn = 0;
	client_info_arrays[array_index].ul_packet_sn_last = 0;
	//timestamp updated at create_new_client function
	client_info_arrays[array_index].start_time = 0x80000000 - (g_time_param_ms & 0x7FFFFFFF);

	client_info_arrays[array_index].client_wifi_adapt_port = 0;
	client_info_arrays[array_index].client_lte_adapt_port = 0;
	client_info_arrays[array_index].client_probe_port = 0;

	client_info_arrays[array_index].tscmsg.flag = 0;
	client_info_arrays[array_index].tfcmsg.flag = 0;

	memset(client_info_arrays[array_index].client_wifi_adapt_ip, 0, sizeof(client_info_arrays[array_index].client_wifi_adapt_ip));
	memset(client_info_arrays[array_index].client_lte_adapt_ip, 0, sizeof(client_info_arrays[array_index].client_lte_adapt_ip));
	memset(&client_info_arrays[array_index].client_lte_addr, 0, sizeof(client_info_arrays[array_index].client_lte_addr));
	memset(&client_info_arrays[array_index].client_wifi_addr, 0, sizeof(client_info_arrays[array_index].client_wifi_addr));
	memset(&client_info_arrays[array_index].client_vnic_addr, 0, sizeof(client_info_arrays[array_index].client_vnic_addr));

	if (ENABLE_UL_ENCRYPT)
	{
		if (!RAND_bytes(client_info_arrays[array_index].aes_key, 32)) {
			/* OpenSSL reports a failure, act accordingly */
			printf("[error] generate key for array_index %d \n", array_index);
		}
	}
	else {
		strncpy((char*)client_info_arrays[array_index].aes_key, "0000000000000000000000000000000\0", 32);
	}

	if (client_info_arrays[array_index].qos_queue_configured == false && ENABLE_DL_QOS)
	{
		config_per_user_queue(array_index);
		client_info_arrays[array_index].qos_queue_configured = true;
	}


	if (client_info_arrays[array_index].m_shared_rx_index_list == NULL)
	{
		printf("NEW LTE CLIENT INDEX QUEUE\n");
		client_info_arrays[array_index].m_shared_rx_index_list = new u_short[CLIENT_RX_BUFFER_SIZE];
		client_info_arrays[array_index].m_rx_index_start = 0;
		client_info_arrays[array_index].m_rx_index_end = 0;

	}

	if (ENABLE_UL_REORDERING)
	{
		 while (client_info_arrays[array_index].m_rx_index_start != client_info_arrays[array_index].m_rx_index_end)
		 {
		 	printf("REMOVE PACKETS FROM LTE OUTPUT INDEX QUEUE\n");
			u_short b_index = client_info_arrays[array_index].m_shared_rx_index_list[client_info_arrays[array_index].m_rx_index_start];
			client_info_arrays[array_index].m_rx_index_start = (client_info_arrays[array_index].m_rx_index_start + 1) % CLIENT_RX_BUFFER_SIZE;
			m_rx_buffer_occupied[b_index] = false;
		};

	}

	if (ENABLE_MEASUREMENT)
	{
		client_info_arrays[array_index].rt_inorder_sn = 0;
		client_info_arrays[array_index].nrt_inorder_sn = 0;

		client_info_arrays[array_index].hr_wifi_inorder_sn = 0;
		client_info_arrays[array_index].hr_lte_inorder_sn = 0;

		client_info_arrays[array_index].hr_output_inorder_sn = 0;

		client_info_arrays[array_index].m_measure_info  = measure_params();
		client_info_arrays[array_index].m_measure_report  = measure_report();
	}
}

int create_new_client(int client_index)
{
	update_current_time_params();//this function will update the global variable g_current_time_s and g_current_time_ms

	int array_index = 0;
	if (client_index == 0) { //  search for new client index 
		int start_search_index = client_info_arrays_index; // array index
		//find the available slot
		while (g_time_param_s - client_info_arrays[client_info_arrays_index].last_recv_msg_time < max_keep_client_time * 60) {
			client_info_arrays_index = (client_info_arrays_index + 1) % max_client_num;
			if (start_search_index == client_info_arrays_index) {
				return -1;
			}
		}
		array_index = client_info_arrays_index;
		client_info_arrays_index = (client_info_arrays_index + 1) % max_client_num;
		client_info_arrays[array_index].session_id = random_session_id();//session id
		client_info_arrays[array_index].client_index = array_index + 2;//client index
	}
	else { //reuse client index just reset parameters 
		array_index = client_index - 2;
	}
	

	set_client_parameters(array_index);

	return array_index;
}

void ncm_cmd_input_exit()
{
	close(ncm_send_sockfd);
	pthread_cancel(talk_with_ncm_thread_id);
	pthread_join(talk_with_ncm_thread_id, NULL);
	pthread_cancel(read_command_line_input_thread_id);
	pthread_join(read_command_line_input_thread_id, NULL);
	
}

void server_exit()
{
	
	if (g_lte_tcp_socktfd >= 0)
		close(g_lte_tcp_socktfd);
	
	if (g_wifi_tcp_socktfd >= 0)
		close(g_wifi_tcp_socktfd);

	close(g_lte_tunnel_sockfd);
	close(g_wifi_tunnel_sockfd);
	close(g_vnic_ctl_sockfd);
	close(g_measure_report_sockfd);

	pthread_cancel(lte_wifi_tunnel_recv_thread_id);
	if (strcmp(wlan_interface, net_cfg.lte_interface) != 0)
	{
		pthread_cancel(lte_wifi_keep_alive_thread_id);
		pthread_cancel(lte_wifi_keep_alive_thread2_id);
	}
	else
	{
		pthread_cancel(lte_wifi_keep_alive_thread_id);
	}

	pthread_cancel(vnic_ctl_recv_thread_id);
	
	if (g_cManager != NULL) {
		g_cManager->m_lte_index_end = g_cManager->m_lte_index_start + 1;
		g_cManager->m_lte_cond.notify_one();//trigger lock and exit thread

		g_cManager->m_wifi_index_end = g_cManager->m_wifi_index_start + 1;
		g_cManager->m_wifi_cond.notify_one();
	}

	m_rx_buffer_output_end = m_rx_buffer_output_start + 1;
	m_output_cond.notify_one();
		pthread_cancel(m_measurement_thread_id);
	pthread_cancel(receive_winapp_control_message_thread_id);

	pthread_join(lte_wifi_tunnel_recv_thread_id, NULL);
	if (strcmp(wlan_interface, net_cfg.lte_interface) != 0)
	{
		pthread_join(lte_wifi_keep_alive_thread_id, NULL);
		pthread_join(lte_wifi_keep_alive_thread2_id, NULL);
	}
	else
	{
		pthread_join(lte_wifi_keep_alive_thread_id, NULL);
	}
	pthread_join(lte_wifi_keep_alive_thread_id, NULL);
	pthread_join(vnic_ctl_recv_thread_id, NULL);
	pthread_join(m_measurement_thread_id, NULL);
	pthread_join(receive_winapp_control_message_thread_id, NULL);

	if (client_info_arrays != NULL) {
		free(client_info_arrays);
		client_info_arrays = NULL;
	}

	for(int j = 0; j < MAX_RX_BUFFER_SIZE; j++)
	{
		delete[] m_rx_buffer[j];
	}
	delete[] m_rx_buffer;
	delete[] m_rx_buffer_occupied;
	delete[] m_rx_buffer_packet_len;
	delete[] m_rx_buffer_header_size;
	delete[] m_rx_buffer_packet_sn;
	delete[] m_rx_buffer_rx_timestamp;
	delete[] m_rx_buffer_output_list;
	delete[] m_lte_wakeup_msg;
	delete[] m_wifi_wakeup_msg;
	delete[] m_client_active_check;
	delete[] client_info_arrays;
	m_client_active_check = NULL;
	client_info_arrays = NULL;

	if (ENABLE_DL_QOS)
	{
		std::stringstream ss;
		ss << "tc qdisc delete dev " << wlan_interface << " root";
		popen_no_msg(ss.str().c_str(), ss.str().size());



		if (strcmp(wlan_interface, net_cfg.lte_interface) != 0)
		{
			//lte and wifi interfances are different, rest the lte interface as well.
			ss.str(std::string());
			ss << "tc qdisc delete dev " << net_cfg.lte_interface << " root";
			popen_no_msg(ss.str().c_str(), ss.str().size());

		}
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(g_ctx);

	if (g_cManager != NULL) {
		delete(g_cManager);
		g_cManager = NULL;
	}


}

int gcm_encrypt_for_ncm(unsigned char *plaintext,int plaintext_len,
            unsigned char *key,
            unsigned char *iv, int iv_len,
            unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;
    int len;
    const int cipher_len = plaintext_len;
    int ret;
    int i;
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL); // IV length is 12

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ret = len;

    EVP_EncryptFinal_ex(ctx, ciphertext, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);

	return ret;
}

int send_aeskey_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt *fmt;
	char ack_buf[100];

	ret = sendto(ncm_send_sockfd, g_ncm_aeskey, 32, 0, (struct sockaddr *)&ncm_addr, sizeof(ncm_addr));

	if (ret < 0)
		return 1;

	printf("[ok] send to ncm aeskey\n");
	return 0;
}


int send_tun_setup_ack_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];
	
	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0 ,100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = TUN_SETUP_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;
	
	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}
	
	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send tun setup ack\n");
	return 0;
}
int send_tfc_ack_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = TFC_MESSAGE_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send tfc ack\n");
	return 0;
}

int send_tfc_ack_to_winapp()
{
	int t = 0;
	int ret;
	struct measure_report_to_winapp_header* winapp_header;
	char ack_buf[100];

	memset(ack_buf, 0, 100);
	winapp_header = (struct measure_report_to_winapp_header*)(ack_buf);
	winapp_header->type = TFC_MESSAGE_ACK;
	winapp_header->UE_index = 0;

	ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	}
	if (ret < 0)
		return 1;

	printf("[ok] send tfc ack to winapp\n");
	return 0;
}

int send_tsc_ack_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = TSC_MESSAGE_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send tsc ack\n");
	return 0;
}

int send_tsc_ack_to_winapp()
{
	int t = 0;
	int ret;
	struct measure_report_to_winapp_header* winapp_header;
	char ack_buf[100];

	memset(ack_buf, 0, 100);
	winapp_header = (struct measure_report_to_winapp_header*)(ack_buf);
	winapp_header->type = TSC_MESSAGE_ACK;
	winapp_header->UE_index = 0;

	ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*) &winapp_addr, sizeof(winapp_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*) &winapp_addr, sizeof(winapp_addr));
	}
	if (ret < 0)
		return 1;
	printf("[ok] send tsc ack to winapp\n");
	return 0;

}

int send_txc_ack_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = TXC_MESSAGE_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send tsc ack\n");
	return 0;
}

int send_txc_ack_to_winapp()
{
	int t = 0;
	int ret;
	struct measure_report_to_winapp_header* winapp_header;
	char ack_buf[100];

	memset(ack_buf, 0, 100);
	winapp_header = (struct measure_report_to_winapp_header*)(ack_buf);
	winapp_header->type = TXC_MESSAGE_ACK;
	winapp_header->UE_index = 0;

	ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send tsc ack to winapp\n");
	return 0;
}

int send_winapp_restart_ack()
{
	int t = 0;
	int ret;
	struct measure_report_to_winapp_header* winapp_header;
	char ack_buf[100];

	memset(ack_buf, 0, 100);
	winapp_header = (struct measure_report_to_winapp_header*)(ack_buf);
	winapp_header->type = WINAPP_RESTART_ACK;
	winapp_header->UE_index = 0;

	ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(g_measure_report_sockfd, ack_buf, MEASURE_REPORT_HEADER, 0, (struct sockaddr*)&winapp_addr, sizeof(winapp_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send winapp restart ack to winapp, prepare to restart now...\n");
	return 0;
}

int send_restart_to_ncm()
{
	int t = 0;
	int ret, encrypt_res;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = RESTART_TO_NCM;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send restart init message to ncm\n");
	//Later server will receive restart req from ncm..
	return 0;
}

int send_ccu_ack_to_ncm()
{
	int t = 0;
	int ret, encrypt_res;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = CCU_MESSAGE_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send ccu ack\n");
	return 0;
}

int send_scu_ack_to_ncm()
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100], encrypt_buf[100];
	char tag[16];
	char iv[12];

	memset(ack_buf, 0, 100);
	memset(encrypt_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN;
	fmt->info.type = SCU_MESSAGE_ACK;
	fmt->info.seq_num = 0;
	fmt->info.client_index = 0;

	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}

	if(gcm_encrypt_for_ncm((unsigned char*)fmt, CTL_MSG_INFO_LEN, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN, tag, 16);
	memcpy(encrypt_buf + CTL_MSG_INFO_LEN + 16, iv, 12);
	ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, fmt->info.len + 28, 0, (struct sockaddr*) & ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;

	printf("[ok] send scu ack\n");
	return 0;
}

void * vnic_ctl_recv_thread(void *lpParam)
{
	int len = 0;
	short pkt_len;
	char recv_buf[1500];
	struct sockaddr_in remote_addr;
	socklen_t socklen = sizeof(remote_addr);
	printf("vnic ctl thread listening...\n");
	while (g_bServerRun) {
		memset(recv_buf, 0, sizeof(recv_buf));
		len = recvfrom(g_vnic_ctl_sockfd, recv_buf, sizeof(recv_buf), 0, 
				(struct sockaddr *)&remote_addr, &socklen);
		if (len == -1)
			continue;
		vnic_tun_send_ctl_ack(remote_addr, recv_buf, len);
	}
	return NULL;
}

int rollover_diff2(int x1, int x2)
{
	int diff = x1 - x2;
	if (diff > (FHDR_FSN_NUM_MASK >> 1))
		diff = diff - FHDR_FSN_NUM_MASK - 1;
	else if (diff < -(FHDR_FSN_NUM_MASK >> 1))
		diff = diff + FHDR_FSN_NUM_MASK + 1;

	return diff;
}


int rollover_diff(int x1, int x2)
{
	int diff = x1 - x2;
	if (diff > (FHDR_CSN_NUM_MASK >> 1))
		diff = diff - FHDR_CSN_NUM_MASK - 1;
	else if (diff < -(FHDR_CSN_NUM_MASK >> 1))
		diff = diff + FHDR_CSN_NUM_MASK + 1;

	return diff;
}

void ul_output_queue_measurement(u_short index, u_int array_index)
{
	//measurement for all links combined
	struct virtual_ul_data_header* header = (struct virtual_ul_data_header*)m_rx_buffer[index];
	int diff_sn;
						
	if (ntohs(*(u_short*)header->flag) == 0x7807) //uplink data
	{ //only measure data

		if (DUPLICATE_FLOW_ID == (int)header->flow_id)// only measure high reliabitliy(hr) flow
		{
			if (client_info_arrays[array_index].start_time != 0)
			{
				if (ntohl(header->time_stamp) != 0)
				{
					//timestamp updated at the begining of the tun_recv function.
					int last_owd = (client_info_arrays[array_index].start_time == 0 ? 0 : (g_time_param_ms + client_info_arrays[array_index].start_time) & 0x7FFFFFFF) - ntohl(header->time_stamp);
					client_info_arrays[array_index].m_measure_info.hr.all.total_owd += last_owd;
					client_info_arrays[array_index].m_measure_info.hr.all.packet_num += 1;
					if (client_info_arrays[array_index].m_measure_info.hr.all.max_owd < last_owd)
					{
						client_info_arrays[array_index].m_measure_info.hr.all.max_owd = last_owd;
					}
					if (client_info_arrays[array_index].m_measure_info.hr.all.min_owd > last_owd)
					{
						client_info_arrays[array_index].m_measure_info.hr.all.min_owd = last_owd;
					}
				}

				client_info_arrays[array_index].m_measure_info.hr.all.total_bytes += m_wr_len;
				u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
				diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].hr_output_inorder_sn);
				if (diff_sn  == 1)
				{
					client_info_arrays[array_index].m_measure_info.hr.all.packet_in_order++;
					client_info_arrays[array_index].hr_output_inorder_sn = last_sn;
				}
				else if ( diff_sn > 1)
				{
					client_info_arrays[array_index].m_measure_info.hr.all.packet_in_order++;
					client_info_arrays[array_index].m_measure_info.hr.all.packet_missing += (diff_sn - 1);
					client_info_arrays[array_index].hr_output_inorder_sn = last_sn;
				}
				else
				{
					client_info_arrays[array_index].m_measure_info.hr.all.packet_out_of_order++;
				}
			}
			else {
				printf("[err] UL measurement: no client\n");
			}
		}
	}
}

void deliver_last_packet(u_short headerSize, u_int array_index)// this function is called whenever the packet can be delivered right after read from TUN 
{

	if ((m_rx_buffer_output_end + 1) % MAX_RX_BUFFER_SIZE == m_rx_buffer_output_start)
	{
		printf("rx output buffer overflow, drop packet!!!!\n");
		if (ENABLE_MEASUREMENT)
		{
			m_server_measure.ul_ring_buffer_overflow++;
			client_info_arrays[array_index].m_measure_info.buffer_overflow++;
		}
		m_rx_buffer_occupied[m_rx_buffer_index_end] = false;
	}
	else
	{
		
		bool rx_buff_full = true;
		u_short next_slot = m_rx_buffer_index_end;

		for (u_short counter = 1; counter < MAX_RX_BUFFER_SIZE; counter++) // find the next available slot
		{
			next_slot = (m_rx_buffer_index_end + counter) % MAX_RX_BUFFER_SIZE;

			if (!m_rx_buffer_occupied[next_slot])//empty slot
			{
				rx_buff_full = false;
				break;
			}
		}


		if (rx_buff_full)
		{
			m_rx_buffer_occupied[m_rx_buffer_index_end] = false;
			if(ENABLE_MEASUREMENT)
			{
				m_server_measure.ul_ring_buffer_overflow++;
				client_info_arrays[array_index].m_measure_info.buffer_overflow++;
			}
		}
		else
		{
			if(ENABLE_MEASUREMENT)
			{
				ul_output_queue_measurement(m_rx_buffer_index_end, array_index);		
			}

			m_rx_buffer_packet_len[m_rx_buffer_index_end] = m_wr_len;
			m_rx_buffer_header_size[m_rx_buffer_index_end] = headerSize;

			//timestamp updated at the begining of the tun_recv function;
			m_rx_buffer_rx_timestamp[m_rx_buffer_index_end] = g_time_param_ms;
			m_rx_buffer_packet_sn[m_rx_buffer_index_end] = client_info_arrays[array_index].ul_packet_sn;

			m_rx_buffer_occupied[m_rx_buffer_index_end] = true;
			m_rx_buffer_output_list[m_rx_buffer_output_end] = m_rx_buffer_index_end;

			m_rx_buffer_index_end = next_slot;
			m_rx_buffer_output_end = (m_rx_buffer_output_end + 1) % MAX_RX_BUFFER_SIZE;
		}

	}

}

void add_to_rx_output_list(u_short index, u_int array_index) // this function is called when the packet is "moved" from client rx(reordering) queues to output list.
{
	if ((m_rx_buffer_output_end + 1) % MAX_RX_BUFFER_SIZE == m_rx_buffer_output_start)
	{
		printf("rx output buffer overflow, drop packet!!!!\n");
		if (ENABLE_MEASUREMENT)
		{
			m_server_measure.ul_ring_buffer_overflow++;
			client_info_arrays[array_index].m_measure_info.buffer_overflow++;
		}
		m_rx_buffer_occupied[index] = false;
	}
	else
	{
		if(ENABLE_MEASUREMENT)
		{
			ul_output_queue_measurement(index, array_index);		
		}
		m_rx_buffer_occupied[index] = true;
		m_rx_buffer_output_list[m_rx_buffer_output_end] = index;
		m_rx_buffer_output_end = (m_rx_buffer_output_end + 1) % MAX_RX_BUFFER_SIZE;
	}
}

bool output_list_packet_available()
{
	return m_rx_buffer_output_start != m_rx_buffer_output_end;
}

void* rx_buffer_ouput_thread(void* p)
{
	while (g_bServerRun)
	{
		m_output_running_flag = false;
		std::unique_lock<std::mutex> lck(m_output_mtx);
		m_output_cond.wait(lck, output_list_packet_available);//wait until output list has data
		m_output_running_flag = true;//the output thread is in running state.
		if(!g_bServerRun)
			break;
		while (m_rx_buffer_output_start != m_rx_buffer_output_end)//buffer not empty
			{
				u_short b_index = m_rx_buffer_output_list[m_rx_buffer_output_start];
				int t_w = tun_write(tun.tun_fd, m_rx_buffer[b_index] + m_rx_buffer_header_size[b_index], m_rx_buffer_packet_len[b_index]);
				m_rx_buffer_output_start = (m_rx_buffer_output_start + 1) % MAX_RX_BUFFER_SIZE;
				m_rx_buffer_occupied[b_index] = false;
			}
	
	}
	return NULL;
}

void release_in_order_packets(u_int array_index)
{
	if (client_info_arrays[array_index].m_rx_index_start != client_info_arrays[array_index].m_rx_index_end)
	{
		bool timeout = false;
		if ((client_info_arrays[array_index].m_rx_index_end + 1) % CLIENT_RX_BUFFER_SIZE == client_info_arrays[array_index].m_rx_index_start)//client index queue full --> release all packets
		{

			if (ENABLE_MEASUREMENT)
			{
				m_server_measure.ul_client_index_queue_overflow++;
				client_info_arrays[array_index].m_measure_info.client_index_queue_overflow++;
			}

			do {
				u_short b_index = client_info_arrays[array_index].m_shared_rx_index_list[client_info_arrays[array_index].m_rx_index_start];

				if (rollover_diff2(m_rx_buffer_packet_sn[b_index], client_info_arrays[array_index].ul_packet_sn) >= 1)
				{
					add_to_rx_output_list(b_index, array_index);
					client_info_arrays[array_index].ul_packet_sn = m_rx_buffer_packet_sn[b_index];
				}
				else
				{   //drop
					m_rx_buffer_occupied[b_index] = false;
				}
				client_info_arrays[array_index].m_rx_index_start = (client_info_arrays[array_index].m_rx_index_start + 1) % CLIENT_RX_BUFFER_SIZE;
				
			} while (client_info_arrays[array_index].m_rx_index_start != client_info_arrays[array_index].m_rx_index_end);
		}
		else
		{

			do {
				u_short b_index = client_info_arrays[array_index].m_shared_rx_index_list[client_info_arrays[array_index].m_rx_index_start];
				//printf("release--------------------------------------------lte first packet sn: %d, inorder: %d\n", m_rx_buffer_packet_sn[b_index], client_info_arrays[array_index].ul_packet_sn);
				if (rollover_diff2(m_rx_buffer_packet_sn[b_index], client_info_arrays[array_index].ul_packet_sn) == 1)
				{
					add_to_rx_output_list(b_index, array_index);
					client_info_arrays[array_index].m_rx_index_start = (client_info_arrays[array_index].m_rx_index_start + 1) % CLIENT_RX_BUFFER_SIZE;
					client_info_arrays[array_index].ul_packet_sn = m_rx_buffer_packet_sn[b_index];
				}
				else if (rollover_diff2(m_rx_buffer_packet_sn[b_index], client_info_arrays[array_index].ul_packet_sn) < 1)
				{
					//drop
					client_info_arrays[array_index].m_rx_index_start = (client_info_arrays[array_index].m_rx_index_start + 1) % CLIENT_RX_BUFFER_SIZE;
					m_rx_buffer_occupied[b_index] = false;
				}
				else if (g_time_param_ms > m_rx_buffer_rx_timestamp[b_index] + REORDERING_TIMEOUT
					|| g_time_param_ms < m_rx_buffer_rx_timestamp[b_index] )//timestamp updated at the beginning of tun_recv function.
				{
					timeout = true;
					add_to_rx_output_list(b_index, array_index);
					client_info_arrays[array_index].m_rx_index_start = (client_info_arrays[array_index].m_rx_index_start + 1) % CLIENT_RX_BUFFER_SIZE;
					client_info_arrays[array_index].ul_packet_sn = m_rx_buffer_packet_sn[b_index];
				}
				else
				{
					break;
				}
			} while (client_info_arrays[array_index].m_rx_index_start != client_info_arrays[array_index].m_rx_index_end);
		}
		if (timeout && ENABLE_MEASUREMENT)
		{
			client_info_arrays[array_index].m_measure_info.reordering_timeout++;
		}
	}

}

void push_last_packet_into_rx_queue(u_int array_index)
{
	
	bool rx_buff_full = true;
	u_short next_slot = m_rx_buffer_index_end;

	for (u_short counter = 1; counter < MAX_RX_BUFFER_SIZE; counter++) // find the next available slot
	{
		next_slot = (m_rx_buffer_index_end + counter) % MAX_RX_BUFFER_SIZE;

		if (!m_rx_buffer_occupied[next_slot])//empty slot
		{
			rx_buff_full = false;
			break;
		}
	}

	if (rx_buff_full)
	{
		//printf("ring buffer full--------------------------------------------lte first packet sn:%d\n", m_rx_buffer_packet_sn[b_index]);
		if (ENABLE_MEASUREMENT)
		{
			m_server_measure.ul_ring_buffer_overflow++;
			client_info_arrays[array_index].m_measure_info.buffer_overflow++;
		}
		m_rx_buffer_occupied[m_rx_buffer_index_end] = false;
	}
	else
	{
		//timestamp updated at the begining of tun_recv function.
		m_rx_buffer_rx_timestamp[m_rx_buffer_index_end] = g_time_param_ms;
		m_rx_buffer_packet_sn[m_rx_buffer_index_end] = client_info_arrays[array_index].ul_packet_sn_last;
		m_rx_buffer_packet_len[m_rx_buffer_index_end] = m_wr_len;
		m_rx_buffer_header_size[m_rx_buffer_index_end] = sizeof(virtual_ul_data_header);
		m_rx_buffer_occupied[m_rx_buffer_index_end] = true;
		
		client_info_arrays[array_index].m_shared_rx_index_list[client_info_arrays[array_index].m_rx_index_end] = m_rx_buffer_index_end;
		//////////////////////// per-link reordering start 
		int slotNext;
		int slotPre = client_info_arrays[array_index].m_rx_index_end;
		u_short b_index_pre;
		u_short b_index_next;
		while (slotPre != client_info_arrays[array_index].m_rx_index_start) {//at least 2 packets in the queue
			//we check if the last received packet is inorder or not
			slotNext = slotPre;
			slotPre = ((slotPre + CLIENT_RX_BUFFER_SIZE) - 1) % CLIENT_RX_BUFFER_SIZE;//find the previous slot
			b_index_pre = client_info_arrays[array_index].m_shared_rx_index_list[slotPre];
			b_index_next = client_info_arrays[array_index].m_shared_rx_index_list[slotNext];

			if (rollover_diff2(m_rx_buffer_packet_sn[b_index_pre], m_rx_buffer_packet_sn[b_index_next]) <= 0)
			{	//packet in order
				break;
			}
			else {
				client_info_arrays[array_index].m_shared_rx_index_list[slotPre] = b_index_next;
				client_info_arrays[array_index].m_shared_rx_index_list[slotNext] = b_index_pre;
			}
		}
		////////////////////////// per-link reordering end
		client_info_arrays[array_index].m_rx_index_end = (client_info_arrays[array_index].m_rx_index_end + 1) % CLIENT_RX_BUFFER_SIZE;
		m_rx_buffer_index_end = next_slot;
	}
}

char get_owd_range(int max, int min)
{
	if (max == INT_MIN || min == INT_MAX)
	{
		//no wifi owd;
		return (char)(-1);//let -1 stands for no measurement
	}
	else
	{
		int range = std::min(127, max - min);
		return (char)range;
	}
}

char get_owd_diff(int owd1, int owd2)
{
	int diff = owd1 - owd2;
	diff = std::max(-127, std::min(127, diff));
	return (char)diff;
}

char get_loss(int inorder, int missing, int outoforder)
{
	int num_of_packets = inorder + missing;
	int num_of_packets_loss = missing - outoforder;
	if (num_of_packets == 0 || num_of_packets_loss <= 0)
	{
		return (char)127;
	}
	else
	{
		return (char)round(abs(log10((double)(num_of_packets / num_of_packets_loss))));
	}
}

u_char get_ooo(int inorder, int missing, int outoforder)
{
	/*
	int num_of_packets = inorder + missing;
	if (outoforder == 0)
	{
		return (char)127;
	}
	else
	{
		return (char)round(abs(log10((double)(num_of_packets / outoforder))));
	}*/
	int ooo_per_sec = outoforder / MEASURE_INTERVAL_S; 
	if (ooo_per_sec > 127)
		ooo_per_sec = 127;
	return ((u_char)(ooo_per_sec));

}


void save_ul_measurement_report(int time_s, u_int array_index)
{
	//save nrt report
	u_int wifiRate, lteRate;
	int wifiOwd, lteOwd;
	wifiRate = client_info_arrays[array_index].m_measure_info.nrt.wifi.total_bytes / (MEASURE_INTERVAL_S * 1000);  //KBps
	lteRate = client_info_arrays[array_index].m_measure_info.nrt.lte.total_bytes / (MEASURE_INTERVAL_S * 1000);  //KBps
	client_info_arrays[array_index].m_measure_report.nrt.total_rate = std::min((u_int)65535, wifiRate + lteRate);
	if (lteRate == 0){
		client_info_arrays[array_index].m_measure_report.nrt.wifi_rate_per = 100;//100% over WIFI
	}
	else {
		client_info_arrays[array_index].m_measure_report.nrt.wifi_rate_per = 100*wifiRate/(wifiRate + lteRate);
	}

	if (client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_num == 0 || client_info_arrays[array_index].m_measure_info.nrt.lte.packet_num == 0)
	{
		//either lte or wifi do not have measurement
		client_info_arrays[array_index].m_measure_report.nrt.ave_owd_diff = 0;
	}
	else {
		wifiOwd = client_info_arrays[array_index].m_measure_info.nrt.wifi.total_owd / client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_num;
		lteOwd = client_info_arrays[array_index].m_measure_info.nrt.lte.total_owd / client_info_arrays[array_index].m_measure_info.nrt.lte.packet_num;
		client_info_arrays[array_index].m_measure_report.nrt.ave_owd_diff = get_owd_diff(wifiOwd, lteOwd);
	}

	client_info_arrays[array_index].m_measure_report.nrt.wifi.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.nrt.wifi.max_owd, 
		client_info_arrays[array_index].m_measure_info.nrt.wifi.min_owd);

	client_info_arrays[array_index].m_measure_report.nrt.lte.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.nrt.lte.max_owd, 
		client_info_arrays[array_index].m_measure_info.nrt.lte.min_owd);

	client_info_arrays[array_index].m_measure_report.nrt.wifi.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.nrt.lte.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.nrt.lte.packet_in_order, 
		client_info_arrays[array_index].m_measure_info.nrt.lte.packet_missing, client_info_arrays[array_index].m_measure_info.nrt.lte.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.nrt.wifi.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.nrt.lte.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.nrt.lte.packet_in_order,
		client_info_arrays[array_index].m_measure_info.nrt.lte.packet_missing, client_info_arrays[array_index].m_measure_info.nrt.lte.packet_out_of_order);


	//save rt report
	wifiRate = client_info_arrays[array_index].m_measure_info.rt.wifi.total_bytes / (MEASURE_INTERVAL_S * 1000);  //KBps
	lteRate = client_info_arrays[array_index].m_measure_info.rt.lte.total_bytes / (MEASURE_INTERVAL_S * 1000);  //KBps
	client_info_arrays[array_index].m_measure_report.rt.total_rate = std::min((u_int)65535, wifiRate + lteRate);
	if (lteRate == 0) {
		client_info_arrays[array_index].m_measure_report.rt.wifi_rate_per = 100;//100% over WIFI
	}
	else {
		client_info_arrays[array_index].m_measure_report.rt.wifi_rate_per = 100 * wifiRate / (wifiRate + lteRate);
	}

	if (client_info_arrays[array_index].m_measure_info.rt.wifi.packet_num == 0 || client_info_arrays[array_index].m_measure_info.rt.lte.packet_num == 0)
	{
		//either lte or wifi do not have measurement
		client_info_arrays[array_index].m_measure_report.rt.ave_owd_diff = 0;
	}
	else {
		wifiOwd = client_info_arrays[array_index].m_measure_info.rt.wifi.total_owd / client_info_arrays[array_index].m_measure_info.rt.wifi.packet_num;
		lteOwd = client_info_arrays[array_index].m_measure_info.rt.lte.total_owd / client_info_arrays[array_index].m_measure_info.rt.lte.packet_num;
		client_info_arrays[array_index].m_measure_report.rt.ave_owd_diff = get_owd_diff(wifiOwd, lteOwd);
	}

	client_info_arrays[array_index].m_measure_report.rt.wifi.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.rt.wifi.max_owd,
		client_info_arrays[array_index].m_measure_info.rt.wifi.min_owd);

	client_info_arrays[array_index].m_measure_report.rt.lte.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.rt.lte.max_owd,
		client_info_arrays[array_index].m_measure_info.rt.lte.min_owd);

	client_info_arrays[array_index].m_measure_report.rt.wifi.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.rt.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.rt.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.rt.wifi.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.rt.lte.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.rt.lte.packet_in_order,
		client_info_arrays[array_index].m_measure_info.rt.lte.packet_missing, client_info_arrays[array_index].m_measure_info.rt.lte.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.rt.wifi.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.rt.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.rt.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.rt.wifi.packet_out_of_order);
	client_info_arrays[array_index].m_measure_report.rt.lte.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.rt.lte.packet_in_order,
		client_info_arrays[array_index].m_measure_info.rt.lte.packet_missing, client_info_arrays[array_index].m_measure_info.rt.lte.packet_out_of_order);

	//save hr report
	u_int allRate = client_info_arrays[array_index].m_measure_info.hr.all.total_bytes / (MEASURE_INTERVAL_S * 1000);  //KBps
	client_info_arrays[array_index].m_measure_report.hr.total_rate = std::min((u_int)65535, allRate);

	if (client_info_arrays[array_index].m_measure_info.hr.wifi.packet_num == 0 || client_info_arrays[array_index].m_measure_info.hr.lte.packet_num == 0 || client_info_arrays[array_index].m_measure_info.hr.all.packet_num == 0)
	{
		//either lte or wifi do not have measurement
		client_info_arrays[array_index].m_measure_report.hr.ave_owd_diff = 0;
		client_info_arrays[array_index].m_measure_report.hr.all_ave_owd_diff = 0;
	}
	else {
		wifiOwd = client_info_arrays[array_index].m_measure_info.hr.wifi.total_owd / client_info_arrays[array_index].m_measure_info.hr.wifi.packet_num;
		lteOwd = client_info_arrays[array_index].m_measure_info.hr.lte.total_owd / client_info_arrays[array_index].m_measure_info.hr.lte.packet_num;
		client_info_arrays[array_index].m_measure_report.hr.ave_owd_diff = get_owd_diff(wifiOwd, lteOwd);
		client_info_arrays[array_index].m_measure_report.hr.all_ave_owd_diff = 
			get_owd_diff(client_info_arrays[array_index].m_measure_info.hr.all.total_owd / client_info_arrays[array_index].m_measure_info.hr.all.packet_num, lteOwd);
	}

	client_info_arrays[array_index].m_measure_report.hr.wifi.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.hr.wifi.max_owd,
		client_info_arrays[array_index].m_measure_info.hr.wifi.min_owd);

	client_info_arrays[array_index].m_measure_report.hr.lte.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.hr.lte.max_owd,
		client_info_arrays[array_index].m_measure_info.hr.lte.min_owd);

	client_info_arrays[array_index].m_measure_report.hr.all.owd_range = get_owd_range(client_info_arrays[array_index].m_measure_info.hr.all.max_owd,
		client_info_arrays[array_index].m_measure_info.hr.all.min_owd);

	client_info_arrays[array_index].m_measure_report.hr.wifi.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.hr.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.hr.wifi.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.hr.lte.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.hr.lte.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.lte.packet_missing, client_info_arrays[array_index].m_measure_info.hr.lte.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.hr.all.neg_log_loss = get_loss(client_info_arrays[array_index].m_measure_info.hr.all.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.all.packet_missing, client_info_arrays[array_index].m_measure_info.hr.all.packet_out_of_order);

	client_info_arrays[array_index].m_measure_report.hr.wifi.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.hr.wifi.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.wifi.packet_missing, client_info_arrays[array_index].m_measure_info.hr.wifi.packet_out_of_order);
	client_info_arrays[array_index].m_measure_report.hr.lte.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.hr.lte.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.lte.packet_missing, client_info_arrays[array_index].m_measure_info.hr.lte.packet_out_of_order);
	client_info_arrays[array_index].m_measure_report.hr.all.outorder_packet_per_s = get_ooo(client_info_arrays[array_index].m_measure_info.hr.all.packet_in_order,
		client_info_arrays[array_index].m_measure_info.hr.all.packet_missing, client_info_arrays[array_index].m_measure_info.hr.all.packet_out_of_order);

	//update timestamp, at least one link has measurement.
	client_info_arrays[array_index].m_measure_report.timestamp_s = time_s;
	client_info_arrays[array_index].m_measure_report.buffer_overflow = client_info_arrays[array_index].m_measure_info.buffer_overflow;
	client_info_arrays[array_index].m_measure_report.client_index_queue_overflow = client_info_arrays[array_index].m_measure_info.client_index_queue_overflow;
	client_info_arrays[array_index].m_measure_report.reordering_timeout = client_info_arrays[array_index].m_measure_info.reordering_timeout;

	if(ENABLE_MEASURE_REPORT)
	{
		printf("+--+---------- Client ID [%d]: timestamp [%d s], ring buffer overflow [%d], client index overflow [%d], reordering timeout [%d] ------------+\n",
			array_index+2,
			client_info_arrays[array_index].m_measure_report.timestamp_s,
			client_info_arrays[array_index].m_measure_report.buffer_overflow,
			client_info_arrays[array_index].m_measure_report.client_index_queue_overflow,
			client_info_arrays[array_index].m_measure_report.reordering_timeout);

		printf("|UL|NRT| rate [%d KBps], wifi per [%d], owd diff [%d ms], wifi/lte owd range [%d/%d ms], wifi/lte -log(PLR) [%d/%d], wifi/lte outorder per s[%d//%d] |\n",
			client_info_arrays[array_index].m_measure_report.nrt.total_rate,
			client_info_arrays[array_index].m_measure_report.nrt.wifi_rate_per,
			client_info_arrays[array_index].m_measure_report.nrt.ave_owd_diff,
			client_info_arrays[array_index].m_measure_report.nrt.wifi.owd_range,
			client_info_arrays[array_index].m_measure_report.nrt.lte.owd_range,
			client_info_arrays[array_index].m_measure_report.nrt.wifi.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.nrt.lte.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.nrt.wifi.outorder_packet_per_s,
			client_info_arrays[array_index].m_measure_report.nrt.lte.outorder_packet_per_s);

		printf("|UL|RT| rate [%d KBps], wifi per [%d], owd diff [%d ms], wifi/lte owd range [%d/%d ms], wifi/lte -log(PLR) [%d/%d], wifi/lte outorder per s[%d//%d] |\n",
			client_info_arrays[array_index].m_measure_report.rt.total_rate,
			client_info_arrays[array_index].m_measure_report.rt.wifi_rate_per,
			client_info_arrays[array_index].m_measure_report.rt.ave_owd_diff,
			client_info_arrays[array_index].m_measure_report.rt.wifi.owd_range,
			client_info_arrays[array_index].m_measure_report.rt.lte.owd_range,
			client_info_arrays[array_index].m_measure_report.rt.wifi.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.rt.lte.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.rt.wifi.outorder_packet_per_s,
			client_info_arrays[array_index].m_measure_report.rt.lte.outorder_packet_per_s);

		printf("|UL|HR| rate [%d KBps], owd diff [%d ms], wifi/lte/all owd range [%d/%d/%d ms], wifi/lte/all -log(PLR) [%d/%d/%d], wifi/lte/all outorder per s[%d/%d/%d] |\n",
			client_info_arrays[array_index].m_measure_report.hr.total_rate,
			client_info_arrays[array_index].m_measure_report.hr.ave_owd_diff,
			client_info_arrays[array_index].m_measure_report.hr.wifi.owd_range,
			client_info_arrays[array_index].m_measure_report.hr.lte.owd_range,
			client_info_arrays[array_index].m_measure_report.hr.all.owd_range,
			client_info_arrays[array_index].m_measure_report.hr.wifi.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.hr.lte.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.hr.all.neg_log_loss,
			client_info_arrays[array_index].m_measure_report.hr.wifi.outorder_packet_per_s,
			client_info_arrays[array_index].m_measure_report.hr.lte.outorder_packet_per_s,
			client_info_arrays[array_index].m_measure_report.hr.all.outorder_packet_per_s);

		printf("+--+--------------------------------------------------------------------------------------------------------------------------------------------+\n");
	}
}


void * measurement_thread (void * p)
{
	char srp_report[1000];
	memset(srp_report, 0, sizeof(srp_report));

	measure_report_to_winapp_header* measure_report_to_winapp_srp = (measure_report_to_winapp_header*)srp_report;
	measure_report_to_winapp_srp->type = SRP_REPORT;
	measure_report_to_winapp_srp->UE_index = (u_short)0;
	int srp_offset = sizeof(measure_report_to_winapp_header);


	while (g_bServerRun)
	{
		sleep(MEASURE_INTERVAL_S);
		update_current_time_params();
		int time_s = g_time_param_s;

		if(ENABLE_MEASUREMENT && m_client_active_list.size() > 0)
		{
			m_server_report.timestamp_s = time_s;

			m_server_report.client_num = m_client_active_list.size();

			m_server_report.dl_throughput = m_server_measure.dl_wifi_bytes/(MEASURE_INTERVAL_S*1000) + m_server_measure.dl_lte_bytes/(MEASURE_INTERVAL_S*1000);  //unit: kBps
			m_server_report.ul_throughput = m_server_measure.ul_wifi_bytes/(MEASURE_INTERVAL_S*1000) + m_server_measure.ul_lte_bytes/(MEASURE_INTERVAL_S*1000);
			m_server_report.total_throughput = m_server_report.dl_throughput + m_server_report.ul_throughput;

			if(m_server_measure.dl_lte_bytes == 0)
			{
				m_server_report.dl_wifi_ratio = 1.0; //if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.dl_wifi_ratio = (double) m_server_measure.dl_wifi_bytes/(m_server_measure.dl_lte_bytes+m_server_measure.dl_wifi_bytes);
			}

			if(m_server_measure.ul_lte_bytes == 0)
			{
				m_server_report.ul_wifi_ratio = 1.0;//if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.ul_wifi_ratio = (double) m_server_measure.ul_wifi_bytes/(m_server_measure.ul_lte_bytes+m_server_measure.ul_wifi_bytes);
			}

			if (m_server_measure.dl_lte_bytes == 0 && m_server_measure.ul_lte_bytes ==0)
			{
				m_server_report.total_wifi_ratio = 1.0;//if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.total_wifi_ratio = (double) (m_server_measure.dl_wifi_bytes + m_server_measure.ul_wifi_bytes)
															/(m_server_measure.dl_lte_bytes + m_server_measure.ul_lte_bytes + m_server_measure.dl_wifi_bytes + m_server_measure.ul_wifi_bytes);
			}

			m_server_report.dl_ring_buffer_overflow = m_server_measure.dl_ring_buffer_overflow;
			m_server_report.ul_ring_buffer_overflow = m_server_measure.ul_ring_buffer_overflow;
			m_server_report.ul_client_index_queue_overflow = m_server_measure.ul_client_index_queue_overflow;

			if(m_server_report.interval_index == 0)
			{
				m_server_report.client_num_max = m_server_report.client_num;
				m_server_report.dl_throughput_max = m_server_report.dl_throughput;
				m_server_report.ul_throughput_max = m_server_report.ul_throughput;
				m_server_report.total_throughput_max = m_server_report.total_throughput;

				m_server_report.dl_ring_buffer_overflow_max = m_server_report.dl_ring_buffer_overflow;
				m_server_report.ul_ring_buffer_overflow_max = m_server_report.ul_ring_buffer_overflow;
				m_server_report.ul_client_index_queue_overflow_max = m_server_report.ul_client_index_queue_overflow;

				m_server_report.dl_wifi_bytes_sum = m_server_measure.dl_wifi_bytes;
				m_server_report.dl_lte_bytes_sum = m_server_measure.dl_lte_bytes;
				m_server_report.ul_wifi_bytes_sum = m_server_measure.ul_wifi_bytes;
				m_server_report.ul_lte_bytes_sum = m_server_measure.ul_lte_bytes;
			}
			else
			{
				m_server_report.client_num_max = std::max(m_server_report.client_num_max, m_server_report.client_num);
				m_server_report.dl_throughput_max = std::max(m_server_report.dl_throughput_max, m_server_report.dl_throughput);
				m_server_report.ul_throughput_max = std::max(m_server_report.ul_throughput_max, m_server_report.ul_throughput);
				m_server_report.total_throughput_max = std::max(m_server_report.total_throughput_max, m_server_report.total_throughput);
				m_server_report.dl_ring_buffer_overflow_max = std::max(m_server_report.dl_ring_buffer_overflow_max, m_server_report.dl_ring_buffer_overflow);
				m_server_report.ul_ring_buffer_overflow_max = std::max(m_server_report.ul_ring_buffer_overflow_max, m_server_report.ul_ring_buffer_overflow);
				m_server_report.ul_client_index_queue_overflow_max = std::max(m_server_report.ul_client_index_queue_overflow_max, m_server_report.ul_client_index_queue_overflow);

				m_server_report.dl_wifi_bytes_sum += m_server_measure.dl_wifi_bytes;
				m_server_report.dl_lte_bytes_sum += m_server_measure.dl_lte_bytes;
				m_server_report.ul_wifi_bytes_sum += m_server_measure.ul_wifi_bytes;
				m_server_report.ul_lte_bytes_sum += m_server_measure.ul_lte_bytes;
			}

			if(m_server_report.dl_lte_bytes_sum == 0)
			{
				m_server_report.dl_wifi_ratio_mean = 1.0; //if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.dl_wifi_ratio_mean = (double) m_server_report.dl_wifi_bytes_sum/(m_server_report.dl_lte_bytes_sum + m_server_report.dl_wifi_bytes_sum);
			}

			if(m_server_report.ul_lte_bytes_sum == 0)
			{
				m_server_report.ul_wifi_ratio_mean = 1.0; //if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.ul_wifi_ratio_mean = (double) m_server_report.ul_wifi_bytes_sum/(m_server_report.ul_lte_bytes_sum + m_server_report.ul_wifi_bytes_sum);
			}

			if(m_server_report.dl_lte_bytes_sum  + m_server_report.ul_lte_bytes_sum == 0)
			{
				m_server_report.total_wifi_ratio_mean = 1.0; //if lte (or both link) does not have data, wifi ratio = 1
			}
			else
			{
				m_server_report.total_wifi_ratio_mean = (double) (m_server_report.dl_wifi_bytes_sum + m_server_report.ul_wifi_bytes_sum )
														/(m_server_report.dl_wifi_bytes_sum + m_server_report.ul_wifi_bytes_sum + m_server_report.dl_lte_bytes_sum + m_server_report.ul_lte_bytes_sum );
			}

			if(m_server_report.interval_index == SERVER_REPORT_CYCLE - 1)
			{
				//update the max and average for the entire cycle
				m_server_report.client_num_last_cycle_max = m_server_report.client_num_max;
				m_server_report.dl_throughput_last_cycle_max = m_server_report.dl_throughput_max;
				m_server_report.ul_throughput_last_cycle_max = m_server_report.ul_throughput_max;
				m_server_report.total_throughput_last_cycle_max = m_server_report.total_throughput_max;
				m_server_report.dl_wifi_ratio_last_cycle_mean = m_server_report.dl_wifi_ratio_mean;
				m_server_report.ul_wifi_ratio_last_cycle_mean = m_server_report.ul_wifi_ratio_mean;
				m_server_report.total_wifi_ratio_last_cycle_mean = m_server_report.total_wifi_ratio_mean;

				m_server_report.dl_ring_buffer_overflow_last_cycle_max = m_server_report.dl_ring_buffer_overflow_max;
				m_server_report.ul_ring_buffer_overflow_last_cycle_max = m_server_report.ul_ring_buffer_overflow_max;
				m_server_report.ul_client_index_queue_overflow_last_cyle_max = m_server_report.ul_client_index_queue_overflow_max;
			}

			if(m_server_report.total_throughput > 100)  //>100KBps
			{
				if(ENABLE_MEASURE_REPORT)
				{
					printf(">>>> Report [%d], time [%d s], client [%d, max:%d, last cycle max:%d] \n",
						m_server_report.interval_index,
						m_server_report.timestamp_s,
						m_server_report.client_num,
						m_server_report.client_num_max,
						m_server_report.client_num_last_cycle_max
						);

					printf("|DU| Throughput [%f, max: %f, last cycle max: %f kBps] |\n",
						(double)m_server_report.total_throughput,
						(double)m_server_report.total_throughput_max,
						(double)m_server_report.total_throughput_last_cycle_max
						);
					printf("|DU| Wifi ratio [%f, mean:%f, last cycle mean:%f]      |\n",
						(double)m_server_report.total_wifi_ratio,
						(double)m_server_report.total_wifi_ratio_mean,
						(double)m_server_report.total_wifi_ratio_last_cycle_mean
						);
					printf("|DL| Throughput [%f, max: %f, last cycle max: %f kBps] |\n",
						(double)m_server_report.dl_throughput,
						(double)m_server_report.dl_throughput_max,
						(double)m_server_report.dl_throughput_last_cycle_max
						);
					printf("|DL| Wifi ratio [%f, mean:%f, last cycle mean:%f]      |\n",
						(double)m_server_report.dl_wifi_ratio,
						(double)m_server_report.dl_wifi_ratio_mean,
						(double)m_server_report.dl_wifi_ratio_last_cycle_mean
						);
					printf("|DL| Ring buffer overflow [%d, max:%d, last cycle max:%d] |\n",
						m_server_report.dl_ring_buffer_overflow,
						m_server_report.dl_ring_buffer_overflow_max,
						m_server_report.dl_ring_buffer_overflow_last_cycle_max
						);

					printf("|UL| Throughput [%f, max: %f, last cycle max: %f kBps] |\n",
						(double)m_server_report.ul_throughput,
						(double)m_server_report.ul_throughput_max,
						(double)m_server_report.ul_throughput_last_cycle_max
						);
					printf("|UL| Wifi ratio [%f, mean:%f, last cycle mean:%f]      |\n",
						(double)m_server_report.ul_wifi_ratio,
						(double)m_server_report.ul_wifi_ratio_mean,
						(double)m_server_report.ul_wifi_ratio_last_cycle_mean
						);
					printf("|UL| Ring buffer overflow [%d, max:%d, last cycle max:%d] |\n",
						m_server_report.ul_ring_buffer_overflow,
						m_server_report.ul_ring_buffer_overflow_max,
						m_server_report.ul_ring_buffer_overflow_last_cycle_max
						);
					printf("|UL| Client queue overflow [%d, max:%d, last cycle max:%d] |\n", 
						m_server_report.ul_client_index_queue_overflow,
						m_server_report.ul_client_index_queue_overflow_max,
						m_server_report.ul_client_index_queue_overflow_last_cyle_max
						);
				}
				//start build srp 
				server_measurement* srp = (server_measurement*)(srp_report + srp_offset);

				srp->time_stamp = (u_short)(m_server_report.timestamp_s & 0x0000FFFF);

				srp->num_of_active_clients_last = m_server_report.client_num;
				srp->num_of_active_clients_current_max = m_server_report.client_num_max;
				srp->num_of_active_clients_last_max = m_server_report.client_num_last_cycle_max;

				srp->dl_throughput_last = (u_short)(m_server_report.dl_throughput / 1000);  //unit: MBps
				srp->dl_throughput_current_max = (u_short)(m_server_report.dl_throughput_max / 1000);
				srp->dl_throughput_last_max = (u_short)(m_server_report.dl_throughput_last_cycle_max / 1000);

				srp->ul_throughput_last = (u_short)(m_server_report.ul_throughput / 1000);
				srp->ul_throughput_current_max = (u_short)(m_server_report.ul_throughput_max / 1000);
				srp->ul_throughput_last_max = (u_short)(m_server_report.ul_throughput_last_cycle_max / 1000);

				srp->total_throughput_last = (u_short)(m_server_report.total_throughput/1000);
				srp->total_throughput_current_max = (u_short)(m_server_report.total_throughput_max/1000);
				srp->total_throughput_last_max = (u_short)(m_server_report.total_throughput_last_cycle_max/1000);

				srp->dl_wifi_ratio_last = (u_char)(m_server_report.dl_wifi_ratio * 100); //unit: %
				srp->dl_wifi_ratio_current_average = (u_char)(m_server_report.dl_wifi_ratio_mean *100);
				srp->dl_wifi_ratio_last_average = (u_char)(m_server_report.dl_wifi_ratio_last_cycle_mean * 100);

				srp->ul_wifi_ratio_last = (u_char)(m_server_report.ul_wifi_ratio * 100);
				srp->ul_wifi_ratio_current_average = (u_char)(m_server_report.ul_wifi_ratio_mean * 100);
				srp->ul_wifi_ratio_last_average = (u_char)(m_server_report.ul_wifi_ratio_last_cycle_mean * 100);

				srp->total_wifi_ratio_last = (u_char)(m_server_report.total_wifi_ratio * 100);
				srp->total_wifi_ratio_current_average = (u_char)(m_server_report.total_wifi_ratio_mean * 100);
				srp->total_wifi_ratio_last_average = (u_char)(m_server_report.total_wifi_ratio_last_cycle_mean * 100);

				srp->num_of_dl_tx_ringbufferoverflow_last = m_server_report.dl_ring_buffer_overflow;
				srp->num_of_dl_tx_ringbufferoverflow_current_max = m_server_report.dl_ring_buffer_overflow_max;
				srp->num_of_dl_tx_ringbufferoverflow_last_max = m_server_report.dl_ring_buffer_overflow_last_cycle_max;

				srp->num_of_ul_rx_ringbufferoverflow_last = m_server_report.ul_ring_buffer_overflow;
				srp->num_of_ul_rx_ringbufferoverflow_current_max = m_server_report.ul_ring_buffer_overflow_max;
				srp->num_of_ul_rx_ringbufferoverflow_last_max = m_server_report.ul_ring_buffer_overflow_last_cycle_max;

				srp->num_of_ul_ue_rx_ringbufferoverflow_last = m_server_report.ul_client_index_queue_overflow;
				srp->num_of_ul_ue_rx_ringbufferoverflow_current_max = m_server_report.ul_client_index_queue_overflow_max;
				srp->num_of_ul_ue_rx_ringbufferoverflow_last_max = m_server_report.ul_client_index_queue_overflow_last_cyle_max;

				srp_offset += sizeof(server_measurement);
				//if (srp_offset + sizeof(server_measurement) > sizeof(srp_report))
				{
					send_measurement_report_to_winapp1(srp_report, srp_offset);
					printf("send SRP message to win app, len = %d\n", srp_offset);
					memset(srp_report + sizeof(measure_report_to_winapp_header), 0, sizeof(srp_report) - sizeof(measure_report_to_winapp_header));
					srp_offset = sizeof(measure_report_to_winapp_header);
				}
				// end build srp
				m_server_measure = server_measure_params();
			}

			//start urp
			char urp_report[1000];
			memset(urp_report, 0, sizeof(urp_report));

			measure_report_to_winapp_header* measure_report_to_winapp_urp = (measure_report_to_winapp_header*)urp_report;
			measure_report_to_winapp_urp->type = URP_REPORT;
			measure_report_to_winapp_urp->UE_index = (u_short)0;
			int urp_offset = sizeof(measure_report_to_winapp_header);

			while (!m_client_active_list.empty())
			{
				if ((urp_offset + sizeof(struct ul_measurement) + 2 * sizeof(struct ul_measurement_ext_a) + sizeof(struct ul_measurement_ext_b)) > 1000)
				{
					//the msg maybe too big if we add another user's urp. therefore we will transmit this msg and build a new one
					send_measurement_report_to_winapp1(urp_report, urp_offset);
					printf("send URP message to win app, len = %d\n", urp_offset);
					memset(urp_report + sizeof(measure_report_to_winapp_header), 0, sizeof(urp_report) - sizeof(measure_report_to_winapp_header));
					urp_offset = sizeof(measure_report_to_winapp_header);
				}

				u_int array_index = m_client_active_list.front();
				m_client_active_list.pop();
				save_ul_measurement_report(time_s, array_index);
				u_short tot_rate = client_info_arrays[array_index].m_measure_report.nrt.total_rate
					+ client_info_arrays[array_index].m_measure_report.rt.total_rate
					+ client_info_arrays[array_index].m_measure_report.hr.total_rate;
				if (tot_rate > 0)
				{
					//start build urp message
					ul_measurement* urp = (ul_measurement*)(urp_report + urp_offset);

					urp->UE_index = htons((u_short)client_info_arrays[array_index].client_index);
					urp->time_stamp = htons((u_short)(time_s & 0x0000FFFF));
					urp->num_of_output_bufferoverflows = client_info_arrays[array_index].m_measure_report.buffer_overflow;
					urp->num_of_reordering_bufferoverflows = client_info_arrays[array_index].m_measure_report.client_index_queue_overflow;
					urp->reordering_timeout = client_info_arrays[array_index].m_measure_report.reordering_timeout;

					u_char rtBit = 0;//first bit
					u_char nrtBit = 0;//second bit
					u_char hrBit = 0;//third bit
					urp_offset += sizeof(struct ul_measurement);
					//build the first one if 
					if (client_info_arrays[array_index].m_measure_report.rt.total_rate > 0) {
						//rt traffic
						rtBit = 128;
						ul_measurement_ext_a* urp_rt = (ul_measurement_ext_a*)(urp_report + urp_offset);

						urp_rt->total_throughput = htons(client_info_arrays[array_index].m_measure_report.rt.total_rate);
						urp_rt->wifi_percent = client_info_arrays[array_index].m_measure_report.rt.wifi_rate_per;
						urp_rt->ave_owd_diff = client_info_arrays[array_index].m_measure_report.rt.ave_owd_diff;
						urp_rt->wifi_owd_range = client_info_arrays[array_index].m_measure_report.rt.wifi.owd_range;
						urp_rt->lte_owd_range = client_info_arrays[array_index].m_measure_report.rt.lte.owd_range;
						urp_rt->wifi_neg_log_loss = client_info_arrays[array_index].m_measure_report.rt.wifi.neg_log_loss;
						urp_rt->lte_neg_log_loss = client_info_arrays[array_index].m_measure_report.rt.lte.neg_log_loss;
						urp_rt->wifi_outoforder = client_info_arrays[array_index].m_measure_report.rt.wifi.outorder_packet_per_s;
						urp_rt->lte_outoforder = client_info_arrays[array_index].m_measure_report.rt.lte.outorder_packet_per_s;
						urp_offset += sizeof(struct ul_measurement_ext_a);
					}

					if (client_info_arrays[array_index].m_measure_report.nrt.total_rate > 0) {
						//nrt traffic
						nrtBit = 64;
						ul_measurement_ext_a* urp_nrt = (ul_measurement_ext_a*)(urp_report + urp_offset);

						urp_nrt->total_throughput = htons(client_info_arrays[array_index].m_measure_report.nrt.total_rate);
						urp_nrt->wifi_percent = client_info_arrays[array_index].m_measure_report.nrt.wifi_rate_per;
						urp_nrt->ave_owd_diff = client_info_arrays[array_index].m_measure_report.nrt.ave_owd_diff;
						urp_nrt->wifi_owd_range = client_info_arrays[array_index].m_measure_report.nrt.wifi.owd_range;
						urp_nrt->lte_owd_range = client_info_arrays[array_index].m_measure_report.nrt.lte.owd_range;
						urp_nrt->wifi_neg_log_loss = client_info_arrays[array_index].m_measure_report.nrt.wifi.neg_log_loss;
						urp_nrt->lte_neg_log_loss = client_info_arrays[array_index].m_measure_report.nrt.lte.neg_log_loss;
						urp_nrt->wifi_outoforder = client_info_arrays[array_index].m_measure_report.nrt.wifi.outorder_packet_per_s;
						urp_nrt->lte_outoforder = client_info_arrays[array_index].m_measure_report.nrt.lte.outorder_packet_per_s;
						urp_offset += sizeof(struct ul_measurement_ext_a);

					}

					if (client_info_arrays[array_index].m_measure_report.hr.total_rate > 0) {
						//hr traffic
						hrBit =32;
						ul_measurement_ext_b* urp_hr = (ul_measurement_ext_b*)(urp_report + urp_offset);

						urp_hr->total_throughput = htons(client_info_arrays[array_index].m_measure_report.hr.total_rate);
						urp_hr->ave_owd_diff = client_info_arrays[array_index].m_measure_report.hr.ave_owd_diff;
						urp_hr->all_ave_owd_diff = client_info_arrays[array_index].m_measure_report.hr.all_ave_owd_diff;

						urp_hr->wifi_owd_range = client_info_arrays[array_index].m_measure_report.hr.wifi.owd_range;
						urp_hr->lte_owd_range = client_info_arrays[array_index].m_measure_report.hr.lte.owd_range;
						urp_hr->all_owd_range = client_info_arrays[array_index].m_measure_report.hr.all.owd_range;

						urp_hr->wifi_neg_log_loss = client_info_arrays[array_index].m_measure_report.hr.wifi.neg_log_loss;
						urp_hr->lte_neg_log_loss = client_info_arrays[array_index].m_measure_report.hr.lte.neg_log_loss;
						urp_hr->all_neg_log_loss = client_info_arrays[array_index].m_measure_report.hr.all.neg_log_loss;

						urp_hr->wifi_outoforder = client_info_arrays[array_index].m_measure_report.hr.wifi.outorder_packet_per_s;
						urp_hr->lte_outoforder = client_info_arrays[array_index].m_measure_report.hr.lte.outorder_packet_per_s;
						urp_hr->all_outoforder = client_info_arrays[array_index].m_measure_report.hr.all.outorder_packet_per_s;
						urp_offset += sizeof(struct ul_measurement_ext_b);

					}
					urp->flag = nrtBit + rtBit + hrBit;
					
					//check reordering buffer and remove timeout packets;
					if (ENABLE_UL_REORDERING)
					{
						release_in_order_packets(array_index);
						if (output_list_packet_available() && !m_output_running_flag)//buffer not empty
						{
							m_output_cond.notify_one();
						}

					}
				}
				//reset parameters
				client_info_arrays[array_index].m_measure_info = measure_params();
			}

			if (urp_offset > sizeof(measure_report_to_winapp_header))
			{
				send_measurement_report_to_winapp1(urp_report, urp_offset);
				printf("send URP message to win app, len = %d\n", urp_offset);
				memset(urp_report + sizeof(measure_report_to_winapp_header), 0, sizeof(urp_report) - sizeof(measure_report_to_winapp_header));
				urp_offset = sizeof(measure_report_to_winapp_header);
			}
			//end
		}

		if(m_client_active_check == NULL)
		{
			printf ("[error] should not new the m_client_active_chenc here!!\n");
			m_client_active_check = new bool[max_client_num];
		}
		else
		{
			memset(m_client_active_check, 0, max_client_num);
		}

		m_server_report.interval_index = (m_server_report.interval_index + 1) % SERVER_REPORT_CYCLE;

	}
	return NULL;
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int gcm_decrypt_for_ncm(unsigned char* ciphertext, int ciphertext_len,
	unsigned char* tag,
	unsigned char* key,
	unsigned char* iv, int iv_len,
	unsigned char* plaintext)
{
	int len;
	int plaintext_len;
	int ret;
	EVP_CIPHER_CTX* ctx;
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();
	
	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	if (ret > 0) {
		plaintext_len += len;
		return plaintext_len;
	}
	else {
		return -1;
	}
}

int gcm_decrypt(unsigned char* ciphertext, int ciphertext_len,
	unsigned char* aad, int aad_len,
	unsigned char* tag,
	unsigned char* key,
	unsigned char* iv, int iv_len,
	unsigned char* plaintext)
{
	int len;
	int plaintext_len;
	int ret;

	/* Initialise key and IV */
	if (!EVP_DecryptInit_ex(g_ctx, NULL, NULL, key, iv))
		handleErrors();

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (!EVP_DecryptUpdate(g_ctx, NULL, &len, aad, aad_len))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (!EVP_DecryptUpdate(g_ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if (!EVP_CIPHER_CTX_ctrl(g_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(g_ctx, plaintext + len, &len);

	/* Clean up */
	//EVP_CIPHER_CTX_free(ctx);

	if (ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else {
		/* Verify failed */
		return -1;
	}
}

void* tunnel_recv(int socketId)
{
	update_current_time_params();//this function will update the global variable g_current_time_s and g_current_time_ms
	int diff_sn = 0;
	int len = 0;
	struct sockaddr_in remote_addr;
	socklen_t socklen = sizeof(remote_addr);

	if (socketId == LTE_SOCKET)
	{
		len = recvfrom(g_lte_tunnel_sockfd, m_rx_buffer[m_rx_buffer_index_end], MAX_PACKET_SIZE, 0, (struct sockaddr*) & remote_addr, &socklen);
	}
	else if (socketId == WIFI_SOCKET)
	{
		len = recvfrom(g_wifi_tunnel_sockfd, m_rx_buffer[m_rx_buffer_index_end], MAX_PACKET_SIZE, 0, (struct sockaddr*) & remote_addr, &socklen);
	}
	else
	{
		printf("[err] unknown receive socket, not LTE nor WIFI\n");
	}
	if (len < sizeof(struct iphdr))
		return NULL;

	struct virtual_ul_data_header* header = (struct virtual_ul_data_header*)m_rx_buffer[m_rx_buffer_index_end];
	m_wr_len = len;
	u_int client_index;
	u_int array_index = 0;

	
	if (ntohs(*(u_short*)header->flag) == 0x800F) { //TODO, only compare the encryption bit, but I see other msg?????
		//encrypted conrtol msgs (PROBE AND TSU)

		struct encrypted_message_header* enc_header = (struct encrypted_message_header*)m_rx_buffer[m_rx_buffer_index_end];
		client_index = ntohs(enc_header->client_id);

		if (client_index >= 2 && client_index < max_client_num + 2) {
			array_index = client_index - 2;
			if (client_info_arrays[array_index].last_recv_msg_time == 0)  //the client does not exist
				return NULL;
		}
		else {
			printf("[err] tunnel recv, no client line 3171, %d\n", client_index);
			return NULL;
		}


	
		bool update_address = false;

		int aad_len = 4;//gma header
		int tag_len = 16;
		int iv_len = 12;
		int msg_len = len - aad_len - tag_len - iv_len;

		//gma header ( aad, 4byte)/ msg / tag (16 bytes) / iv (12 bytes)/

		//enc_trailer = tag + iv
	
		struct encrypted_vnic_trailer* enc_trailer = (struct encrypted_vnic_trailer*)(m_rx_buffer[m_rx_buffer_index_end] + aad_len + msg_len);


		//decrypted msg overwrite the encrypted msg.
		int decryptedMsg_len = gcm_decrypt((u_char*)(m_rx_buffer[m_rx_buffer_index_end] + aad_len), msg_len,
			(u_char*)(m_rx_buffer[m_rx_buffer_index_end]), aad_len,
			enc_trailer->tag,
			client_info_arrays[array_index].aes_key,
			enc_trailer->iv, iv_len,
			(u_char*)(m_rx_buffer[m_rx_buffer_index_end] + aad_len));

		if (decryptedMsg_len >= 0) {
			
			struct vnic_ack* dec_probe = (struct vnic_ack*)(m_rx_buffer[m_rx_buffer_index_end] + aad_len + sizeof(struct iphdr) + sizeof(struct udphdr));//skip virtual IP + UDP hdr


			if (dec_probe->type == PROBE_VNIC || dec_probe->type == TSU_VNIC || dec_probe->type == ACK_VNIC) {
				
				//for probe and tsu, we need to check the sn number for security reasons...
				if (client_info_arrays[array_index].session_id == ntohl(dec_probe->key) && rollover_diff(ntohs(dec_probe->seq_num), client_info_arrays[array_index].last_control_msg_sn) > 0)
				{
					//printf("[PROBE or TSU], the sn of last msg (%d), sn of this  msg (%d)\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(probe_req->seq_num));
					client_info_arrays[array_index].last_control_msg_sn = ntohs(dec_probe->seq_num);
					update_address = true;
					m_wr_len = msg_len;
					deliver_last_packet(aad_len, array_index);
				}
				else
				{
					printf("[ERROR, drop control msg]  [PROBE OR TSU], the sn of last msg (%d), sn of this  msg (%d)\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(dec_probe->seq_num));
				}
			}
			else
			{
				//all other msgs. dont check sn
				printf("[ERROR, drop control msg becasue of unknown control msg(type:%d), only PROBE and TSU should be encrypted]", dec_probe->type);
			}

		}
		else {
			printf("Decryption failed\n");
		}


		if (update_address) {
			if (socketId == LTE_SOCKET)
			{
				//timestamp updated at the beginning of the tun_recv function
				*(int*)(client_info_arrays[array_index].client_lte_adapt_ip) = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_lte_adapt_port = ntohs(remote_addr.sin_port);
				client_info_arrays[array_index].client_lte_addr.sin_family = AF_INET;
				client_info_arrays[array_index].client_lte_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_lte_addr.sin_port = remote_addr.sin_port;
	
			}
			else//wifi
			{
				*(int*)(client_info_arrays[array_index].client_wifi_adapt_ip) = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_wifi_adapt_port = ntohs(remote_addr.sin_port);
				client_info_arrays[array_index].client_wifi_addr.sin_family = AF_INET;
				client_info_arrays[array_index].client_wifi_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_wifi_addr.sin_port = remote_addr.sin_port;
			}
		}

	}
	else if (ntohs(*(u_short*)header->flag) == 0) {

		struct iphdr* ip = (struct iphdr*)(m_rx_buffer[m_rx_buffer_index_end] + sizeof(struct virtual_message_header));
		client_index = (u_int)(ntohl(ip->saddr) & 0x0000FFFF);


		if (client_index >= 2 && client_index < max_client_num + 2) {
			array_index = client_index - 2;
			if (client_info_arrays[array_index].last_recv_msg_time == 0)  //the client does not exist
				return NULL;
		}
		else {
			//deliver_last_packet(sizeof(virtual_ul_data_header), array_index);
			printf("[err] tunnel recv, no client line 3278 %d\n", client_index);
			return NULL;
		}

		bool update_address = false;
		
		struct vnic_ack* dec_probe = (struct vnic_ack*)(m_rx_buffer[m_rx_buffer_index_end] + sizeof(struct virtual_message_header) + sizeof(struct iphdr) + sizeof(struct udphdr));//skip virtual IP + UDP hdr

		if (dec_probe->type == PROBE_VNIC || dec_probe->type == TSU_VNIC || dec_probe->type == ACK_VNIC) {
			//for probe and tsu, we need to check the sn number for security reasons...
			if (client_info_arrays[array_index].session_id == ntohl(dec_probe->key) && rollover_diff(ntohs(dec_probe->seq_num), client_info_arrays[array_index].last_control_msg_sn) > 0)
			{
				//printf("[PROBE or TSU], the sn of last msg (%d), sn of this  msg (%d)\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(probe_req->seq_num));
				client_info_arrays[array_index].last_control_msg_sn = ntohs(dec_probe->seq_num);
				update_address = true;

				m_wr_len -= sizeof(struct virtual_message_header);
				deliver_last_packet(sizeof(struct virtual_message_header), array_index);
			}
			else
			{
				printf("[ERROR, drop control msg]  [PROBE OR TSU], session id (%d), session id of this  msg (%d)\n", client_info_arrays[array_index].session_id, ntohl(dec_probe->key));
				printf("[ERROR, drop control msg]  [PROBE OR TSU], the sn of last msg (%d), sn of this  msg (%d)\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(dec_probe->seq_num));
			}
		}
		else
		{
			//all other msgs. dont check sn
			m_wr_len -= sizeof(struct virtual_message_header);
			deliver_last_packet(sizeof(struct virtual_message_header), array_index);
		}

		if (update_address) {
			if (socketId == LTE_SOCKET)
			{
				//timestamp updated at the beginning of the tun_recv function
				*(int*)(client_info_arrays[array_index].client_lte_adapt_ip) = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_lte_adapt_port = ntohs(remote_addr.sin_port);
				client_info_arrays[array_index].client_lte_addr.sin_family = AF_INET;
				client_info_arrays[array_index].client_lte_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_lte_addr.sin_port = remote_addr.sin_port;
		
			}
			else//wifi
			{
				*(int*)(client_info_arrays[array_index].client_wifi_adapt_ip) = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_wifi_adapt_port = ntohs(remote_addr.sin_port);
				client_info_arrays[array_index].client_wifi_addr.sin_family = AF_INET;
				client_info_arrays[array_index].client_wifi_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
				client_info_arrays[array_index].client_wifi_addr.sin_port = remote_addr.sin_port;
			}
		}

	}
	else if (ntohs(*(u_short*)header->flag) == 0x7807) {
		m_wr_len -= sizeof(struct virtual_ul_data_header);
		struct iphdr* ip = (struct iphdr*)(m_rx_buffer[m_rx_buffer_index_end] + sizeof(struct virtual_ul_data_header));
		client_index = (u_int)(ntohl(ip->saddr) & 0x0000FFFF); //10.8.x.y -> client_index = x*256 + y
		if (client_index >= 2 && client_index < max_client_num + 2) {
			array_index = client_index - 2;
			if (client_info_arrays[array_index].last_recv_msg_time == 0)  //the client does not exist
				return NULL;
			if (client_info_arrays[array_index].client_lte_adapt_port != ntohs(remote_addr.sin_port) &&	client_info_arrays[array_index].client_wifi_adapt_port != ntohs(remote_addr.sin_port))
				return NULL;
		}
		else {
			printf("[err] tunnel recv, no client, line 3351, %d\n", client_index);
			return NULL;
		}

		if (ENABLE_MEASUREMENT)
		{
			//if (REALTIME_FLOW_ID == (int)header->flow_id || DUPLICATE_FLOW_ID == (int)header->flow_id)//only the RT and duplicate mode
			{
				//wait until the time is synced.
				if (client_info_arrays[array_index].start_time != 0)
				{
					if(!m_client_active_check[array_index])//store this client index into active list
					{
						m_client_active_list.push(array_index);
						m_client_active_check[array_index] = true;
					}
					//timestamp updated at the begining of tun_recv function.
					int synced_time = (client_info_arrays[array_index].start_time == 0 ? 0 : (g_time_param_ms + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);


					switch ((int)header->flow_id)
					{
						case NON_REALTIME_FLOW_ID:
							if (socketId == LTE_SOCKET) {
								m_server_measure.ul_lte_bytes += m_wr_len;
								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.nrt.lte.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.nrt.lte.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.nrt.lte.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.nrt.lte.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.nrt.lte.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.nrt.lte.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.nrt.lte.total_bytes += m_wr_len;

								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].nrt_inorder_sn);
								if (diff_sn == 1)
								{
									client_info_arrays[array_index].m_measure_info.nrt.lte.packet_in_order++;
									client_info_arrays[array_index].nrt_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.nrt.lte.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.nrt.lte.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].nrt_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.nrt.lte.packet_out_of_order++;
								}

							}
							else if (socketId == WIFI_SOCKET) {
								m_server_measure.ul_wifi_bytes += m_wr_len;
								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.nrt.wifi.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.nrt.wifi.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.nrt.wifi.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.nrt.wifi.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.nrt.wifi.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.nrt.wifi.total_bytes += m_wr_len;

								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].nrt_inorder_sn);
								if ( diff_sn == 1)
								{
									client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_in_order++;
									client_info_arrays[array_index].nrt_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].nrt_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.nrt.wifi.packet_out_of_order++;
								}
							}
							else {
								printf("[err] unknown socket\n");
							}
							break;
						case REALTIME_FLOW_ID:
							if (socketId == LTE_SOCKET) {
								m_server_measure.ul_lte_bytes += m_wr_len;

								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.rt.lte.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.rt.lte.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.rt.lte.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.rt.lte.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.rt.lte.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.rt.lte.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.rt.lte.total_bytes += m_wr_len;
								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].rt_inorder_sn);
								if (diff_sn == 1)
								{
									client_info_arrays[array_index].m_measure_info.rt.lte.packet_in_order++;
									client_info_arrays[array_index].rt_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.rt.lte.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.rt.lte.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].rt_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.rt.lte.packet_out_of_order++;
								}
							}
							else if (socketId == WIFI_SOCKET) {
								m_server_measure.ul_wifi_bytes += m_wr_len;

								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.rt.wifi.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.rt.wifi.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.rt.wifi.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.rt.wifi.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.rt.wifi.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.rt.wifi.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.rt.wifi.total_bytes += m_wr_len;
								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].rt_inorder_sn);
								if (diff_sn== 1)
								{
									client_info_arrays[array_index].m_measure_info.rt.wifi.packet_in_order++;
									client_info_arrays[array_index].rt_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.rt.wifi.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.rt.wifi.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].rt_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.rt.wifi.packet_out_of_order++;
								}
							}
							else {
								printf("[err] unknown socket\n");
							}
							break;
						case DUPLICATE_FLOW_ID:
							if (socketId == LTE_SOCKET) {
								m_server_measure.ul_lte_bytes += m_wr_len;

								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.hr.lte.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.hr.lte.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.hr.lte.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.hr.lte.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.hr.lte.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.hr.lte.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.hr.lte.total_bytes += m_wr_len;
								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].hr_lte_inorder_sn);
								if (diff_sn == 1)
								{
									client_info_arrays[array_index].m_measure_info.hr.lte.packet_in_order++;
									client_info_arrays[array_index].hr_lte_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.hr.lte.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.hr.lte.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].hr_lte_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.hr.lte.packet_out_of_order++;
								}
							}
							else if (socketId == WIFI_SOCKET) {
								m_server_measure.ul_wifi_bytes += m_wr_len;

								if (ntohl(header->time_stamp) != 0)
								{
									int last_owd = synced_time - ntohl(header->time_stamp);
									client_info_arrays[array_index].m_measure_info.hr.wifi.total_owd += last_owd;
									client_info_arrays[array_index].m_measure_info.hr.wifi.packet_num += 1;
									if (client_info_arrays[array_index].m_measure_info.hr.wifi.max_owd < last_owd)
									{
										client_info_arrays[array_index].m_measure_info.hr.wifi.max_owd = last_owd;
									}
									if (client_info_arrays[array_index].m_measure_info.hr.wifi.min_owd > last_owd)
									{
										client_info_arrays[array_index].m_measure_info.hr.wifi.min_owd = last_owd;
									}
								}

								client_info_arrays[array_index].m_measure_info.hr.wifi.total_bytes += m_wr_len;
								u_int last_sn = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
								diff_sn = rollover_diff2(last_sn, client_info_arrays[array_index].hr_wifi_inorder_sn);
								if (diff_sn == 1)
								{
									client_info_arrays[array_index].m_measure_info.hr.wifi.packet_in_order++;
									client_info_arrays[array_index].hr_wifi_inorder_sn = last_sn;
								}
								else if (diff_sn > 1)
								{
									client_info_arrays[array_index].m_measure_info.hr.wifi.packet_in_order++;
									client_info_arrays[array_index].m_measure_info.hr.wifi.packet_missing += (diff_sn - 1);
									client_info_arrays[array_index].hr_wifi_inorder_sn = last_sn;
								}
								else
								{
									client_info_arrays[array_index].m_measure_info.hr.wifi.packet_out_of_order++;
								}
							}
							else {
								printf("[err] unknown socket\n");
							}
							break;
						default:
							printf("[err] flow type not defined\n");
					}

				}
			}
		}

		if ((int)header->flow_id == DUPLICATE_FLOW_ID && ENABLE_UL_REORDERING)
		{
			if (client_info_arrays[array_index].linkStatusBitmap == 3) //wifi_link_ok && lte_link_ok
			{
					//timestamp updated at the begining of the function tun_recv
					client_info_arrays[array_index].ul_packet_sn_last = (ntohl(header->sn)) & FHDR_FSN_NUM_MASK;//3 LSB are gsn
					diff_sn = rollover_diff2(client_info_arrays[array_index].ul_packet_sn_last, client_info_arrays[array_index].ul_packet_sn);
					if (diff_sn == 1)
					{
						client_info_arrays[array_index].ul_packet_sn = client_info_arrays[array_index].ul_packet_sn_last;
						deliver_last_packet(sizeof(virtual_ul_data_header), array_index);
					}
					else if (diff_sn > 1)
					{
						push_last_packet_into_rx_queue(array_index);
					}
					else
					{
						//printf("discard duplicated or out of order\n");
					}
			}
			else
			{  //no reodering if only one link is available 
				client_info_arrays[array_index].ul_packet_sn = (ntohl(header->sn))& FHDR_FSN_NUM_MASK;//3 LSB are gsn
				deliver_last_packet(sizeof(virtual_ul_data_header), array_index);
			}
			release_in_order_packets(array_index);

		}
		else //NRT or RT mode, no duplication, no reordering. Or UL reordering is not enabled
		{
			//printf("wifi flow id: %d, sn: %d \n", (int)header->flow_id, (ntohl(header->sn)) & 0x00FFFFFF);
			deliver_last_packet(sizeof(virtual_ul_data_header), array_index);
		}
	
	}

	client_info_arrays[array_index].last_recv_msg_time = g_time_param_s;

	if (socketId == LTE_SOCKET)
	{
		client_info_arrays[array_index].last_recv_lte_msg_time = g_time_param_s;
	}
	else if (socketId == WIFI_SOCKET)
	{
		client_info_arrays[array_index].last_recv_wifi_msg_time = g_time_param_s;
	}

	if (output_list_packet_available() && !m_output_running_flag)//buffer not empty
	{
		m_output_cond.notify_one();
	}
	return NULL;
}

void* lte_wifi_tunnel_recv_thread(void* lpParam)
{
	while (g_bServerRun) {

		// select lte/wifi to receive
		bool wifiRecv = false;
		bool lteRecv = false;

		if (g_lte_tunnel_sockfd == -1 || g_wifi_tunnel_sockfd == -1)
		{
			//wait until both sockets are setup;
			continue;
		}
		else//one or more sockets are setup, select one of them
		{
			fd_set socks;
			FD_ZERO(&socks);
			FD_SET(g_lte_tunnel_sockfd, &socks);
			FD_SET(g_wifi_tunnel_sockfd, &socks);

			// find out which sockets are read - NB: it might be both!
			int nsocks = max(g_lte_tunnel_sockfd, g_wifi_tunnel_sockfd) + 1;
			if (select(nsocks, &socks, (fd_set*)0, (fd_set*)0, 0) >= 0) {

				if (FD_ISSET(g_lte_tunnel_sockfd, &socks)) {
					//handle lte socket
					lteRecv = true;
				}

				if (FD_ISSET(g_wifi_tunnel_sockfd, &socks)) {
					// handle wifi socket
					wifiRecv = true;
				}
			}
		}

		if (lteRecv)
		{
			tunnel_recv(LTE_SOCKET);
		}

		if (wifiRecv)
		{
			tunnel_recv(WIFI_SOCKET);
		}
	}
	return NULL;
}

int create_master_tcp_socket(int N, int PORT, int flag)
{
	int opt = 1;
	int master_socket = 0;
	struct sockaddr_in address;

	//create a master socket  
	if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		//close(master_socket);
		perror("socket failed");
		return(-1);
	}

	//set master socket to allow multiple connections ,  
	//this is just a good habit, it will work without this  
	if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt,
		sizeof(opt)) < 0)
	{
		close(master_socket);
		perror("setsockopt");
		return(-1);
	}

	//type of socket created  
	address.sin_family = AF_INET;
	//address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	if (flag == 1)
	{
		address.sin_addr.s_addr = inet_addr(lte_interface_ip);
	}
	else
	{
		address.sin_addr.s_addr = inet_addr(wifi_interface_ip);
	}

	if (bind(master_socket, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
		close(master_socket);
		perror("bind failed");
		return(-1);
	}
	printf("Listener on port %d \n", PORT);

	//try to specify maximum of N pending connections for the master socket  
	if (listen(master_socket, N) < 0)
	{
		perror("listen");
		close(master_socket);
		return(-1);
	}

	int flags = 1;
	if (setsockopt(master_socket, SOL_SOCKET, SO_KEEPALIVE, (void*)&flags, sizeof(flags))) {
		perror("setsockopt()");
		close(master_socket);
		return(-1);
	}

	flags = 3;
	if (setsockopt(master_socket, SOL_TCP, TCP_KEEPCNT, (void*)&flags, sizeof(flags))) { perror("ERROR: setsocketopt(), SO_KEEPCNT"); close(master_socket);
	return(-1);};

	flags = 60;
	if (setsockopt(master_socket, SOL_TCP, TCP_KEEPINTVL, (void*)&flags, sizeof(flags))) { perror("ERROR: setsocketopt(), SO_KEEPINTVL"); close(master_socket);
	return(-1);};

	flags =1;
	
	if (setsockopt(master_socket, SOL_TCP, TCP_NODELAY, (void*)&flags, sizeof(flags))) { perror("ERROR: setsocketopt(), TCP_NODELAY"); close(master_socket);
		return(-1);
	};

	return(master_socket);
}


void* lte_wifi_keep_alive_thread(void* lpParam)
{
	char buffer[1024] = { 0 }; //max_pkt_size = 1024 B
	int N = 10;
	int PORT = server_tcp_port;
	int master_socket, client_socket;
	int activity;
	int flag = *(int*)lpParam;
	free(lpParam);

	struct timeval waitTimeout;
	waitTimeout.tv_sec = 10; //wait 10 seconds for the first wakeup message;
	waitTimeout.tv_usec = 0;

	struct sockaddr_in address;

	//type of socket created  
	address.sin_family = AF_INET;
	//address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	if (flag == 1)
	{
		address.sin_addr.s_addr = inet_addr(lte_interface_ip);
	}
	else
	{
		address.sin_addr.s_addr = inet_addr(wifi_interface_ip);
	}
	master_socket = create_master_tcp_socket(N, PORT, flag);
	while (master_socket < 0)
	{
		printf("creating TCP socket failed");
		usleep(1000 * 1000 * 60); //wait for 60seconds, and then restart
		master_socket = create_master_tcp_socket(N, PORT, flag);
	}
	if (flag == 1)
	{
		g_lte_tcp_socktfd = master_socket;
	}
	else
	{
		g_wifi_tcp_socktfd = master_socket;
	}
	
		//accept the incoming connection  
	int addrlen = sizeof(address);
	puts("Waiting for connections ...");
	while (1)
	{
		if ((client_socket = accept(master_socket, (struct sockaddr*)&address,
			(socklen_t*)&addrlen)) < 0)
		{
			perror("accept");
			//restart the master TCP socket 
			close(master_socket);
			master_socket = -1;
			while (master_socket < 0)
			{
				printf("creating TCP socket failed");
				usleep(1000 * 1000 * 60); //wait for 60seconds, and then restart
				master_socket = create_master_tcp_socket(N, PORT, flag);
			}
			continue;
		}

		//inform user of socket number - used in send and receive commands 
		printf("[Connection Accepted] Wait for the first wakeup message, socket fd is %d , ip is : %s , port : %d \n", client_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

		//set of socket descriptors  
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(client_socket, &readfds);

		// / length(2B)/ Virtual IP (4B) / Type (1B) / CID (1B) / Key (4B) / SN (2B) / Vender ID (2B) / Sub-type (1B) /
		//we will read 2 bytes for the length field first, then read the payload, the number of bytes in the payload is indicated in the length feild;
		//if we receive part of the msg, we will wait at most 2 seconds in case the remaining parts arrive.

		//step 1: read the length filed (2B)
		int lengthFieldBytes = 2;
		activity = 1;
		int bufferIndex = 0;
		while (activity > 0)
		{
			waitTimeout.tv_sec = 10; //wait 10 seconds for the first wakeup message;
			waitTimeout.tv_usec = 0;
			activity = select(client_socket + 1, &readfds, NULL, NULL, &waitTimeout);//listen to this socket for 2 seconds waiting for the first Wakeup message

			if ((activity < 0) && (errno != EINTR))
			{
				printf("select error, will close socket\n");
				break;
			}
			else if (activity == 0)
			{
				//no activity, timeout happens.
				printf("client timeout, will close socket\n");
				break;
			}
			else
			{
				int readSize = read(client_socket, &buffer[bufferIndex], lengthFieldBytes - bufferIndex);
				if (readSize <= 0)
				{
					printf("the received message size (%d) is smaller than expected, will close socket\n", readSize);
					break;
				}
				else if(bufferIndex + readSize < lengthFieldBytes)//only receive part of the 2B size field, continue receiving
				{
					printf("received a message, continue...\n");
					bufferIndex += readSize;
				}
				else
				{
					bufferIndex += readSize;
					//received the length field, break loop and process it
					printf("received the complete length field.\n");
					break;
				}
			}

		}

		//have activity for this client.
		if (bufferIndex < lengthFieldBytes)
		{
			close(client_socket);
			printf("[Close socket] the total received message size (%d) is smaller than expected (%d)\n", bufferIndex, lengthFieldBytes);

		}
		else
		{
			//length field is received.

			u_short payloadBytes = ntohs(*(u_short*)buffer);
			printf("[Receive length filed] payloadBytes = %d\n", payloadBytes);

			if (payloadBytes == 0 || payloadBytes > 1000)
			{
				printf("[Close socket] the payload equals zero or too big\n");
				close(client_socket);
			}
			else
			{
				//step 2: receives payload
				activity = 1;
				bufferIndex = 0;
				memset(buffer, 0, 1024);
				while (activity > 0)
				{
					activity = select(client_socket + 1, &readfds, NULL, NULL, &waitTimeout);//listen to this socket for 2 seconds wating for the payload first Wakeup message

					if ((activity < 0) && (errno != EINTR))
					{
						printf("select error, will close socket\n");
						break;
					}
					else if (activity == 0)
					{
						//no activity, timeout happens.
						printf("client timeout, will close socket\n");
						break;
					}
					else
					{
						int readSize = read(client_socket, &buffer[bufferIndex], payloadBytes - bufferIndex);
						if (readSize <= 0)
						{
							printf("the received message size (%d) is smaller than expected, will close socket\n", readSize);
							break;
						}
						else if (bufferIndex + readSize < payloadBytes)//only receive part of the payload field, continue receiving
						{
							printf("received a message, continue...\n");
							bufferIndex += readSize;
						}
						else
						{
							bufferIndex += readSize;
							//received complete payload, break loop and process it
							printf("received the complete message payload.\n");
							break;
						}
					}

				}

				//have activity for this client.
				if (bufferIndex < payloadBytes)
				{
					close(client_socket);
					printf("[Close socket] the total received message size (%d) is smaller than expected (%d)\n", bufferIndex, payloadBytes);
				}
				else
				{
					//parse the received control message and add client_socket to client_info
					struct encrypted_message_header* enc_header = (struct encrypted_message_header*)buffer;

					if (ntohs(*(u_short*)enc_header->flag) == 0x800F) { //TODO, only compare the encryption bit

						u_int client_index = ntohs(enc_header->client_id);
						u_int array_index = 0;
						if (client_index >= 2 && client_index < max_client_num + 2) {
							array_index = client_index - 2;
						}
						else {
							printf("[tcp rx err], no client. client ID: %d \n", client_index);
							close(client_socket);
							continue;
							//close(master_socket);
							//return NULL;
						}
						//printf("[DECRYPT] client id: %d \n", client_index);

						int add_len = 4;
						int tag_len = 16;
						int iv_len = 12;
						int msg_len = payloadBytes - add_len - tag_len - iv_len;


						struct encrypted_vnic* enc_msg = (struct encrypted_vnic*)(buffer);
						struct encrypted_vnic_trailer* enc_trailer = (struct encrypted_vnic_trailer*)(buffer + add_len + msg_len);

						int decryptedMsg_len = gcm_decrypt(enc_msg->msg, msg_len,
							enc_msg->aad, add_len,
							enc_trailer->tag,
							client_info_arrays[array_index].aes_key,
							enc_trailer->iv, iv_len,
							enc_msg->msg);

						if (decryptedMsg_len >= 0) {
							struct wake_up_req* wakeupMsg = (struct wake_up_req*)enc_msg->msg;

							printf("[Receives a control message (%d bytes)]: type = %u, cid = %u, key = %d, sn = %d, vender id = %d, sub-type= %u \n",
								payloadBytes, wakeupMsg->type, wakeupMsg->cid, ntohl(wakeupMsg->key), ntohs(wakeupMsg->sn), ntohs(wakeupMsg->venderId), wakeupMsg->subType);
							//printf("Receives a message: byte0 = %u, byte1 = %u, byte2 = %u, byte3 = %u, byte4 = %d, byte5 = %u \n", wakeupMsg->byte0, wakeupMsg->byte1, wakeupMsg->byte2, wakeupMsg->byte3, wakeupMsg->byte4, wakeupMsg->byte5);

							if (wakeupMsg->type == 255 && wakeupMsg->subType == 6)
							{

								//check if the sn number is bigger.
								if (rollover_diff(ntohs(wakeupMsg->sn), client_info_arrays[array_index].last_control_msg_sn) > 0)//msg sn bigger than ns in the client info, add socket.
								{
									printf("[Add socket]current client tcp msg sn: %u, the sn of received msg: %d\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(wakeupMsg->sn));
									client_info_arrays[array_index].last_control_msg_sn = ntohs(wakeupMsg->sn);
									//add this socket to the client_info array

									//set the socket to non-blocking 

									if (fcntl(client_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK) == -1) {
										printf("error calling fcntl to set the client socket to NONBlock");
										// handle the error.  By the way, I've never seen fcntl fail in this way
									}


									if (wakeupMsg->cid == WIFI_CID)//wifi
									{
										if (client_info_arrays[array_index].keep_alive_wifi_socket >= 0)//this client already connected before, remove the old socket and update with the new one
										{
											close(client_info_arrays[array_index].keep_alive_wifi_socket);
										}

										int flags = WIFI_TCP_KEEP_ALIVE_S;
										if (setsockopt(master_socket, SOL_TCP, TCP_KEEPIDLE, (void*)&flags, sizeof(flags))) {
											perror("ERROR: setsocketopt(), SO_KEEPIDLE");
										};

										client_info_arrays[array_index].keep_alive_wifi_socket = client_socket;
										printf("array_index %d, new wifi socket id: %d\n", array_index, client_info_arrays[array_index].keep_alive_wifi_socket);
									}
									else if (wakeupMsg->cid == LTE_CID) //lte
									{
										if (client_info_arrays[array_index].keep_alive_lte_socket >= 0)//this client already connected before, remove the old socket and update with the new one
										{
											close(client_info_arrays[array_index].keep_alive_lte_socket);
										}

										int flags = LTE_TCP_KEEP_ALIVE_S;
										if (setsockopt(master_socket, SOL_TCP, TCP_KEEPIDLE, (void*)&flags, sizeof(flags))) {
											perror("ERROR: setsocketopt(), SO_KEEPIDLE");
										};

										client_info_arrays[array_index].keep_alive_lte_socket = client_socket;
										printf("array_index %d, new lte socket id: %d\n", array_index, client_info_arrays[array_index].keep_alive_lte_socket);
									}
									else
									{
										printf("[error] unkown CID (%u) in control message, only cid 0 or 3 is allowed\n", wakeupMsg->cid);
									}
								}
								else
								{
									//ignore this msg if its sn is smaller or equal to current sn in client info.
									printf("[close socket due to abnormal sn]current client tcp msg sn: %u, the sn of received msg: %d\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(wakeupMsg->sn));
									close(client_socket);
								}

							}
							else
							{
								close(client_socket);
								printf("[Close socket] unknown msg type and subtype\n");
							}

						}
						else {
							printf("Decryption failed\n");
						}

					}
					else if (ntohs(*(u_short*)enc_header->flag) == 0x8000) { //TODO, only compare the encryption bit

						//plan text msg
						u_int client_index = ntohs(enc_header->client_id);
						u_int array_index = 0;
						if (client_index >= 2 && client_index < max_client_num + 2) {
							array_index = client_index - 2;
						}
						else {
							printf("[tcp rx err], no client. client ID: %d \n", client_index);
							close(client_socket);
							continue;
							//close(master_socket);
							//return NULL;
						}

						struct wake_up_req* wakeupMsg = (struct wake_up_req*)(buffer + sizeof(struct encrypted_message_header));

						printf("[Receives a control message (%d bytes)]: type = %u, cid = %u, key = %d, sn = %d, vender id = %d, sub-type= %u \n",
							payloadBytes, wakeupMsg->type, wakeupMsg->cid, ntohl(wakeupMsg->key), ntohs(wakeupMsg->sn), ntohs(wakeupMsg->venderId), wakeupMsg->subType);
						//printf("Receives a message: byte0 = %u, byte1 = %u, byte2 = %u, byte3 = %u, byte4 = %d, byte5 = %u \n", wakeupMsg->byte0, wakeupMsg->byte1, wakeupMsg->byte2, wakeupMsg->byte3, wakeupMsg->byte4, wakeupMsg->byte5);

						if (wakeupMsg->type == 255 && wakeupMsg->subType == 6)
						{

							//check if the sn number is bigger.
							if (rollover_diff(ntohs(wakeupMsg->sn), client_info_arrays[array_index].last_control_msg_sn) > 0)//msg sn bigger than ns in the client info, add socket.
							{
								printf("[Add socket]current client tcp msg sn: %u, the sn of received msg: %d\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(wakeupMsg->sn));
								client_info_arrays[array_index].last_control_msg_sn = ntohs(wakeupMsg->sn);
								//add this socket to the client_info array

								//set the socket to non-blocking 

								if (fcntl(client_socket, F_SETFL, fcntl(client_socket, F_GETFL, 0) | O_NONBLOCK) == -1) {
									printf("error calling fcntl to set the client socket to NONBlock");
									// handle the error.  By the way, I've never seen fcntl fail in this way
								}


								if (wakeupMsg->cid == WIFI_CID)//wifi
								{
									if (client_info_arrays[array_index].keep_alive_wifi_socket >= 0)//this client already connected before, remove the old socket and update with the new one
									{
										close(client_info_arrays[array_index].keep_alive_wifi_socket);
									}

									int flags = WIFI_TCP_KEEP_ALIVE_S;
									if (setsockopt(master_socket, SOL_TCP, TCP_KEEPIDLE, (void*)&flags, sizeof(flags))) {
										perror("ERROR: setsocketopt(), SO_KEEPIDLE");
									};

									client_info_arrays[array_index].keep_alive_wifi_socket = client_socket;
									printf("array_index %d, new wifi socket id: %d\n", array_index, client_info_arrays[array_index].keep_alive_wifi_socket);
								}
								else if (wakeupMsg->cid == LTE_CID) //lte
								{
									if (client_info_arrays[array_index].keep_alive_lte_socket >= 0)//this client already connected before, remove the old socket and update with the new one
									{
										close(client_info_arrays[array_index].keep_alive_lte_socket);
									}

									int flags = LTE_TCP_KEEP_ALIVE_S;
									if (setsockopt(master_socket, SOL_TCP, TCP_KEEPIDLE, (void*)&flags, sizeof(flags))) {
										perror("ERROR: setsocketopt(), SO_KEEPIDLE");
									};

									client_info_arrays[array_index].keep_alive_lte_socket = client_socket;
									printf("array_index %d, new lte socket id: %d\n", array_index, client_info_arrays[array_index].keep_alive_lte_socket);
								}
								else
								{
									printf("[error] unkown CID (%u) in control message, only cid 0 or 3 is allowed\n", wakeupMsg->cid);
									close(client_socket);
								}
							}
							else
							{
								//ignore this msg if its sn is smaller or equal to current sn in client info.
								printf("[close socket due to abnormal sn]current client tcp msg sn: %u, the sn of received msg: %d\n", client_info_arrays[array_index].last_control_msg_sn, ntohs(wakeupMsg->sn));
								close(client_socket);
							}

						}
						else
						{
							close(client_socket);
							printf("[Close socket] unknown msg type and subtype\n");
						}

					}
					else {
						close(client_socket);
						printf("ERROR UKNOWN MSG TYPE\n");
					}

				}

			}

		}

	}
	close(master_socket);
}


void* receive_winapp_control_message_thread(void* lpParam)
{
	int len;
	char recv_buf[4096];
	struct winapp_ctl_msg* ctl_msg;
	struct sockaddr_in remote_addr;
	socklen_t socklen = sizeof(remote_addr);
	memset(&winapp_addr, 0, sizeof(winapp_addr));

	while (g_bServerRun) {
		memset(recv_buf, 0, sizeof(recv_buf));
		len = recvfrom(g_measure_report_sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*) & remote_addr, &socklen);

		if (len == -1)
			continue;

		winapp_addr.sin_family = AF_INET;
		winapp_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
		winapp_addr.sin_port = remote_addr.sin_port;

		ctl_msg = (winapp_ctl_msg*)recv_buf;
		if (ctl_msg->key == WIN_APP_KEY) {
			if (ctl_msg->flag == 0) {
				g_send_measurement_to_winapp = false;
				printf("[report to winapp] stop\n");
			}
			else if (ctl_msg->flag == 1) {
				g_send_measurement_to_winapp = true;
				printf("[report to winapp] start\n");
			}
			else if (ctl_msg->flag == 2) {
				printf("[winapp] Update config file\n");
				char* content = (char*)(recv_buf + sizeof(winapp_ctl_msg));
				FILE* cfg_fp = fopen("/home/ncm_ws/conf.ini", "w");
				if(cfg_fp == NULL)
				{
					printf("[winapp]can't find server config file\n");
				}
				else
				{
					int r = fputs(content, cfg_fp);
					if (r == EOF)
					{
						printf("[winapp]failed to update config file");
					}
					fclose(cfg_fp);
				}
			}
			else if (ctl_msg->flag == 3){
				printf("[winapp] restart server and ncm\n");
				send_winapp_restart_ack();
				send_restart_to_ncm();
			}
			else if(ctl_msg->flag == TSC_MESSAGE_REQ){
				//TSC request
				char send_buf[100];
				unsigned int client_index = *(unsigned int*)&recv_buf[8];
				printf("client_index = %d\n", client_index);
				if (client_index >= 2 && client_index < max_client_num + 2) 
				{
					int array_index = client_index - 2;
					update_current_time_params();
					if (g_time_param_s - client_info_arrays[array_index].last_recv_msg_time >= max_keep_client_time * 60)
					{
						printf("[receive_winapp_control_message_thread] client inactive\n");
						continue;
					}
					client_info_arrays[array_index].tscmsg.ul_duplication_enable = *(u_char*)&recv_buf[12];
					client_info_arrays[array_index].tscmsg.dl_dynamic_split_enable = *(u_char*)&recv_buf[13];
					client_info_arrays[array_index].tscmsg.flow_id = 1;
					client_info_arrays[array_index].tscmsg.K1 = *(u_char*)&recv_buf[14];
					client_info_arrays[array_index].tscmsg.K2 = *(u_char*)&recv_buf[15];
					client_info_arrays[array_index].tscmsg.L1 = *(u_char*)&recv_buf[16];
					client_info_arrays[array_index].tscmsg.flag = 1;

					struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
					*(u_short*)header->flag = 0;
					tsc_msg_header* tsc_req = (tsc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
					tsc_req->type = 0xFF;
					tsc_req->vendor_id = 0;
					tsc_req->sub_type = 4;
					tsc_req->len = sizeof(tsc_msg_header);
					tsc_req->ul_duplication_enable = *(u_char*)&recv_buf[12];
					tsc_req->dl_dynamic_split_enable = *(u_char*)&recv_buf[13];
					tsc_req->flow_id = 1;
					tsc_req->K1 = *(u_char*)&recv_buf[14];
					tsc_req->K2 = *(u_char*)&recv_buf[15];
					tsc_req->L1 = *(u_char*)&recv_buf[16];
					printf("[TSC] array_index = %d, ul_duplication_enable = %d, dl_dynamic_split_enable = %d, K1 = %d,  K2 = %d, L = %d\n",
						array_index, tsc_req->ul_duplication_enable, tsc_req->dl_dynamic_split_enable, tsc_req->K1, tsc_req->K2, tsc_req->L1);

					send_ctl_mesage_to_client(array_index, send_buf, sizeof(tsc_msg_header) + VIRTUAL_MESSAGE);
					send_tsc_ack_to_winapp();
			
				}
				else {
					printf("[winapp listening] wrong client index\n");
				}
			}
			else if(ctl_msg->flag == TFC_MESSAGE_REQ){
				//TFC request
				char send_buf[100];
				unsigned int client_index = *(unsigned int*)&recv_buf[8];
				printf("client_index = %d\n", client_index);
				if (client_index >= 2 && client_index < max_client_num + 2) 
				{
					int array_index = client_index - 2;
					update_current_time_params();
					if (g_time_param_s - client_info_arrays[array_index].last_recv_msg_time >= max_keep_client_time * 60)
					{
						printf("[receive_winapp_control_message_thread] client inactive\n");
						continue;
					}
					client_info_arrays[array_index].tfcmsg.flow_id = *(u_char*)&recv_buf[12];
					client_info_arrays[array_index].tfcmsg.proto_type = *(u_char*)&recv_buf[13];
					client_info_arrays[array_index].tfcmsg.port_start = *(u_short*)&recv_buf[14];
					client_info_arrays[array_index].tfcmsg.port_end = *(u_short*)&recv_buf[16];
					client_info_arrays[array_index].tfcmsg.flag = 1;

					tfc_msg_header* tfc_req = (tfc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
					tfc_req->type = 0xFF;
					tfc_req->vendor_id = 0;
					tfc_req->sub_type = 6;
					tfc_req->flow_id = *(u_char*)&recv_buf[12];
					tfc_req->proto_type = *(u_char*)&recv_buf[13];
					tfc_req->port_start = *(u_short*)&recv_buf[14];
					tfc_req->port_end = *(u_short*)&recv_buf[16];
					printf("[TFC] array_index = %d, flow_id = %d, proto_type = %d, port_start = %d,  port_end = %d\n",
						array_index, tfc_req->flow_id, tfc_req->proto_type, tfc_req->port_start, tfc_req->port_end);

					send_ctl_mesage_to_client(array_index, send_buf, sizeof(tfc_msg_header) + VIRTUAL_MESSAGE);
					send_tfc_ack_to_winapp();
				}
				else {
					printf("[winapp listening] wrong client index\n");
				}
			}
			else if(ctl_msg->flag == TXC_MESSAGE_REQ){
				//TXC request 
				char send_buf[100];
				unsigned int client_index = *(unsigned int*)&recv_buf[8];
				printf("client_index = %d\n", client_index);
				if (client_index >= 2 && client_index < max_client_num + 2) 
				{
					int array_index = client_index - 2;
					update_current_time_params();
					if (g_time_param_s - client_info_arrays[array_index].last_recv_msg_time >= max_keep_client_time * 60)
					{
						printf("[receive_winapp_control_message_thread] client inactive\n");
						continue;
					}
					u_char linkId = recv_buf[12];
					int clientId = array_index + 2;

					//int wifiLinkBit = 0;
					int wifiRtFlowBit = 16384;
					int wifiNrtFlowBit = 24576;

					int lteLinkBit = 32768;
					int lteRtFlowBit = 49152;
					int lteNrtFlowBit = 57344;


					//The queues are already been added when the client is created. We need to change the queue, not add.
					//Add : tc class add dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k
					//Change : tc class change dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k

					if (linkId == 0)//wifi
					{
						u_int mWIFI_RATE_MBPS = *(u_int*)&recv_buf[13];
						u_int mWIFI_NRT_RATE_MBPS = *(u_int*)&recv_buf[17];
						u_int mWIFI_DELAY_MS = *(u_int*)&recv_buf[21];
			
						printf("[TXC] array_index = %d, linkId = %d, WIFI_RATE_MBPS = %d, WIFI_NRT_RATE_MBPS = %d,  WIFI_DELAY_MS = %d\n",
							array_index, linkId, mWIFI_RATE_MBPS, mWIFI_NRT_RATE_MBPS, mWIFI_DELAY_MS);

						//set wifi parent class, it include realtime queue and non-realtime queue
						std::stringstream ss;
						//burstsize = max((u_int)10, (u_int)(WIFI_RATE_MBPS * 10 / 8));
						ss << "tc class change dev " << wlan_interface << " parent 1:0001 classid 1:" << hex << clientId << dec << " htb rate " << mWIFI_RATE_MBPS << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per link per client
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						//set wifi realtime queue
						ss.str(std::string());
						ss << "tc class change dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiRtFlowBit + clientId) << dec << " htb rate " << mWIFI_RATE_MBPS - mWIFI_NRT_RATE_MBPS << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 2)
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						//set wifi non-realtime queue
						ss.str(std::string());
						ss << "tc class change dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiNrtFlowBit + clientId) << dec << " htb rate " << (mWIFI_NRT_RATE_MBPS) << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 3)
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());


						int queueLimt = max((u_int)10, mWIFI_DELAY_MS);

						//set the queue size 
						ss.str(std::string());
						ss << "tc qdisc change dev " << wlan_interface << " parent 1:" << hex << (wifiRtFlowBit + clientId) << " handle " << (wifiRtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						ss.str(std::string());
						ss << "tc qdisc change dev " << wlan_interface << " parent 1:" << hex << (wifiNrtFlowBit + clientId) << " handle " << (wifiNrtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());
			
						send_txc_ack_to_winapp();
					}
					else if (linkId == 1)//lte
					{
						u_int mLTE_RATE_MBPS = *(u_int*)&recv_buf[13];
						u_int mLTE_NRT_RATE_MBPS = *(u_int*)&recv_buf[17];
						u_int mLTE_DELAY_MS = *(u_int*)&recv_buf[21];
						//burstsize = max((u_int)10, (u_int)(LTE_RATE_MBPS * 10 / 8));
						printf("[TXC] array_index = %d, linkId = %d, LTE_RATE_MBPS = %d, LTE_NRT_RATE_MBPS = %d,  LTE_DELAY_MS = %d\n",
							array_index, linkId, mLTE_RATE_MBPS, mLTE_NRT_RATE_MBPS, mLTE_DELAY_MS);
						//set lte parent class, it includes realtime and non-realtime queue
						std::stringstream ss;
						ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:0001 classid 1:" << hex << (lteLinkBit + clientId) << dec << " htb rate " << mLTE_RATE_MBPS << "mbit ceil " << mLTE_RATE_MBPS << "mbit";//per link per client
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						//set lte realtime queue
						ss.str(std::string());
						ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteRtFlowBit + clientId) << dec << " htb rate " << mLTE_RATE_MBPS - mLTE_NRT_RATE_MBPS << "mbit ceil " << mLTE_RATE_MBPS << "mbit" ;//per client per flow/class (class id = 2)
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						//set lte non-realtime queue;
						ss.str(std::string());
						ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteNrtFlowBit + clientId) << dec << " htb rate " << (mLTE_NRT_RATE_MBPS) << "mbit ceil " << mLTE_RATE_MBPS << "mbit" ;//per client per flow/class (class id = 3)
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						int queueLimt = max((u_int)10, mLTE_DELAY_MS);

						//set the queue size 
						ss.str(std::string());
						ss << "tc qdisc change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteRtFlowBit + clientId) << " handle " << (lteRtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
						printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						ss.str(std::string());
						ss << "tc qdisc change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteNrtFlowBit + clientId) << " handle " << (lteNrtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size()); 

						send_txc_ack_to_winapp();
					}
					else
					{
						printf("[TXC] unknown link ID = %d, available: 0 (wifi) or 1 (LTE)", linkId);
					}
				}
				else {
					printf("[winapp listening] wrong client index\n");
				}
			}
		}
	}

	return NULL;
}

bool ncm_sock_setup()
{
	int enable = 1;
	struct	sockaddr_in ncm_send_sockfd_addr;

	ncm_send_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if ((ncm_send_sockfd < 0)) {
		printf("[err] ncm socket create\n");
		return false; //goto ERR_NCM;
	}

	ncm_addr.sin_family = AF_INET;
	ncm_addr.sin_port = htons(ncm_addr_port);
	ncm_addr.sin_addr.s_addr = inet_addr(ncm_addr_ip);

	ncm_send_sockfd_addr.sin_family = AF_INET;
	ncm_send_sockfd_addr.sin_port = htons(local_addr_port);
	ncm_send_sockfd_addr.sin_addr.s_addr = inet_addr(local_addr_ip);

	if (setsockopt(ncm_send_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		printf("[err] ncm socket reuse\n");
		goto ERR_NCM;
	}


	if (bind(ncm_send_sockfd, (struct sockaddr *)&ncm_send_sockfd_addr, sizeof(ncm_send_sockfd_addr))) {
		
		printf("[err] ncm socket bind\n");
		goto ERR_NCM;
	}

	return true;

ERR_NCM:
	close(ncm_send_sockfd);
	return false;
}

bool normal_socket_setup(u_short port, u_char *ip, int *sockfd)
{
	struct sockaddr_in	addr;
	int sndbuf_size = 6000000;
	int size_len = sizeof(sndbuf_size);

	*sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (*sockfd < 0) {
		printf("[err] normal socket create\n");
		return false;
		//goto ERR;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(u_int *)(ip);

	if (bind(*sockfd, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("[err] normal socket bind \n");
		goto ERR;
	}

	if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, size_len) || 
	    setsockopt(*sockfd, SOL_SOCKET, SO_RCVBUF, &sndbuf_size, size_len)) {
		printf("[err] normal socket set sendbuf & recvbuf \n");
		goto ERR;
	}

	return true;

ERR:
	close(*sockfd);
	return false;
}


bool udp_socket_setup_nb(u_short port, int* sockfd)
{
	struct sockaddr_in	addr;
	int sndbuf_size = 6000000;  //buffer size in bytes
	int size_len = sizeof(sndbuf_size);

	*sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (*sockfd < 0) {
		printf("[err] normal socket create\n");
		return false; //goto ERR;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(measure_report_ip);

	if (bind(*sockfd, (struct sockaddr*)&addr, sizeof(addr))) {
		printf("[err] normal socket bind  = %d\n", port);
		goto ERR;
	}

	if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, size_len) ||
		setsockopt(*sockfd, SOL_SOCKET, SO_RCVBUF, &sndbuf_size, size_len)) {
		printf("[err] normal socket set sendbuf & recvbuf \n");
		goto ERR;
	}

	return true;

ERR:
	close(*sockfd);
	return false;
}

bool udp_socket_setup(u_short port, char* ip, int* sockfd)
{
	struct sockaddr_in	addr;
	int sndbuf_size = 6000000;  //buffer size in bytes
	int size_len = sizeof(sndbuf_size);

	*sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (*sockfd < 0) {
		printf("[err] normal socket create\n");
		return false; //goto ERR;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (bind(*sockfd, (struct sockaddr*) & addr, sizeof(addr))) {
		printf("[err] normal socket bind  = %d\n", port);
		goto ERR;
	}

	if (setsockopt(*sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, size_len) ||
		setsockopt(*sockfd, SOL_SOCKET, SO_RCVBUF, &sndbuf_size, size_len)) {
		printf("[err] normal socket set sendbuf & recvbuf \n");
		goto ERR;
	}

	return true;

ERR:
	close(*sockfd);
	return false;
}



void ProcessMsgReceivedFromWebSock(int array_index, char* buff, u_short len)
{
	struct	ctl_msg_fmt* fmt;

	fmt = (struct ctl_msg_fmt*)buff;

	if (fmt->info.type == CLIENT_SUSPEND_REQ) {
		int begin = *((u_char*)fmt + 2);
		if (begin == 1 && client_info_arrays[array_index].client_suspend == false) {
			client_info_arrays[array_index].client_suspend = true;
			client_info_arrays[array_index].lte_link_used = false;
			client_info_arrays[array_index].wifi_link_used = false;
			client_info_arrays[array_index].start_time = 0;
			printf("[ncm->server] begin suspend\n");
		}
	}

	else if (fmt->info.type == CLIENT_RESUME_REQ) {
		if (client_info_arrays[array_index].client_suspend) {
			client_info_arrays[array_index].client_suspend = false;
			client_info_arrays[array_index].lte_link_used = true;
			client_info_arrays[array_index].wifi_link_used = true;
		}
		//update_current_time_params();
		client_info_arrays[array_index].start_time = 0x80000000 - (g_time_param_ms & 0x7FFFFFFF);
		printf("[ncm->server] receive resume req, set start time to %d\n", client_info_arrays[array_index].start_time);
	}

	else if (fmt->info.type == CLOSE_CLIENT_REQ) {
		client_info_arrays[array_index].last_recv_msg_time = 0;
	}

	else if (fmt->info.type == USER_PLAN_SETUP_CNF) {
		client_info_arrays[array_index].client_probe_port = *(u_short*)&buff[10]; //8888
		client_info_arrays[array_index].client_wifi_adapt_port = *(u_short*)&buff[12]; //7777
		client_info_arrays[array_index].client_lte_adapt_port = *(u_short*)&buff[14]; //9999

		printf("[ok] client_probe_port: %d, client_wifi_adapt_port: %d, client_lte_adapt_port: %d\n",
			client_info_arrays[array_index].client_probe_port, client_info_arrays[array_index].client_wifi_adapt_port, client_info_arrays[array_index].client_lte_adapt_port);
	}
	else if (fmt->info.type == TFC_MESSAGE_REQ) {
		char send_buf[100];
		//set gma flag to 0, i.e., control msg
		struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
		*(u_short*)header->flag = 0;


		client_info_arrays[array_index].tfcmsg.flow_id = *(u_char*)&buff[10];
		client_info_arrays[array_index].tfcmsg.proto_type = *(u_char*)&buff[11];
		client_info_arrays[array_index].tfcmsg.port_start = htons(*(u_short*)&buff[12]);
		client_info_arrays[array_index].tfcmsg.port_end = htons(*(u_short*)&buff[14]);
		client_info_arrays[array_index].tfcmsg.flag = 1;

	    tfc_msg_header* tfc_req = (tfc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
		tfc_req->type = 0xFF;
		tfc_req->vendor_id = 0;
		tfc_req->sub_type = 6;
		tfc_req->flow_id = *(u_char*)&buff[10];
		tfc_req->proto_type = *(u_char*)&buff[11];
		tfc_req->port_start = htons(*(u_short*)&buff[12]);
		tfc_req->port_end = htons(*(u_short*)&buff[14]);
		printf("[TFC] array_index = %d, flow_id = %d, proto_type = %d, port_start = %d,  port_end = %d\n",
			array_index, tfc_req->flow_id, tfc_req->proto_type, ntohs(tfc_req->port_start), ntohs(tfc_req->port_end));

		send_ctl_mesage_to_client(array_index, send_buf, sizeof(tfc_msg_header) + VIRTUAL_MESSAGE);
		send_tfc_ack_to_ncm();
	
	}
	else if (fmt->info.type == TSC_MESSAGE_REQ) {
		char send_buf[100];

		//set gma flag to 0, i.e., control msg
		struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
		*(u_short*)header->flag = 0;

		client_info_arrays[array_index].tscmsg.ul_duplication_enable = *(u_char*)&buff[10];
		client_info_arrays[array_index].tscmsg.dl_dynamic_split_enable = *(u_char*)&buff[11];
		client_info_arrays[array_index].tscmsg.flow_id = 1;
		client_info_arrays[array_index].tscmsg.K1 = *(u_char*)&buff[12];
		client_info_arrays[array_index].tscmsg.K2 = *(u_char*)&buff[13];
		client_info_arrays[array_index].tscmsg.L1 = *(u_char*)&buff[14];
		client_info_arrays[array_index].tscmsg.flag = 1;

		tsc_msg_header* tsc_req = (tsc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
		tsc_req->type = 0xFF;
		tsc_req->vendor_id = 0;
		tsc_req->sub_type = 4;
		tsc_req->len = htons(sizeof(tsc_msg_header));
		tsc_req->ul_duplication_enable = *(u_char*)&buff[10];
		tsc_req->dl_dynamic_split_enable = *(u_char*)&buff[11];
		tsc_req->flow_id = 1;
		tsc_req->K1 = *(u_char*)&buff[12];
		tsc_req->K2 = *(u_char*)&buff[13];
		tsc_req->L1 = *(u_char*)&buff[14];
		printf("[TSC] array_index = %d, ul_duplication_enable = %d, dl_dynamic_split_enable = %d, K1 = %d,  K2 = %d, L = %d\n",
			array_index, tsc_req->ul_duplication_enable, tsc_req->dl_dynamic_split_enable, tsc_req->K1, tsc_req->K2, tsc_req->L1);

		send_ctl_mesage_to_client(array_index, send_buf, sizeof(tsc_msg_header) + VIRTUAL_MESSAGE);
		send_tsc_ack_to_ncm();
	}

	else if (fmt->info.type == TXC_MESSAGE_REQ && ENABLE_DL_QOS) {
		u_char linkId = buff[10];

		int clientId = array_index + 2;

		//int wifiLinkBit = 0;
		int wifiRtFlowBit = 16384;
		int wifiNrtFlowBit = 24576;

		int lteLinkBit = 32768;
		int lteRtFlowBit = 49152;
		int lteNrtFlowBit = 57344;


		//The queues are already been added when the client is created. We need to change the queue, not add.
		//Add : tc class add dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k
		//Change : tc class change dev em2 parent 1 :1 classid 1 : 7FFF htb rate $1mbit ceil $1mbit burst $2k

		if (linkId == 0)//wifi
		{
			u_int mWIFI_RATE_MBPS = *(u_int*)&buff[11];
			u_int mWIFI_NRT_RATE_MBPS = *(u_int*)&buff[15];
			u_int mWIFI_DELAY_MS = *(u_int*)&buff[19];
			
			printf("[TXC] array_index = %d, linkId = %d, WIFI_RATE_MBPS = %d, WIFI_NRT_RATE_MBPS = %d,  WIFI_DELAY_MS = %d\n",
				array_index, linkId, mWIFI_RATE_MBPS, mWIFI_NRT_RATE_MBPS, mWIFI_DELAY_MS);

			//set wifi parent class, it include realtime queue and non-realtime queue
			std::stringstream ss;
			//burstsize = max((u_int)10, (u_int)(WIFI_RATE_MBPS * 10 / 8));
			ss << "tc class change dev " << wlan_interface << " parent 1:0001 classid 1:" << hex << clientId << dec << " htb rate " << mWIFI_RATE_MBPS << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per link per client
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			//set wifi realtime queue
			ss.str(std::string());
			ss << "tc class change dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiRtFlowBit + clientId) << dec << " htb rate " << mWIFI_RATE_MBPS - mWIFI_NRT_RATE_MBPS << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 2)
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			//set wifi non-realtime queue
			ss.str(std::string());
			ss << "tc class change dev " << wlan_interface << " parent 1:" << hex << clientId << " classid 1:" << (wifiNrtFlowBit + clientId) << dec << " htb rate " << (mWIFI_NRT_RATE_MBPS) << "mbit ceil " << mWIFI_RATE_MBPS << "mbit";//per client per flow/class (class id = 3)
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			
			int queueLimt = max((u_int)10, mWIFI_DELAY_MS);

			//set the queue size 
			ss.str(std::string());
			ss << "tc qdisc change dev " << wlan_interface << " parent 1:" << hex << (wifiRtFlowBit + clientId) << " handle " << (wifiRtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			ss.str(std::string());
			ss << "tc qdisc change dev " << wlan_interface << " parent 1:" << hex << (wifiNrtFlowBit + clientId) << " handle " << (wifiNrtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());
			
			send_txc_ack_to_ncm();
		}
		else if (linkId == 1)//lte
		{
			u_int mLTE_RATE_MBPS = *(u_int*)&buff[11];
			u_int mLTE_NRT_RATE_MBPS = *(u_int*)&buff[15];
			u_int mLTE_DELAY_MS = *(u_int*)&buff[19];
			//burstsize = max((u_int)10, (u_int)(LTE_RATE_MBPS * 10 / 8));
			printf("[TXC] array_index = %d, linkId = %d, LTE_RATE_MBPS = %d, LTE_NRT_RATE_MBPS = %d,  LTE_DELAY_MS = %d\n",
				array_index, linkId, mLTE_RATE_MBPS, mLTE_NRT_RATE_MBPS, mLTE_DELAY_MS);
			//set lte parent class, it includes realtime and non-realtime queue
			std::stringstream ss;
			ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:0001 classid 1:" << hex << (lteLinkBit + clientId) << dec << " htb rate " << mLTE_RATE_MBPS << "mbit ceil " << mLTE_RATE_MBPS << "mbit";//per link per client
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			//set lte realtime queue
			ss.str(std::string());
			ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteRtFlowBit + clientId) << dec << " htb rate " << mLTE_RATE_MBPS - mLTE_NRT_RATE_MBPS << "mbit ceil " << mLTE_RATE_MBPS << "mbit" ;//per client per flow/class (class id = 2)
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			//set lte non-realtime queue;
			ss.str(std::string());
			ss << "tc class change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteLinkBit + clientId) << " classid 1:" << (lteNrtFlowBit + clientId) << dec << " htb rate " << (mLTE_NRT_RATE_MBPS) << "mbit ceil " << mLTE_RATE_MBPS << "mbit" ;//per client per flow/class (class id = 3)
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			int queueLimt = max((u_int)10, mLTE_DELAY_MS);
			
			//set the queue size 
			ss.str(std::string());
			ss << "tc qdisc change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteRtFlowBit + clientId) << " handle " << (lteRtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
			printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size());

			ss.str(std::string());
			ss << "tc qdisc change dev " << net_cfg.lte_interface << " parent 1:" << hex << (lteNrtFlowBit + clientId) << " handle " << (lteNrtFlowBit + clientId) << dec << ":0 pfifo limit " << queueLimt;
			//printf("[QOS] %s\n", ss.str().c_str());
			popen_no_msg(ss.str().c_str(), ss.str().size()); 

			send_txc_ack_to_ncm();
		}
		else
		{
			printf("[TXC] unknown link ID = %d, available: 0 (wifi) or 1 (LTE)", linkId);
		}

	}

	else if (fmt->info.type == CCU_MESSAGE_REQ) {
		int totalLength = (int)len - (int)sizeof(ctl_msg_info) - 4 + VIRTUAL_MESSAGE + (int)sizeof(ccu_msg_header);
		if (totalLength > 0 && totalLength < 1400 && len < 1400 && len > 0)
		{
			char send_buf[1400];		
			memset(send_buf, 0, 1400);
			//set gma flag to 0, i.e., control msg
			struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
			*(u_short*)header->flag = 0;

			ccu_msg_header* ccu_req = (ccu_msg_header*)(send_buf + VIRTUAL_MESSAGE);
			ccu_req->type = 0xFF;
			ccu_req->vendor_id = 0;
			ccu_req->sub_type = 5;
			ccu_req->len = totalLength;
			memcpy(send_buf + VIRTUAL_MESSAGE + sizeof(ccu_msg_header), buff + sizeof(ctl_msg_info) + 4, len - sizeof(ctl_msg_info) - 4);
			send_ctl_mesage_to_client(array_index, send_buf, totalLength);
			send_ccu_ack_to_ncm();
			printf("receive ccu message req\n");
		}
	}
}

int send_through_ws_link(char* buf, int len)
{
	int t = 0;
	int ret;
	char tag[16];
	char iv[12];
	char encrypt_buf[100];

	memset(encrypt_buf, 0, 100);

	//buf length should be 50 here
	memset(tag, 0, 16);
	memset(iv, 0 ,12);
	if (!RAND_bytes((unsigned char*)iv, 12)) {
		/* OpenSSL reports a failure, act accordingly */
		printf("[error] openssl to generate iv\n");
	}
	if(gcm_encrypt_for_ncm((unsigned char*)buf, len, (unsigned char*)g_ncm_aeskey,
				 (unsigned char*)iv, 12, (unsigned char*)encrypt_buf, (unsigned char*)tag) <= 0)
	{
		printf("error: encrypt message sent to udp\n");
		return 1;
	}
	memcpy(encrypt_buf + len, tag, 16);
	memcpy(encrypt_buf + len + 16, iv, 12);

	ret = sendto(ncm_send_sockfd, encrypt_buf, len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(ncm_send_sockfd, encrypt_buf, len + 28, 0, (struct sockaddr*)&ncm_addr, sizeof(ncm_addr));
	}

	if (ret < 0)
		return 1;
	printf("[ok] send_through_ws_link\n");
	return 0;

}

int send_create_client_ack_to_ncm(u_int req_sn, u_int client_index, u_int session_id, u_char* aesKey)
{
	int t = 0;
	int ret;
	struct ctl_msg_fmt* fmt;
	char ack_buf[100];

	memset(ack_buf, 0, 100);
	fmt = (struct ctl_msg_fmt*)(ack_buf);
	fmt->info.len = CTL_MSG_INFO_LEN + 44;
	fmt->info.type = CREATE_CLIENT_ACK;
	fmt->info.client_index = 0;
	fmt->info.seq_num = 0;
	memcpy(ack_buf + CTL_MSG_INFO_LEN, &req_sn, 4);
	memcpy(ack_buf + CTL_MSG_INFO_LEN + 4, &client_index, 4);
	memcpy(ack_buf + CTL_MSG_INFO_LEN + 8, &session_id, 4);
	memcpy(ack_buf + CTL_MSG_INFO_LEN + 12, aesKey, 32);
	ret = send_through_ws_link(ack_buf, fmt->info.len);
	if (ret)
		return 1;
	printf("[ok] send create client ACK to ncm\n");
	return 0;
}

void * talk_with_ncm_thread(void *lpParam)
{
	int len;
	char recv_buf[1400];
	struct ctl_msg_fmt *fmt;
	socklen_t socklen = sizeof(ncm_addr);

	int msg_len;
	int tag_len = 16;
	int iv_len = 12;
	char tag[tag_len];
	char iv[iv_len];
	int decryptedMsg_len;

	
	while (g_bQuit) {
		memset(recv_buf, 0, sizeof(recv_buf));

		memset(tag, 0 ,sizeof(tag));
		memset(iv, 0, sizeof(iv));
		len = recvfrom(ncm_send_sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&ncm_addr, &socklen);
		recv_buf[1399] = '\0';

		if (len == -1)
			continue;
		if (!encrypted_ncm)
		{
			fmt = (struct ctl_msg_fmt *)recv_buf;
			if (fmt->info.type == SERVER_AESKEY_REQ)
			{
				printf("\n receive aeskey req from NCM \n");
				char *pKey = recv_buf + sizeof(struct ctl_msg_info);
				memcpy(g_ncm_aeskey, pKey, sizeof(g_ncm_aeskey));
				if (send_aeskey_to_ncm())
				{
					printf("[Error] failed to send to ncm aes-key ack \n");
					continue;
				}
			}
			else
			{
				printf("[Error] Need aeskey req first for encryption \n");
				continue;
			}
			encrypted_ncm = true;
		}
		else
		{
			msg_len = len - iv_len - tag_len;
			if(msg_len > 0 && msg_len < 1400 && msg_len + tag_len > 0 && msg_len + tag_len < 1400)
			{
				decryptedMsg_len = gcm_decrypt_for_ncm((unsigned char*)recv_buf, msg_len, 
					(unsigned char*)(recv_buf + msg_len), (unsigned char*)g_ncm_aeskey, 
					(unsigned char*)(recv_buf + msg_len + tag_len), iv_len, (unsigned char*)recv_buf);
				if (decryptedMsg_len < 0)
				{
					printf("[Error] Decryption failed! \n");
					continue;
				}
			}
			else{
				printf("[Error] Wrong msg_len! \n");
				continue;
			}
		
		fmt = (struct ctl_msg_fmt *)recv_buf;
		if (fmt->info.type == SET_ANCHOR_MODE) {
			u_char anchor_mode = fmt->reserved[0];
			printf("[ok] anchor mode: %d\n", anchor_mode);
			if (anchor_mode != 2) {
				printf("[err] NOT VNIC anchor, plz check\n");
				continue;
			}
		//	g_websock_port = *(unsigned short *)&(fmt->reserved[1]);
		//	g_websock_ip   = *(unsigned int *)&(fmt->reserved[3]);
		//	printf("[ok] g_websock_port:%d, g_websock_ip:%x, \n",
		//		g_websock_port, g_websock_ip);
			
		}
		else if (fmt->info.type == SERVER_AESKEY_REQ)
			{
				printf("\n receive aeskey req from NCM \n");
				if (send_aeskey_to_ncm())
				{
					printf("[Error] failed to send to ncm aeskeys \n");
				}
			}

		else if (fmt->info.type == TUN_SETUP_REQUEST) {
			printf("\n receive NCM message length: %d \n", len);
			if (tun_set_up == true) {
				g_bServerRun = false;//exit all thread and then restart
				wait_command_cond.notify_one();
				while (g_cManager != NULL)
				{
					printf("[error] g_cMnager is not delted, wait another 1 s...;\n");
					usleep(1000000);//wait thread end
				}
				g_bServerRun = true;
			}
			recv_buf[1399] = '\0';
			if (load_receive_parameters(recv_buf + 6) != 1)
			{
				printf("[error] read parameters failed;\n");
				break;
			}

			if(g_cManager != NULL)
			{
				printf("[error] g_cManage is not NULL;\n");
				break;
			}

			g_cManager = new ClientManager();

			m_rx_buffer = new char* [MAX_RX_BUFFER_SIZE];
			for (int i = 0; i < MAX_RX_BUFFER_SIZE; i++)
			{
				m_rx_buffer[i] = new char[MAX_PACKET_SIZE];
			}

			m_rx_buffer_occupied = new bool[MAX_RX_BUFFER_SIZE];
			for (unsigned int ind = 0; ind < MAX_RX_BUFFER_SIZE; ind++)
			{
				m_rx_buffer_occupied[ind] = false;
			}
			m_rx_buffer_packet_len = new u_short[MAX_RX_BUFFER_SIZE];
			m_rx_buffer_header_size = new u_short[MAX_RX_BUFFER_SIZE];
			m_rx_buffer_packet_sn = new u_int[MAX_RX_BUFFER_SIZE];
			m_rx_buffer_rx_timestamp = new u_int[MAX_RX_BUFFER_SIZE]; // receive timestamp, ms.
			m_rx_buffer_output_list = new u_short[MAX_RX_BUFFER_SIZE];
			m_lte_wakeup_msg = new char[WAKEUP_MSG_LENGTH];
			m_wifi_wakeup_msg = new char[WAKEUP_MSG_LENGTH];


			memset(&fiveG_probe_ts, 0, sizeof(fiveG_probe_ts));
			fiveG_probe_ts.it_value.tv_sec = fiveG_D / 1000;
			fiveG_probe_ts.it_value.tv_nsec = (fiveG_D % 1000) * 1000000;

			memset(&LTE_stay_ts, 0, sizeof(LTE_stay_ts));
			LTE_stay_ts.it_value.tv_sec = lte_T / 1000;
			LTE_stay_ts.it_value.tv_nsec = (lte_T % 1000) * 1000000;

			if (tun_server_init()) {
				printf("[err] init tun\n");
			}
			if (strcmp(wifi_interface_ip, "0.0.0.0") == 0) {
				if (getNetworkAddr(wlan_interface, wifi_interface_ip, NULL)) {
					printf("[err] Get wifi ip \n");
				}
			}

			if (strcmp(lte_interface_ip, "0.0.0.0") == 0) {
				if (getNetworkAddr(net_cfg.lte_interface, lte_interface_ip, NULL)) {
					printf("[err] Get LTE ip \n");
				}
			}
			if (getNetworkAddr(measure_report_nic, measure_report_ip, NULL)){
				printf("[err] Get Measurement Report Nic ip\n");
			}

			printf("wifi ip address = %s, lte ip address = %s\n", wifi_interface_ip, lte_interface_ip);
			
			popen_no_msg("iptables -F", 12);
			popen_no_msg("sysctl -w net.ipv4.ip_forward=1", 32);
			popen_no_msg("rm -rf ./log/*", 15);

			

			//configure the QoS queues for wifi and lte
			
			if (ENABLE_DL_QOS)
			{
				std::stringstream ss;
				ss << "tc qdisc delete dev " << wlan_interface << " root";
				//printf("[QOS] %s\n", ss.str().c_str());
				popen_no_msg(ss.str().c_str(), ss.str().size());

				ss.str(std::string());
				//ss << "tc qdisc add dev " << wlan_interface << " root handle 1: htb default FFFF";
				ss << "tc qdisc add dev " << wlan_interface << " root handle 1: htb";
				//printf("[QOS] %s\n", ss.str().c_str());
				popen_no_msg(ss.str().c_str(), ss.str().size());

				//max number of clients is bounded by 2^(12) = 4K  (0x0FFF)
				//hashTableNum needs to be1, 2, 4, 8, 16, 32, 64, 128, or 256. Otherwise it is not efficient.

				int hashTableNum = 16; //4K users
				int startNum = 256; //0x0100; define the start number of the hash table.
				
				ss.str(std::string());
				ss << "tc filter add dev " << wlan_interface << " parent 1: prio 5 protocol ip handle A00: u32 divisor "<< hashTableNum;
				//printf("[QOS] %s\n", ss.str().c_str());
				popen_no_msg(ss.str().c_str(), ss.str().size());

				//a filter rules is stored in this structure.  hashTable : bucket : item
				//We will create 16 hashtable (use MSB of client ID to find), each hash table will have 256 buckets (use LSB client ID to find). 
				//that will support 16*256 users, each bucket will includes 4 items (num of filter rules for each user, wifi nrt, wifi rt, lte nrt, lte rt).

				//add filter, find the hashtable based on the MSB of the client ID
				ss.str(std::string());
				ss << "tc filter add dev " << wlan_interface << " parent 1: prio 5 protocol ip u32 match u16 0xF807 0xffff at 28 hashkey mask 0x00000f00 at 28 link A00:";
				//printf("[QOS] %s\n", ss.str().c_str());
				popen_no_msg(ss.str().c_str(), ss.str().size());

				for (int tableInd = 0; tableInd < hashTableNum; tableInd++)
				{
					//setup the 256 buckets in each hash table
					ss.str(std::string());
					ss << "tc filter add dev " << wlan_interface << " parent 1: prio 5 protocol ip handle " << hex << startNum + tableInd << dec << ": u32 divisor 256";
					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());

					//link to the bucket based on the LSB of the client ID
					ss.str(std::string());
					ss << "tc filter add dev "<< wlan_interface <<" parent 1: prio 5 protocol ip u32 ht A00:" << hex << tableInd << " match ip protocol 17 0xff hashkey mask 0x000000ff at 28 link " << startNum + tableInd <<dec << ":";
					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());
	
				}

				if (strcmp(wlan_interface, net_cfg.lte_interface) != 0)
				{
					//lte and wifi interfances are different, rest the lte interface as well.

					ss.str(std::string());
					ss << "tc qdisc delete dev " << net_cfg.lte_interface << " root";

					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());

					ss.str(std::string());
					//ss << "tc qdisc add dev " << net_cfg.lte_interface << " root handle 1: htb default FFFF";
					ss << "tc qdisc add dev " << net_cfg.lte_interface << " root handle 1: htb";
					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());

					
					ss.str(std::string());
					ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 protocol ip handle A00: u32 divisor " << hashTableNum;
					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());

					//a filter rules is stored in this structure.  hashTable : bucket : item
					//We will create 16 hashtable (use MSB of client ID to find), each hash table will have 256 buckets (use LSB client ID to find). 
					//that will support 16*256 users, each bucket will includes 4 items (num of filter rules for each user, wifi nrt, wifi rt, lte nrt, lte rt).

					//add filter, find the hashtable based on the MSB of the client ID
					ss.str(std::string());
					ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 protocol ip u32 match u16 0xF807 0xffff at 28 hashkey mask 0x00000f00 at 28 link A00:";
					//printf("[QOS] %s\n", ss.str().c_str());
					popen_no_msg(ss.str().c_str(), ss.str().size());

					for (int tableInd = 0; tableInd < hashTableNum; tableInd++)
					{
						//setup the 256 buckets in each hash table
						ss.str(std::string());
						ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 protocol ip handle " << hex << startNum + tableInd << dec << ": u32 divisor 256";
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

						//link to the bucket based on the LSB of the client ID
						ss.str(std::string());
						ss << "tc filter add dev " << net_cfg.lte_interface << " parent 1: prio 5 protocol ip u32 ht A00:" << hex << tableInd << " match ip protocol 17 0xff hashkey mask 0x000000ff at 28 link " << startNum + tableInd << dec << ":";
						//printf("[QOS] %s\n", ss.str().c_str());
						popen_no_msg(ss.str().c_str(), ss.str().size());

					}
				}
			}
			
			//this is for decryption
			/* Create and initialise the context */
			if (!(g_ctx = EVP_CIPHER_CTX_new()))
				handleErrors();

			/* Initialise the decryption operation. */
			if (!EVP_DecryptInit_ex(g_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
				handleErrors();
	

			if (pthread_create(&m_lte_transmit_thread_id, NULL, LteTransmitThreadEntry, g_cManager)) {//(THREADFUNCPTR) &ClientManager::LteTransmitThread, g_cManager)) {
				printf("[err] Create LteTransmitThread\n");
			}
			if (pthread_create(&m_wifi_transmit_thread_id, NULL, WifiTransmitThreadEntry, g_cManager)) {//(THREADFUNCPTR) &ClientManager::WifiTransmitThread, g_cManager)) {
				printf("[err] Create WifiTransmitThread\n");
			}

			if (pthread_create(&m_rx_buffer_ouput_thread_id, NULL, rx_buffer_ouput_thread, NULL)) {
				printf("[err] Create rx buffer output thread\n");
			}

			if (ENABLE_MEASUREMENT)
			{
				if (pthread_create(&m_measurement_thread_id, NULL, measurement_thread, NULL)) {
					printf("[err] Create measurement thread\n");
				}
			}

			printf("[ok] g_vnic_ip: %x, g_vnic_gateway: %x, g_vnic_mask: %x, g_vnic_dns: %x , server_udp_port: %d , server_tcp_port: %d, max_client_num: %d \n",
				*(u_int*)g_vnic_ip, *(u_int*)g_vnic_gateway,
				*(u_int*)g_vnic_mask, *(u_int*)g_vnic_dns, server_udp_port, server_tcp_port, max_client_num);

			if (max_client_num > 0) {
				if (client_info_arrays == NULL)
					client_info_arrays = new client_info[max_client_num]; 
				else
					memset(client_info_arrays, 0, max_client_num * CLIENT_INFO_LEN);//initial to false

				if(m_client_active_check == NULL)
				{
					m_client_active_check = new bool[max_client_num];//initial to false
				}
				else
				{
					memset(m_client_active_check, 0, max_client_num);//initial to false
				}
				if (client_info_arrays == NULL) {
					printf("[error] request buffer failed;\n");
					break;
				}
				for (int i = 0; i < max_client_num; ++i) {
					client_info_arrays[i].last_recv_msg_time = 0;
				}
			}

			tun_set_up = config_tun_interface(g_vnic_gateway, g_vnic_mask, g_vnic_mtu, forward_interface);

			//init lte, wifi, vnic tunnel
			if (g_lte_tunnel_sockfd == -1) {
				udp_socket_setup(lte_interface_port, lte_interface_ip,
					&g_lte_tunnel_sockfd);
			}
			else {
				printf("g_lte_tunnel_sockfd already existed\n");
			}

			if (g_wifi_tunnel_sockfd == -1) {
				udp_socket_setup(wifi_interface_port,
					wifi_interface_ip,
					&g_wifi_tunnel_sockfd);
			}
			else {
				printf("g_wifi_tunnel_sockfd already existed\n");
			}

			if (pthread_create(&lte_wifi_tunnel_recv_thread_id, NULL, lte_wifi_tunnel_recv_thread, NULL)) {
				printf("[err] Create lte_wifi_tunnel_recv_thread\n");
			}

			int* tcp_flag = (int*)malloc(sizeof(int));
			int* tcp_flag2 = (int*)malloc(sizeof(int));

			if(tcp_flag == NULL || tcp_flag2 == NULL)
			{
				// Handle out of memory in some fashion
				printf("[err] Create wifi/lte keep alive threads: Out of memory\n");
				if(tcp_flag != NULL)
				{
					free(tcp_flag);
				}
				if(tcp_flag2 != NULL)
				{
					free(tcp_flag2);
				}
			}
			else
			{
				if (strcmp(wlan_interface, net_cfg.lte_interface) != 0) {
					printf("lte & wifi different interface, create two threads\n");
					*tcp_flag = 0;
					*tcp_flag2 = 1;
					if (pthread_create(&lte_wifi_keep_alive_thread_id, NULL, lte_wifi_keep_alive_thread, (void*)tcp_flag)) {
						free(tcp_flag);
						printf("[err] Create wifi lte_wifi_keep_alive_thread\n");
					}
					if (pthread_create(&lte_wifi_keep_alive_thread2_id, NULL, lte_wifi_keep_alive_thread, (void*)tcp_flag2)) {
						free(tcp_flag2);
						printf("[err] Create lte lte_wifi_keep_alive_thread\n");
					}
				}
				else {
					free(tcp_flag2);
					*tcp_flag = 0;
					if (pthread_create(&lte_wifi_keep_alive_thread_id, NULL, lte_wifi_keep_alive_thread, (void*)tcp_flag)) {
						free(tcp_flag);
						printf("[err] Create lte_wifi_keep_alive_thread\n");
					}
					
				}
			}

			if (g_vnic_ctl_sockfd == -1) {
				normal_socket_setup(server_udp_port, g_vnic_gateway, &g_vnic_ctl_sockfd);
				if (pthread_create(&vnic_ctl_recv_thread_id, NULL, vnic_ctl_recv_thread, NULL)) {
					printf("[err] Create vnic_ctl_recv_thread\n");
				}
			}
			else {
				printf("g_vnic_ctl_sockfd existed\n");
			}

			if (g_measure_report_sockfd == -1) {
				bool bl = udp_socket_setup_nb(measure_report_port, &g_measure_report_sockfd);
				if (bl)
				{
					printf("win measurement bind successful\n");
				}
				if (pthread_create(&receive_winapp_control_message_thread_id, NULL, receive_winapp_control_message_thread, NULL)) {
					printf("[err] Create vnic_ctl_recv_thread\n");
				}
			}
			else {
				printf("g_measure_report_sockfd existed\n");
			}
			send_tun_setup_ack_to_ncm();
		}

		else if (fmt->info.type == CREATE_CLIENT_REQ) {
			int client_index = *(u_int*)&recv_buf[10];
			printf("Create New Client Req, client_index: = %d\n", client_index);
			if (client_index >= 0 && client_index < max_client_num + 2) { // array index = client index - 2
				int array_index = create_new_client(client_index);
				if (array_index == -1) {
					send_create_client_ack_to_ncm(fmt->info.client_index, 0, 0, 0);
					break;
				}
				else {

					printf("[ok] Create New Client, array_index:%d, client_index:%d\n", array_index, client_info_arrays[array_index].client_index);
					client_info_arrays[array_index].lte_link_ok = true;
					client_info_arrays[array_index].req_sn = *(u_int*)&recv_buf[6];

					printf("request create client SN : %d, session id : %d, aeskey: %s\n", client_info_arrays[array_index].req_sn, client_info_arrays[array_index].session_id, client_info_arrays[array_index].aes_key);
					send_create_client_ack_to_ncm(client_info_arrays[array_index].req_sn, client_info_arrays[array_index].client_index, client_info_arrays[array_index].session_id, client_info_arrays[array_index].aes_key);
				}
			}
			else {
				printf("[CREATE_CLIENT_REQ] wrong client index\n");
			}
		}
		
		else if (fmt->info.type == SCU_MESSAGE_REQ) {
		printf("len = % d\n", len);
			REORDERING_TIMEOUT = *(u_int*)&recv_buf[6];
			WIFI_RATE_MBPS = *(u_int*)&recv_buf[10];
			WIFI_NRT_RATE_MBPS = *(u_int*)&recv_buf[14];
			WIFI_DELAY_MS = *(u_int*)&recv_buf[18];
			LTE_RATE_MBPS = *(u_int*)&recv_buf[22];
			LTE_NRT_RATE_MBPS = *(u_int*)&recv_buf[26];
			LTE_DELAY_MS = *(u_int*)&recv_buf[30];
			MAX_RATE_MBPS = *(u_int*)&recv_buf[34];
			SLEEP_TIME_UNIT_US = *(u_int*)&recv_buf[38];
			PKT_BURST_SIZE_KB = *(u_int*)&recv_buf[42];
			MEASURE_INTERVAL_S = *(u_int*)&recv_buf[46];
			SERVER_REPORT_CYCLE = *(u_int*)&recv_buf[50];
			ENABLE_MEASURE_REPORT = *(u_int*)&recv_buf[54];
			printf("receive SCU message, REORDERING_TIMEOUT = %d, MAX_RATE_MBPS = %d, SLEEP_TIMEUNIT_US = %d, PKT_BURST_SIZE_KB = %d, MEASURE_INTERVAL_S = %d,"
				"SERVER_REPORT_CYCLE = % d, ENABLE_MEASURE_REPORT = % d\n", REORDERING_TIMEOUT, MAX_RATE_MBPS, SLEEP_TIME_UNIT_US, PKT_BURST_SIZE_KB, MEASURE_INTERVAL_S, SERVER_REPORT_CYCLE, ENABLE_MEASURE_REPORT);

			printf("WIFI_RATE_MBPS = %d, WIFI_NRT_RATE_MBPS = %d, WIFI_DELAY_MS = %d, "
				"LTE_RATE_MBPS = %d, LTE_NRT_RATE_MBPS = %d, LTE_DELAY_MS = % d,\n", WIFI_RATE_MBPS, WIFI_NRT_RATE_MBPS, WIFI_DELAY_MS, LTE_RATE_MBPS, LTE_NRT_RATE_MBPS, LTE_DELAY_MS);
			send_scu_ack_to_ncm();
		}

		else {
		if (len >= 10) { //6 bytes ctl message + 4 bytes client index + other info
			u_int client_index = *(u_int*)&recv_buf[6];
			printf("client_index = %d\n", client_index);
			if (client_index >= 2 && client_index < max_client_num + 2) { // array index = client index - 2
				int array_index = client_index - 2;
				update_current_time_params();
				if (g_time_param_s - client_info_arrays[array_index].last_recv_msg_time >= max_keep_client_time * 60)
				{
					printf("[talk_with_ncm_thread] client inactive\n");
					continue;
				}
				ProcessMsgReceivedFromWebSock(array_index, (char*)fmt, fmt->info.len);
			}
			else {
				printf("[ncm listening] wrong client index\n");
			}
			}
		}
		}		
	}
	return NULL;	
}

void* read_command_line_input_thread(void* lpParam)
{
	printf("\ncommand prompt:\n");
	printf("input '0' to disable print\n");
	printf("input '1' to enable print\n");
	//printf("input 'tsc [client_index] [UL_duplication_enabled] [DL_Dynamic_Splitting_Enabled] [K1] [K2] [L] ' to control client send tsu message\n");
	printf("input 'add [start_client_ID] [end_client_Id]' to add dummy users\n\n");

	printf("input 'quit' to quit the program\n\n");

	while (g_bQuit)
	{
		char	buff[100];

		fgets(buff, 100, stdin);
		buff[strlen(buff) - 1] = '\0';
		m_server_measure = server_measure_params();
		m_server_report = server_measure_report();
		if (strlen(buff) == 4 && buff[0] == 'q' && buff[1] == 'u' && buff[2] == 'i' && buff[3] == 't') {
			g_bServerRun = false;
			//g_bInsmod = false;
			g_bQuit = false;
			wait_command_cond.notify_one();
		}
		else if (buff[0] == 'a')
		{
			char* cmdbuf = buff;
			char* string_cmd = strsep(&cmdbuf, " ");

			if (!strncmp(string_cmd, "add", strlen("add")))
			{
				if (!cmdbuf)
				{
					printf("[wrong format] input 'add [start_client_ID] [end_client_Id]' to add dummy users\n\n");
					continue;
				}
				while (cmdbuf[0] == ' ')
					cmdbuf++;
				int startIndex = atoi(strsep(&cmdbuf, " "));

				if (!cmdbuf)
				{
					printf("[wrong format] input 'add [start_client_ID] [end_client_Id]' to add dummy users\n\n");
					continue;
				}

				while (cmdbuf[0] == ' ')
					cmdbuf++;
				int endIndex = atoi(strsep(&cmdbuf, " "));

				if (startIndex < 11)
				{
					printf("[error] choose a start client index larger than 10\n");
					continue;
				}
				if (endIndex < startIndex || endIndex > 10000)
				{
					printf("[error] choose a end client index such that starat index <= end index <= 10000\n");
					continue;
				}

				printf("add client: %d, %d\n", startIndex, endIndex);
				for (int cInd = startIndex; cInd <= endIndex; cInd++)
				{
					create_new_client(cInd);
				}
			}
			else
			{
				printf("[wrong format] input 'add [start_client_ID] [end_client_Id]' to add dummy users\n\n");
			}
		}
	}
	g_bServerRun = false;
	g_bQuit = false;
	return NULL;
}

int main(int argc, char ** argv)
{
	int ret = 0;
	char cpu_check[50]=" lscpu | grep \"Vendor ID\"";
	std::string intelcpu ("GenuineIntel");
	std::string res = popen_msg(cpu_check, 50);
	std::size_t found = res.find(intelcpu);
	
	if (found!=std::string::npos)
	{
		printf("Intel CPU is installed, continue\n");
	}
	else
	{
		printf("Intel CPU is NOT installed, exit\n");
		return -1;
	}
	
	if(!IFOM_Config_Load(SERVER_CONFIG_FILE)) {
		printf("[err] load config file \n");
		return -1;
	}

	
	if (!ncm_sock_setup()) {
		printf("[err] ncm_sock_setup \n");
	}

	if (pthread_create(&talk_with_ncm_thread_id, NULL, talk_with_ncm_thread, NULL)) {
		printf("[err] Create talk with ncm thread\n");
	}

	if (pthread_create(&read_command_line_input_thread_id, NULL, read_command_line_input_thread, NULL)) {
		printf("[err] Create talk with ncm thread\n");
	}

	while(g_bQuit)
	{
		std::unique_lock<std::mutex> lck(wait_command_mtx);
		wait_command_cond.wait(lck);//wait for restart or quit
		if (g_bQuit) //restart
		{
			tun_server_exit();
			server_exit();
			reset_server_parameters();
		}
		else // quit
		{
			break;
		}
	}

	tun_server_exit();
	server_exit();
	ncm_cmd_input_exit();
	return 0;	

}
