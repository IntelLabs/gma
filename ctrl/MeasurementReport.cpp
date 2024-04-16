//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : MeasurementReport.cpp
//Description : c++ file for Generic Multi-Access Network Virtualization

#include <stdio.h>
#include <time.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iterator>
#include <vector>
#include <pthread.h>
#include <thread>
#include <string.h>
#include "Setup1.h"
#include "ReportHeader.h"
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
using namespace std;

bool b_quit = false;
bool g_record = false;
bool send_keep_alive = false;
unsigned int sockfd = 0;
struct sockaddr_in servaddr;
pthread_t   talk_with_server_id;
pthread_t   send_keep_alive_id;
char	server_ip[IP_MAX_SIZE];
unsigned short	server_port;
char    root_location[CONFIG_STR_MAX_LEN];
int    send_keep_alive_time;
int    csv_enable = 1;

const char config_key[END_INDEX][CONFIG_STR_MAX_LEN] =
{
	"SERVER_IP_CONFIG",
	"SERVER_PORT_CONFIG",
	"ROOT_LOCATION_CONFIG",
	"SEND_KEEP_ALIVE_TIME_CONFIG",
	"CSV_ENABLE_CONFIG"
};

bool is_number(const std::string& s)
{
	//Note: This function only supports non-negative numbers
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

u_int Params_Config_Load(string filename)
{
	FILE* pfile;
	char buff[2048];
	char key_config_str[END_INDEX][CONFIG_STR_MAX_LEN];
	char* pbuff;
	char* psemicolon;
	int index = 0;
	int err;

	if ((pfile = fopen("Params_config.txt", "r")) != NULL)
	{
		if (fread(buff, 1, sizeof(buff), pfile) > 0)
		{
			pbuff = buff;
			while ((index != END_INDEX) && (pbuff = strstr(pbuff, config_key[index])))
			{
				pbuff = strstr(pbuff, "=");
				if(pbuff == NULL)
					break;
				psemicolon = strstr(pbuff, ";");
				if(psemicolon == NULL)
					break;
				memcpy(key_config_str[index], pbuff + 1, psemicolon - pbuff - 1);
				key_config_str[index][psemicolon - pbuff - 1] = '\0';
				index++;
				pbuff++;
			}
			if (index != END_INDEX)
			{
				printf("[error] Load Configuration file error\n");
				fclose(pfile);
				return 0;
			}
			if (strlen(key_config_str[SERVER_IP_INDEX]) < IP_MAX_SIZE)
			{
				memcpy(server_ip, key_config_str[SERVER_IP_INDEX], strlen(key_config_str[SERVER_IP_INDEX]));
				server_ip[strlen(key_config_str[SERVER_IP_INDEX])] = '\0';
			}
			
			server_port = atoi(key_config_str[SERVER_PORT_INDEX]);
			memcpy(root_location, key_config_str[ROOT_LOCATION_INDEX], strlen(key_config_str[ROOT_LOCATION_INDEX]));
			root_location[strlen(key_config_str[ROOT_LOCATION_INDEX])] = '\0';
			printf("server_ip = %s, server_port = %d, root_location = %s\n",
				server_ip, server_port, root_location);
			send_keep_alive_time = atoi(key_config_str[SEND_KEEP_ALIVE_TIME_INDEX]);
			csv_enable = atoi(key_config_str[CSV_ENABLE_INDEX]);
			printf("send_keep_alive_time = %d, csv_enable = %d\n", send_keep_alive_time, csv_enable);
			fclose(pfile);
			return 1;
		}
		else
		{
			printf("[error] Load Vnic Configuration file error\n");
			fclose(pfile);
			return 0;
		}
	}
	else
	{
		printf("cannot open file\n");
	}
	return 0;
}
void send_start_message_to_server()
{
	int ret = 0;
	int t = 0;
	char buf[10];

	winapp_ctl_msg* control_msg = (winapp_ctl_msg*)buf;
	control_msg->key = WIN_APP_KEY;
	control_msg->flag = START_FLAG;

	ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
	while (ret == -1 && ++t < 3)
	{
		usleep(1000);
		ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		continue;
	}
	if (ret == -1)
	{
		printf("not send\n");
	}
	return;
}
/*
void check_and_create_folder(int client_index)
{
	char ue_ip_folder[CONFIG_STR_MAX_LEN2] = { 0 };
	char ul_folder[CONFIG_STR_MAX_LEN2] = { 0 };
	char dl_folder[CONFIG_STR_MAX_LEN2] = { 0 };
	sprintf(ue_ip_folder, "%s/%d", root_location, client_index);
	if ((access(ue_ip_folder, 0)) != -1)
	{
		return;
	}
	else
	{
		if (mkdir(ue_ip_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0 ) 
			printf("\n mkdir ue_ip_folder error");
		sprintf(dl_folder, "%s/%d/DL", root_location, client_index);
		sprintf(ul_folder, "%s/%d/UL", root_location, client_index);
		if (mkdir(dl_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir dl_folder error");
		if (mkdir(ul_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir ul_folder error");
		sprintf(dl_folder, "%s/%d/DL/realtime", root_location, client_index);
		sprintf(ul_folder, "%s/%d/UL/realtime", root_location, client_index);
		
		if (mkdir(dl_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir dl_folder error");
		if (mkdir(ul_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir ul_folder error");
		
		sprintf(dl_folder, "%s/%d/DL/non_realtime", root_location, client_index);
		sprintf(ul_folder, "%s/%d/UL/non_realtime", root_location, client_index);
		if (mkdir(dl_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir dl_folder error");
		if (mkdir(ul_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir ul_folder error");
		
		
		sprintf(ul_folder, "%s/%d/UL/hr_realtime", root_location, client_index);
		if (mkdir(ul_folder, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
			printf("\n mkdir ul_folder error");
	}
	return;
}
*/
/*
void check_and_create_file()//this function is for test
{
	FILE* csv_file_pointer;
	FILE* result_file_pointer;
	time_t TimeNow = time(NULL);
	struct tm *timep = localtime(&TimeNow);
	if (timep != NULL)
		printf("mon = %d,day = %d\n", timep->tm_mon + 1, timep->tm_mday);
	else
	{
		printf("localtime failed\n");
		return;
	}
	int client_index = 7170;
	int type = 0;
	for (int i = 0; i < 4; ++i) {
		type = i;
		if (type == MRP_REPORT) //MRP
		{
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/%d/MRP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(result_file, "%s/%d/DL/results.txt", root_location, client_index);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "w");
				if (csv_file_pointer != NULL)
				{
					fprintf(csv_file_pointer,  "%s", "time_stamp;total_tpt;wifi_ratio;max_dl_tx_rate_wifi;max_dl_tx_rate_lte;wifi_rssi;lte_rssi;owd_range_wifi;"
						"owd_range_lte;average_owd_difference;last_rtt_wifi;last_rtt_lte;pack_loss_wifi;pack_loss_lte;out_of_order_packet_count_wifi;"
						"out_of_order_packet_count_lte;num_of_tsu_message;reordering_timeout;num_of_reordering_bufferoverflows;num_link_failures_wifi;"
						"num_link_failures_lte;min_owd_difference;\n");
					fclose(csv_file_pointer);
				}
				csv_file_pointer = fopen(csv_file, "a+");
			}
			if (csv_file_pointer != NULL)
			{
				fprintf(csv_file_pointer, "%s", "huanhangfu\n");
				fclose(csv_file_pointer);
			}
			result_file_pointer = fopen(result_file, "w");
			if (result_file_pointer != NULL)
			{
				fprintf(result_file_pointer, "%s", result_file);
				fclose(result_file_pointer);
			}
		}
		else if (type == LRP_REPORT) //LRP
		{
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/%d/LRP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "w");
				if (csv_file_pointer != NULL)
				{
				fprintf(csv_file_pointer, "%s", "time_stamp;bssid;\n");
				fclose(csv_file_pointer);
				}
				csv_file_pointer = fopen(csv_file, "a+");
			}
			if (csv_file_pointer != NULL)
			{
				fclose(csv_file_pointer);
			}
		}
		else if (type == URP_REPORT) //URP
		{
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/%d/URP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(result_file, "%s/%d/UL/results.txt", root_location, client_index);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "w");
				if (csv_file_pointer != NULL)
				{
					fprintf(csv_file_pointer, "%s", "time_stamp;total_tpt;wifi_ratio;owd_range_wifi;owd_range_lte;owd_range_all;average_owd_difference_wifi_lte;"
						"average_owd_difference_all_min;pack_loss_wifi;pack_loss_lte;pack_loss_all;out_of_order_packet_count_wifi;"
						"out_of_order_packet_count_lte;out_of_order_packet_count_all;num_of_output_bufferoverflows;num_of_reordering_bufferoverflows;"
						"reordering_timeout");
					fclose(csv_file_pointer);
				}
				csv_file_pointer = fopen(csv_file, "a+");
			}
			if (csv_file_pointer != NULL)
			{
				fprintf(csv_file_pointer, "%s", result_file);
				fclose(csv_file_pointer);
			}
			result_file_pointer = fopen(result_file, "w");
			if (result_file_pointer != NULL)
			{
				fprintf(result_file_pointer, "%s", result_file);
				fclose(result_file_pointer);
			}
		}
		else if (type == SRP_REPORT) //SRP
		{
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/SRP_%d_%d_%d.csv", root_location, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(result_file, "%s/results.txt", root_location);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "w");
				if (csv_file_pointer != NULL)
				{
					fprintf(csv_file_pointer, "%s", "time_stamp;num_of_active_clients_last;num_of_active_clients_current_max;num_of_active_clients_last_max;"
						"dl_throughput_last;dl_throughput_current_max;dl_throughput_last_max;ul_throughput_last;ul_throughput_current_max;"
						"ul_throughput_last_max;total_throughput_last;total_throughput_current_max;total_throughput_last_max;dl_wifi_ratio_last;"
						"dl_wifi_ratio_current_average;dl_wifi_ratio_last_average;ul_wifi_ratio_last;ul_wifi_ratio_current_average;"
						"ul_wifi_ratio_last_average;total_wifi_ratio_last;total_wifi_ratio_current_average;total_wifi_ratio_last_average;"
						"num_of_dl_tx_ringbufferoverflow_last;num_of_dl_tx_ringbufferoverflow_current_max;num_of_dl_tx_ringbufferoverflow_last_max;"
						"num_of_ul_rx_ringbufferoverflow_last;num_of_ul_rx_ringbufferoverflow_current_max;num_of_ul_rx_ringbufferoverflow_last_max;"
						"num_of_ul_ue_rx_ringbufferoverflow_last;num_of_ul_ue_rx_ringbufferoverflow_current_max;num_of_ul_ue_rx_ringbufferoverflow_last_max\n");
					fclose(csv_file_pointer);
				}
				csv_file_pointer = fopen(csv_file, "a+");
			}
			if (csv_file_pointer != NULL)
			{
				fprintf(csv_file_pointer, "%s", result_file);
				fclose(csv_file_pointer);
			}
			result_file_pointer = fopen(result_file, "w");
			if (result_file_pointer != NULL)
			{
				fprintf(result_file_pointer, "%s", result_file);
				fclose(result_file_pointer);
			}
		}
	}
}
*/

bool send_tsc_message_to_server(char* buf)
{
	int t = 0;
	int ret = 0;
	char sendbuf[100];
	winapp_ctl_msg* ctl_msg = (winapp_ctl_msg*)sendbuf;
	ctl_msg->key = WIN_APP_KEY;
	ctl_msg->flag = TSC_MESSAGE_REQ;
	tsc_msg* tscmsg = (tsc_msg*)(sendbuf + CTL_MSG);


	std::string bufstring(buf);
	std::istringstream iss(bufstring);
	std::vector<std::string> tokens{ std::istream_iterator<std::string>(iss),
	std::istream_iterator<std::string>() };
	if (tokens.size() == 7 && strcmp(tokens[0].c_str(), "tsc") == 0)
	{
		for (int i = 1; i < tokens.size(); i++)
		{
			if (!is_number(tokens[i]))
				return false;
		}
		int idNum = std::stoi(tokens[1]);
		tscmsg->client_index = idNum;
		tscmsg->UL_duplication_enabled = (unsigned char)(std::stoi(tokens[2]) & 0xFF);//UL_duplication_enabled
		tscmsg->DL_dynamic_Splitting_Enabled = (unsigned char)(std::stoi(tokens[3]) & 0xFF);//DL_Dynamic_Splitting_Enabled
		tscmsg->K1 = (unsigned char)(std::stoi(tokens[4]) & 0xFF);//K1
		tscmsg->K2 = (unsigned char)(std::stoi(tokens[5]) & 0xFF);//K2
		tscmsg->L1 = (unsigned char)(std::stoi(tokens[6]) & 0xFF);//L1
		int ret = sendto(sockfd, sendbuf, CTL_MSG + TSC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		while (ret == -1 && ++t < 3)
		{
			usleep(1000);
			ret = sendto(sockfd, sendbuf, CTL_MSG + TSC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
			continue;
		}
		if (ret == -1)
			return false;
		else
			return true;
	}
	else
	{
		return false;
	}

}

bool send_tfc_message_to_server(char* buf)
{
	int t = 0;
	int ret = 0;
	char sendbuf[100];
	winapp_ctl_msg* ctl_msg = (winapp_ctl_msg*)sendbuf;
	ctl_msg->key = WIN_APP_KEY;
	ctl_msg->flag = TFC_MESSAGE_REQ;

	tfc_msg* tfcmsg = (tfc_msg*)(sendbuf + CTL_MSG);

	std::string bufstring(buf);
	std::istringstream iss(bufstring);
	std::vector<std::string> tokens{ std::istream_iterator<std::string>(iss),
	std::istream_iterator<std::string>() };
	if (tokens.size() == 6 && strcmp(tokens[0].c_str(), "tfc") == 0)
	{
		for (int i = 1; i < tokens.size(); i++)
		{
			if (!is_number(tokens[i]))
				return false;
		}
		int idNum = std::stoi(tokens[1]);
		tfcmsg->client_index = idNum;
		tfcmsg->flow_id = (unsigned char)(std::stoi(tokens[2]) & 0xFF);//flowID
		tfcmsg->proto_type = (unsigned char)(std::stoi(tokens[3]) & 0xFF);//proto_type
		tfcmsg->port_start = (unsigned short)(std::stoi(tokens[4]) & 0xFFFF);//port_start
		tfcmsg->port_end = (unsigned short)(std::stoi(tokens[5]) & 0XFFFF);
		int ret = sendto(sockfd, sendbuf, CTL_MSG + TFC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		while (ret == -1 && ++t < 3)
		{
			usleep(1000);
			ret = sendto(sockfd, sendbuf, CTL_MSG + TFC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
			continue;
		}
		if (ret == -1)
			return false;
		else
			return true;
	}
	else
	{
		return false;
	}
}

bool send_txc_message_to_server(char* buf)
{
	int t = 0;
	int ret = 0;
	char sendbuf[100];
	winapp_ctl_msg* ctl_msg = (winapp_ctl_msg*)sendbuf;
	ctl_msg->key = WIN_APP_KEY;
	ctl_msg->flag = TXC_MESSAGE_REQ;
	txc_msg* txcmsg = (txc_msg*)(sendbuf + CTL_MSG);

	std::string bufstring(buf);
	std::istringstream iss(bufstring);
	std::vector<std::string> tokens{ std::istream_iterator<std::string>(iss),
	std::istream_iterator<std::string>() };
	if (tokens.size() == 6 && strcmp(tokens[0].c_str(), "txc") == 0)
	{
		for (int i = 1; i < tokens.size(); i++)
		{
			if (!is_number(tokens[i]))
				return false;
		}//We have prevent parameters to be negative.
		int idNum = std::stoi(tokens[1]);
		int max_rate = std::stoi(tokens[3]);
		int nrt_rate = std::stoi(tokens[4]);
		int max_delay = std::stoi(tokens[5]);
		txcmsg->link_id = (unsigned char)(std::stoi(tokens[2]) & 0XFF);
		
		if (txcmsg->link_id < 2)  //0: Wi-Fi 1: LTE: 2: enable tx offset 3: disable tx offset
		{
			if (max_rate <=0 || nrt_rate <=0 || max_delay <0)
			{
				printf("Wrong configuration\n");
				return false;
			}
		}
		
		txcmsg->client_index = idNum;
		txcmsg->max_rate = max_rate;
		txcmsg->nrt_rate = nrt_rate;
		txcmsg->max_delay = max_delay;

		int ret = sendto(sockfd, sendbuf, CTL_MSG + TXC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		while (ret == -1 && ++t < 3)
		{
			usleep(1000);
			ret = sendto(sockfd, sendbuf, CTL_MSG + TXC_MSG, 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
			continue;
		}
		if (ret == -1)
			return false;
		else
			return true;
	}
	else
	{
		return false;
	}
}

void send_update_config_request_to_server()
{
	int ret = 0;
	int t = 0;
	int i = 0;
	char buf[4096] = {0};
	winapp_ctl_msg* control_msg = (winapp_ctl_msg*)buf;
	control_msg->key = WIN_APP_KEY;
	control_msg->flag = UPDATE_CFG_FLAG;

	char* content = (char*)(buf + sizeof(winapp_ctl_msg));
	FILE* fp = fopen("conf.ini", "r");
	if (fp == NULL)
	{
		printf("[config] Error! there is no such config file and please have a check\n");
		return;
	}
	int c = fgetc(fp);
	while (c != EOF)
	{
		content[i++] = (char) c;
		c = fgetc(fp);
	}

	ret = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
	while (ret == -1 && ++t < 3)
	{
		usleep(1000);
		ret = sendto(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		continue;
	}
	fclose(fp);
	return;
}

void send_restart_message_to_server()
{
	int ret = 0;
	int t = 0;
	char buf[20];
	winapp_ctl_msg* control_msg = (winapp_ctl_msg*)buf;
	control_msg->key = WIN_APP_KEY;
	control_msg->flag = RESTART_FLAG;

	ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
	while (ret == -1 && ++t < 3)
	{
		usleep(1000);
		ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		continue;
	}
	return;
}

void send_stop_message_to_server()
{
	int ret = 0;
	int t = 0;
	char buf[20];

	winapp_ctl_msg* control_msg = (winapp_ctl_msg*)buf;
	control_msg->key = WIN_APP_KEY;
	control_msg->flag = STOP_FLAG;

	ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
	while (ret == -1 && ++t < 3)
	{
		usleep(1000);
		ret = sendto(sockfd, buf, sizeof(winapp_ctl_msg), 0, (struct sockaddr*)&servaddr, sizeof(servaddr));
		continue;
	}
	return;
}
void* send_keep_alive_thread(void* args)
{
	while (send_keep_alive)
	{
		send_start_message_to_server();
		usleep(send_keep_alive_time * 1000 * 1000);
	}
	return 0;
}

void* talk_with_server_thread(void* args)
{
	int		                pkt_len;
	unsigned int		    socklen = sizeof(servaddr);
	char                    recv_buf[BUFFER_MAX_SIZE];
	int                     client_index;
	time_t					TimeNow = time(NULL);
	FILE* csv_file_pointer;
	FILE* result_file_pointer;

	while (!b_quit)
	{
		memset(recv_buf, 0, BUFFER_MAX_SIZE);
		pkt_len = recvfrom(sockfd, recv_buf, BUFFER_MAX_SIZE, 0, (struct sockaddr*)&servaddr, &socklen);
		if (pkt_len < 0)
			continue;

		measure_report_to_winapp_header* measure_report = (measure_report_to_winapp_header*)recv_buf;

		TimeNow = time(NULL);
		struct tm* timep = localtime(&TimeNow);

		if (timep == NULL)
		{
			printf("localtime failed\n");
			continue;
		}
		/*
		if (measure_report->type == MRP_REPORT && pkt_len >= sizeof(measure_report_to_winapp_header) + sizeof(dl_measurement_prefix)) //MRP
		{
			client_index = ntohs(measure_report->UE_index);
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char ip_csv_file[CONFIG_STR_MAX_LEN2] = { 0 };

			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char rt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char nrt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };

			sprintf(csv_file, "%s/%d/MRP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(ip_csv_file, "%s/%d/ip_addr.csv", root_location, client_index);

			sprintf(result_file, "%s/%d/DL/results.txt", root_location, client_index);
			sprintf(rt_result_file, "%s/%d/DL/realtime/results.txt", root_location, client_index);
			sprintf(nrt_result_file, "%s/%d/DL/non_realtime/results.txt", root_location, client_index);

			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL)
				{
					printf("can not open MRP csv file\n");
					continue;
				}
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL)
				{
					printf("can not open MRP csv file\n");
					continue;
				}

				fprintf(csv_file_pointer, "time_stamp,total_throughput,max_dl_tx_rate_wifi,max_dl_tx_rate_lte,wifi_rssi,lte_rssi,last_rtt_wifi,last_rtt_lte,"
					"num_of_tsu_message,reordering_timeout,num_of_reordering_bufferoverflows,num_link_failures_wifi,num_link_failures_lte,min_owd_difference,"
					"rt_total_throughput,rt_wifi_throughput_ratio,rt_owd_range_wifi,rt_owd_range_lte,"
					"rt_average_owd_difference,rt_pack_loss_wifi,rt_pack_loss_lte,rt_out_of_order_packet_count_wifi,rt_out_of_order_packet_count_lte,"
					"nrt_total_throughput,nrt_wifi_throughput_ratio,nrt_owd_range_wifi,nrt_owd_range_lte,"
					"nrt_average_owd_difference,nrt_pack_loss_wifi,nrt_pack_loss_lte,nrt_out_of_order_packet_count_wifi,nrt_out_of_order_packet_count_lte\n");
			}

			int offset = sizeof(measure_report_to_winapp_header);

			FILE* ip_csv_file_pointer = fopen(ip_csv_file, "w");
			if (ip_csv_file_pointer == NULL)
			{
				printf("can not open MRP ip csv file\n");
			}
			else
			{
				lte_wifi_ip* ip_addr = (lte_wifi_ip*)(recv_buf + offset);
				offset += sizeof(struct lte_wifi_ip);
				printf("[IP] client index: %d, lte_ip: %d.%d.%d.%d, wifi_ip: %d.%d.%d.%d\n", client_index, \
					(ntohl(ip_addr->lte_ip) >> 24) & 0xFF, (ntohl(ip_addr->lte_ip) >> 16) & 0xFF, (ntohl(ip_addr->lte_ip) >> 8) & 0xFF, (ntohl(ip_addr->lte_ip)) & 0xFF, \
					(ntohl(ip_addr->wifi_ip) >> 24) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 16) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 8) & 0xFF, (ntohl(ip_addr->wifi_ip)) & 0xFF);
				fprintf(ip_csv_file_pointer, "lte_addr,wifi_addr\n");
				fprintf(ip_csv_file_pointer, "%d.%d.%d.%d,%d.%d.%d.%d\n", \
					(ntohl(ip_addr->lte_ip) >> 24) & 0xFF, (ntohl(ip_addr->lte_ip) >> 16) & 0xFF, (ntohl(ip_addr->lte_ip) >> 8) & 0xFF, (ntohl(ip_addr->lte_ip)) & 0xFF, \
					(ntohl(ip_addr->wifi_ip) >> 24) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 16) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 8) & 0xFF, (ntohl(ip_addr->wifi_ip)) & 0xFF);
				fclose(ip_csv_file_pointer);
			}

			dl_measurement_prefix* mrp = NULL;
			dl_measurement_opt* mrp_rt = NULL;
			dl_measurement_opt* mrp_nrt = NULL;

			while (offset + sizeof(dl_measurement_prefix) <= pkt_len)
			{
				mrp = (dl_measurement_prefix*)(recv_buf + offset);

				printf("[MRP] count: %d, rtBit: %d, nrtBit: %d\n", mrp->count, (mrp->flag >> 7) & 1, (mrp->flag >> 6) & 1);
				if (csv_enable == 1)
				{
					fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
						ntohs(mrp->time_stamp), ntohs(mrp->total_throughput), ntohs(mrp->max_dl_tx_rate_wifi), ntohs(mrp->max_dl_tx_rate_lte), \
						mrp->wifi_rssi, mrp->lte_rssi, mrp->last_rtt_wifi, mrp->last_rtt_lte, mrp->num_of_tsu_message, mrp->reordering_timeout, \
						mrp->num_of_reordering_bufferoverflows, mrp->num_link_failures_wifi, mrp->num_link_failures_lte, mrp->min_owd_difference);
				}

				offset += sizeof(dl_measurement_prefix);
				if ((mrp->flag >> 7) & 1) {//rt
					mrp_rt = (dl_measurement_opt*)(recv_buf + offset);
					offset += sizeof(dl_measurement_opt);

					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
							ntohs(mrp_rt->total_throughput), mrp_rt->wifi_throughput_ratio, mrp_rt->owd_range_wifi, mrp_rt->owd_range_lte, \
							mrp_rt->average_owd_difference, mrp_rt->pack_loss_wifi, mrp_rt->pack_loss_lte, mrp_rt->out_of_order_packet_count_wifi, mrp_rt->out_of_order_packet_count_lte);

					}
				}
				else {
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, ",,,,,,,,,");
					}
				}

				if ((mrp->flag >> 6) & 1) {//nrt
					mrp_nrt = (dl_measurement_opt*)(recv_buf + offset);
					offset += sizeof(dl_measurement_opt);
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d", \
							ntohs(mrp_nrt->total_throughput), mrp_nrt->wifi_throughput_ratio, mrp_nrt->owd_range_wifi, mrp_nrt->owd_range_lte, \
							mrp_nrt->average_owd_difference, mrp_nrt->pack_loss_wifi, mrp_nrt->pack_loss_lte, mrp_nrt->out_of_order_packet_count_wifi, mrp_nrt->out_of_order_packet_count_lte);
					}
				}
				fprintf(csv_file_pointer, "\n");

			}
			fclose(csv_file_pointer);

			if (mrp != NULL) {//the fixed filed
				result_file_pointer = fopen(result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP result file\n");
					continue;
				}

				fprintf(result_file_pointer, "time_stamp=%d;total_throughput=%d;max_dl_tx_rate_wifi=%d;max_dl_tx_rate_lte=%d;"
					"wifi_rssi=%d;lte_rssi=%d;last_rtt_wifi=%d;last_rtt_lte=%d;num_of_tsu_message=%d;reordering_timeout=%d;"
					"num_of_reordering_bufferoverflows=%d;num_link_failures_wifi=%d;num_link_failures_lte=%d;min_owd_diff=%d;\n", \
					ntohs(mrp->time_stamp), ntohs(mrp->total_throughput), ntohs(mrp->max_dl_tx_rate_wifi), ntohs(mrp->max_dl_tx_rate_lte), \
					mrp->wifi_rssi, mrp->lte_rssi, mrp->last_rtt_wifi, mrp->last_rtt_lte, mrp->num_of_tsu_message, mrp->reordering_timeout, \
					mrp->num_of_reordering_bufferoverflows, mrp->num_link_failures_wifi, mrp->num_link_failures_lte, mrp->min_owd_difference);

				fclose(result_file_pointer);
			}

			if (mrp_rt != NULL) {//rt

				result_file_pointer = fopen(rt_result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP realtime result file\n");
					continue;
				}

				fprintf(result_file_pointer, "total_throughput=%d;wifi_throughput_ratio=%d;owd_range_wifi=%d;owd_range_lte=%d;"
					"average_owd_difference=%d;pack_loss_wifi=%d;pack_loss_lte=%d;out_of_order_packet_count_wifi=%d;out_of_order_packet_count_lte=%d;\n", \
					ntohs(mrp_rt->total_throughput), mrp_rt->wifi_throughput_ratio, mrp_rt->owd_range_wifi, mrp_rt->owd_range_lte, \
					mrp_rt->average_owd_difference, mrp_rt->pack_loss_wifi, mrp_rt->pack_loss_lte, mrp_rt->out_of_order_packet_count_wifi, mrp_rt->out_of_order_packet_count_lte);

				fclose(result_file_pointer);
			}


			if (mrp_nrt != NULL) {//nrt
				result_file_pointer = fopen(nrt_result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP non-realtime result file\n");
					continue;
				}

				fprintf(result_file_pointer, "total_throughput=%d;wifi_throughput_ratio=%d;owd_range_wifi=%d;owd_range_lte=%d;"
					"average_owd_difference=%d;pack_loss_wifi=%d;pack_loss_lte=%d;out_of_order_packet_count_wifi=%d;out_of_order_packet_count_lte=%d;\n", \
					ntohs(mrp_nrt->total_throughput), mrp_nrt->wifi_throughput_ratio, mrp_nrt->owd_range_wifi, mrp_nrt->owd_range_lte, \
					mrp_nrt->average_owd_difference, mrp_nrt->pack_loss_wifi, mrp_nrt->pack_loss_lte, mrp_nrt->out_of_order_packet_count_wifi, mrp_nrt->out_of_order_packet_count_lte);

				fclose(result_file_pointer);
			}
		}
		else if (measure_report->type == LRP_REPORT && pkt_len >= sizeof(measure_report_to_winapp_header) + sizeof(lrp_report) && csv_enable == 1) //LRP
		{
			client_index = ntohs(measure_report->UE_index);
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/%d/LRP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL) {
					printf("can not open LRP csv file\n");
					continue;
				}
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL) {
					printf("can not open LRP csv file\n");
					continue;
				}
				fprintf(csv_file_pointer, "time_stamp,wifi_connect\n");
			}
			lrp_report* lrp = (lrp_report*)(recv_buf + sizeof(measure_report_to_winapp_header));
			fprintf(csv_file_pointer, "%d,%2x:%2x:%2x:%2x:%2x:%2x, %d\n", ntohs(lrp->time_stamp), lrp->bssid[0], lrp->bssid[1], lrp->bssid[2], lrp->bssid[3], lrp->bssid[4], lrp->bssid[5], lrp->code);
			//LRP code definition: 
			//0: wifi disconnect
			//1: wifi connect
			//2: wifi probe failure
			//3: wifi TSU failure 

			fclose(csv_file_pointer);
		}
		else if (measure_report->type == URP_REPORT && pkt_len >= sizeof(measure_report_to_winapp_header) + sizeof(ul_measurement_prefix)) //URP
		{
			int offset = sizeof(measure_report_to_winapp_header);

			ul_measurement_prefix* urp = NULL;
			ul_measurement_ext_a* urp_rt = NULL;
			ul_measurement_ext_a* urp_nrt = NULL;
			ul_measurement_ext_b* urp_hr = NULL;

			while (offset + sizeof(ul_measurement_prefix) <= pkt_len)
			{
				urp = (ul_measurement_prefix*)(recv_buf + offset);

				client_index = ntohs(urp->UE_index);

				bool rtBit = (urp->flag >> 7) & 1;
				bool nrtBit = (urp->flag >> 6) & 1;
				bool hrBit = (urp->flag >> 5) & 1;

				printf("[URP] client index: %d, rtBit: %d, nrtBit: %d, hrBit: %d\n", client_index, rtBit, nrtBit, hrBit);

				offset += sizeof(ul_measurement_prefix);

				check_and_create_folder(client_index);
				char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };

				sprintf(csv_file, "%s/%d/URP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);

				if ((access(csv_file, 0)) != -1)
				{
					csv_file_pointer = fopen(csv_file, "a+");
					if (csv_file_pointer == NULL) {
						printf("can not open URP csv file\n");
						continue;
					}
				}
				else
				{
					csv_file_pointer = fopen(csv_file, "a+");
					if (csv_file_pointer == NULL) {
						printf("can not open URP csv file\n");
						continue;
					}
					fprintf(csv_file_pointer, "time_stamp,num_of_output_bufferoverflows,num_of_reordering_bufferoverflows,reordering_timeout,"
						"RT_total_throughput,RT_wifi_per,RT_owd_diff,RT_wifi_owd_range,RT_lte_owd_range,RT_wifi_neg_log_loss,RT_lte_neg_log_loss,RT_wifi_outoforder,RT_lte_outoforder,"
						"NRT_total_throughput,NRT_wifi_per,NRT_owd_diff,NRT_wifi_owd_range,NRT_lte_owd_range,NRT_wifi_neg_log_loss,NRT_lte_neg_log_loss,NRT_wifi_outoforder,NRT_lte_outoforder,"
						"HR_total_throughput,HR_owd_diff,HR_all_owd_diff,HR_wifi_owd_range,HR_lte_owd_range,HR_all_owd_range,"
						"HR_wifi_neg_log_loss,HR_lte_neg_log_loss,HR_all_neg_log_loss,HR_wifi_outoforder,HR_lte_outoforder,HR_all_outoforder\n");
				}

				if (csv_enable == 1)
				{
					fprintf(csv_file_pointer, "%d,%d,%d,%d,", \
						ntohs(urp->time_stamp), urp->num_of_output_bufferoverflows, urp->num_of_reordering_bufferoverflows, urp->reordering_timeout);
				}

				if (rtBit) {
					urp_rt = (ul_measurement_ext_a*)(recv_buf + offset);
					offset += sizeof(ul_measurement_ext_a);
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
							ntohs(urp_rt->total_throughput), urp_rt->wifi_percent, urp_rt->ave_owd_diff, urp_rt->wifi_owd_range, urp_rt->lte_owd_range, \
							urp_rt->wifi_neg_log_loss, urp_rt->lte_neg_log_loss, urp_rt->wifi_outoforder, urp_rt->lte_outoforder);
					}
				}
				else {
					fprintf(csv_file_pointer, ",,,,,,,,,");
				}

				if (nrtBit) {
					urp_nrt = (ul_measurement_ext_a*)(recv_buf + offset);
					offset += sizeof(ul_measurement_ext_a);
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
							ntohs(urp_nrt->total_throughput), urp_nrt->wifi_percent, urp_nrt->ave_owd_diff, urp_nrt->wifi_owd_range, urp_nrt->lte_owd_range, \
							urp_nrt->wifi_neg_log_loss, urp_nrt->lte_neg_log_loss, urp_nrt->wifi_outoforder, urp_nrt->lte_outoforder);
					}
				}
				else {
					fprintf(csv_file_pointer, ",,,,,,,,,");
				}

				if (hrBit) {
					urp_hr = (ul_measurement_ext_b*)(recv_buf + offset);
					offset += sizeof(ul_measurement_ext_b);
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
							ntohs(urp_hr->total_throughput), urp_hr->ave_owd_diff, urp_hr->all_ave_owd_diff, urp_hr->wifi_owd_range, urp_hr->lte_owd_range, urp_hr->all_owd_range, \
							urp_hr->wifi_neg_log_loss, urp_hr->lte_neg_log_loss, urp_hr->all_neg_log_loss, urp_hr->wifi_outoforder, urp_hr->lte_outoforder, urp_hr->all_outoforder);
					}
				}
				else {
					fprintf(csv_file_pointer, ",,,,,,,,,,,,");
				}
				fprintf(csv_file_pointer, "\n");
				fclose(csv_file_pointer);
			}
			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char rt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char nrt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char hr_result_file[CONFIG_STR_MAX_LEN2] = { 0 };

			sprintf(result_file, "%s/%d/UL/results.txt", root_location, client_index);
			sprintf(rt_result_file, "%s/%d/UL/realtime/results.txt", root_location, client_index);
			sprintf(nrt_result_file, "%s/%d/UL/non_realtime/results.txt", root_location, client_index);
			sprintf(hr_result_file, "%s/%d/UL/hr_realtime/results.txt", root_location, client_index);

			if (urp != NULL) {//fixed part
				result_file_pointer = fopen(result_file, "w");
				if (result_file_pointer == NULL) {
					printf("can not open URP result file\n");
				}
				else
				{
					fprintf(result_file_pointer, "time_stamp=%d;num_of_output_bufferoverflows=%d;num_of_reordering_bufferoverflows=%d;reordering_timeout=%d\n", \
						ntohs(urp->time_stamp), urp->num_of_output_bufferoverflows, urp->num_of_reordering_bufferoverflows, urp->reordering_timeout);
					fclose(result_file_pointer);
				}
			}

			if (urp_rt != NULL) {//rt
				result_file_pointer = fopen(rt_result_file, "w");
				if (result_file_pointer == NULL) {
					printf("can not open URP rt result file\n");
				}
				else
				{
					fprintf(result_file_pointer, "rt_total_throughput=%d;rt_wifi_percent=%d;rt_ave_owd_diff=%d;rt_wifi_owd_range=%d;rt_lte_owd_range=%d;"
						"rt_wifi_neg_log_loss=%d;rt_lte_neg_log_loss=%d;rt_wifi_outoforder=%d;rt_lte_outoforder=%d\n", \
						ntohs(urp_rt->total_throughput), urp_rt->wifi_percent, urp_rt->ave_owd_diff, urp_rt->wifi_owd_range, urp_rt->lte_owd_range, \
						urp_rt->wifi_neg_log_loss, urp_rt->lte_neg_log_loss, urp_rt->wifi_outoforder, urp_rt->lte_outoforder);
					fclose(result_file_pointer);
				}
			}

			if (urp_nrt != NULL) {//nrt
				result_file_pointer = fopen(nrt_result_file, "w");
				if (result_file_pointer == NULL) {
					printf("can not open URP nrt result file\n");
				}
				else
				{
					fprintf(result_file_pointer, "nrt_total_throughput=%d;nrt_wifi_percent=%d;nrt_ave_owd_diff=%d;nrt_wifi_owd_range=%d;nrt_lte_owd_range=%d;"
						"nrt_wifi_neg_log_loss=%d;nrt_lte_neg_log_loss=%d;nrt_wifi_outoforder=%d;nrt_lte_outoforder=%d\n", \
						ntohs(urp_nrt->total_throughput), urp_nrt->wifi_percent, urp_nrt->ave_owd_diff, urp_nrt->wifi_owd_range, urp_nrt->lte_owd_range, \
						urp_nrt->wifi_neg_log_loss, urp_nrt->lte_neg_log_loss, urp_nrt->wifi_outoforder, urp_nrt->lte_outoforder);
					fclose(result_file_pointer);
				}
			}

			if (urp_hr != NULL) {//hr
				result_file_pointer = fopen(hr_result_file, "w");
				if (result_file_pointer == NULL) {
					printf("can not open URP hr result file\n");
				}
				else
				{
					fprintf(result_file_pointer, "hr_total_throughput=%d;hr_ave_owd_diff=%d;hr_all_ave_owd_diff=%d;hr_wifi_owd_range=%d;hr_lte_owd_range=%d;hr_all_owd_range=%d;"
						"hr_wifi_neg_log_loss=%d;hr_lte_neg_log_loss=%d;hr_all_neg_log_loss=%d;hr_wifi_outoforder=%d;hr_lte_outoforder=%d;hr_all_outoforder=%d\n", \
						ntohs(urp_hr->total_throughput), urp_hr->ave_owd_diff, urp_hr->all_ave_owd_diff, urp_hr->wifi_owd_range, urp_hr->lte_owd_range, urp_hr->all_owd_range, \
						urp_hr->wifi_neg_log_loss, urp_hr->lte_neg_log_loss, urp_hr->all_neg_log_loss, urp_hr->wifi_outoforder, urp_hr->lte_outoforder, urp_hr->all_outoforder);
					fclose(result_file_pointer);
				}
			}


		}
		else if (measure_report->type == SRP_REPORT && pkt_len >= sizeof(measure_report_to_winapp_header) + sizeof(server_measurement)) //SRP
		{
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			sprintf(csv_file, "%s/SRP_%d_%d_%d.csv", root_location, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(result_file, "%s/results.txt", root_location);
			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL) {
					printf("can not open SRP csv file\n");
					continue;
				}
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL) {
					printf("can not open SRP csv file\n");
					continue;
				}
				fprintf(csv_file_pointer, "time_stamp,num_of_active_clients_last,num_of_active_clients_current_max,num_of_active_clients_last_max,"
					"dl_throughput_last,dl_throughput_current_max,dl_throughput_last_max,ul_throughput_last,ul_throughput_current_max,"
					"ul_throughput_last_max,total_throughput_last,total_throughput_current_max,total_throughput_last_max,dl_wifi_ratio_last,"
					"dl_wifi_ratio_current_average,dl_wifi_ratio_last_average,ul_wifi_ratio_last,ul_wifi_ratio_current_average,"
					"ul_wifi_ratio_last_average,total_wifi_ratio_last,total_wifi_ratio_current_average,total_wifi_ratio_last_average,"
					"num_of_dl_tx_ringbufferoverflow_last,num_of_dl_tx_ringbufferoverflow_current_max,num_of_dl_tx_ringbufferoverflow_last_max,"
					"num_of_ul_rx_ringbufferoverflow_last,num_of_ul_rx_ringbufferoverflow_current_max,num_of_ul_rx_ringbufferoverflow_last_max,"
					"num_of_ul_ue_rx_ringbufferoverflow_last,num_of_ul_ue_rx_ringbufferoverflow_current_max,num_of_ul_ue_rx_ringbufferoverflow_last_max\n");
			}

			int offset = sizeof(measure_report_to_winapp_header);
			server_measurement* srp = NULL;
			while (offset + sizeof(server_measurement) <= pkt_len)
			{
				srp = (server_measurement*)(recv_buf + offset);
				if (csv_enable == 1)
				{
					fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", \
						srp->time_stamp, srp->num_of_active_clients_last, srp->num_of_active_clients_current_max, srp->num_of_active_clients_last_max, srp->dl_throughput_last, \
						srp->dl_throughput_current_max, srp->dl_throughput_last_max, srp->ul_throughput_last, srp->ul_throughput_current_max, srp->ul_throughput_last_max, srp->total_throughput_last, srp->total_throughput_current_max, \
						srp->total_throughput_last_max, srp->dl_wifi_ratio_last, srp->dl_wifi_ratio_current_average, srp->dl_wifi_ratio_last_average, \
						srp->ul_wifi_ratio_last, srp->ul_wifi_ratio_current_average, srp->ul_wifi_ratio_last_average, srp->total_wifi_ratio_last, \
						srp->total_wifi_ratio_current_average, srp->total_wifi_ratio_last_average, srp->num_of_dl_tx_ringbufferoverflow_last, srp->num_of_dl_tx_ringbufferoverflow_current_max, \
						srp->num_of_dl_tx_ringbufferoverflow_last_max, srp->num_of_ul_rx_ringbufferoverflow_last, srp->num_of_ul_rx_ringbufferoverflow_current_max, srp->num_of_ul_rx_ringbufferoverflow_last_max, \
						srp->num_of_ul_ue_rx_ringbufferoverflow_last, srp->num_of_ul_ue_rx_ringbufferoverflow_current_max, srp->num_of_ul_ue_rx_ringbufferoverflow_last_max);
				}
				offset += sizeof(server_measurement);
			}

			fclose(csv_file_pointer);

			result_file_pointer = fopen(result_file, "w");
			if (result_file_pointer == NULL) {
				printf("can not open SRP result file\n");
				continue;
			}
			if (srp != NULL)
			{
				fprintf(result_file_pointer, "time_stamp=%d;num_of_active_clients_last=%d;num_of_active_clients_current_max=%d;num_of_active_clients_last_max=%d;dl_throughput_last=%d;"
					"dl_throughput_current_max=%d;dl_throughput_last_max=%d;ul_throughput_last=%d;ul_throughput_current_max=%d;ul_throughput_last_max=%d;total_throughput_last=%d;total_throughput_current_max=%d;"
					"total_throughput_last_max=%d;dl_wifi_ratio_last=%d;dl_wifi_ratio_current_average=%d;dl_wifi_ratio_last_average=%d;"
					"ul_wifi_ratio_last=%d;ul_wifi_ratio_current_average=%d;ul_wifi_ratio_last_average=%d;total_wifi_ratio_last=%d;"
					"total_wifi_ratio_current_average=%d;total_wifi_ratio_last_average=%d;num_of_dl_tx_ringbufferoverflow_last=%d;num_of_dl_tx_ringbufferoverflow_current_max=%d;"
					"num_of_dl_tx_ringbufferoverflow_last_max=%d;num_of_ul_rx_ringbufferoverflow_last=%d;num_of_ul_rx_ringbufferoverflow_current_max=%d;num_of_ul_rx_ringbufferoverflow_last_max=%d;"
					"num_of_ul_ue_rx_ringbufferoverflow_last=%d;num_of_ul_ue_rx_ringbufferoverflow_current_max=%d;num_of_ul_ue_rx_ringbufferoverflow_last_max=%d;\n", \
					srp->time_stamp, srp->num_of_active_clients_last, srp->num_of_active_clients_current_max, srp->num_of_active_clients_last_max, srp->dl_throughput_last, \
					srp->dl_throughput_current_max, srp->dl_throughput_last_max, srp->ul_throughput_last, srp->ul_throughput_current_max, srp->ul_throughput_last_max, srp->total_throughput_last, srp->total_throughput_current_max, \
					srp->total_throughput_last_max, srp->dl_wifi_ratio_last, srp->dl_wifi_ratio_current_average, srp->dl_wifi_ratio_last_average, \
					srp->ul_wifi_ratio_last, srp->ul_wifi_ratio_current_average, srp->ul_wifi_ratio_last_average, srp->total_wifi_ratio_last, \
					srp->total_wifi_ratio_current_average, srp->total_wifi_ratio_last_average, srp->num_of_dl_tx_ringbufferoverflow_last, srp->num_of_dl_tx_ringbufferoverflow_current_max, \
					srp->num_of_dl_tx_ringbufferoverflow_last_max, srp->num_of_ul_rx_ringbufferoverflow_last, srp->num_of_ul_rx_ringbufferoverflow_current_max, srp->num_of_ul_rx_ringbufferoverflow_last_max, \
					srp->num_of_ul_ue_rx_ringbufferoverflow_last, srp->num_of_ul_ue_rx_ringbufferoverflow_current_max, srp->num_of_ul_ue_rx_ringbufferoverflow_last_max);
			}
			fclose(result_file_pointer);
		}
		else if (measure_report->type == MRP_REPORT_V2 && pkt_len >= sizeof(measure_report_to_winapp_header) + sizeof(dl_measurement_prefix)) //MRP	
		{
			client_index = ntohs(measure_report->UE_index);
			check_and_create_folder(client_index);
			char csv_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char ip_csv_file[CONFIG_STR_MAX_LEN2] = { 0 };

			char result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char rt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };
			char nrt_result_file[CONFIG_STR_MAX_LEN2] = { 0 };

			sprintf(csv_file, "%s/%d/MRP_%d_%d_%d.csv", root_location, client_index, timep->tm_year + 1900, timep->tm_mon + 1, timep->tm_mday);
			sprintf(ip_csv_file, "%s/%d/ip_addr.csv", root_location, client_index);

			sprintf(result_file, "%s/%d/DL/results.txt", root_location, client_index);
			sprintf(rt_result_file, "%s/%d/DL/realtime/results.txt", root_location, client_index);
			sprintf(nrt_result_file, "%s/%d/DL/non_realtime/results.txt", root_location, client_index);

			if ((access(csv_file, 0)) != -1)
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL)
				{
					printf("can not open MRP csv file\n");
					continue;
				}
			}
			else
			{
				csv_file_pointer = fopen(csv_file, "a+");
				if (csv_file_pointer == NULL)
				{
					printf("can not open MRP csv file\n");
					continue;
				}

				fprintf(csv_file_pointer, "time_stamp,total_throughput,max_dl_tx_rate_wifi,max_dl_tx_rate_lte,wifi_rssi,lte_rssi,last_rtt_wifi,last_rtt_lte,"
					"num_of_tsu_message,reordering_timeout,num_of_reordering_bufferoverflows,num_link_failures_wifi,num_link_failures_lte,min_owd_difference,"
					"rt_total_throughput,rt_wifi_throughput_ratio,rt_owd_range_wifi,rt_owd_range_lte,"
					"rt_average_owd_difference,rt_pack_loss_wifi,rt_pack_loss_lte,rt_out_of_order_packet_count_wifi,rt_out_of_order_packet_count_lte,"
					"nrt_total_throughput,nrt_wifi_throughput_ratio,nrt_owd_range_wifi,nrt_owd_range_lte,"
					"nrt_average_owd_difference,nrt_pack_loss_wifi,nrt_pack_loss_lte,nrt_out_of_order_packet_count_wifi,nrt_out_of_order_packet_count_lte,nrt_owd_range_all,nrt_pack_loss_all,nrt_avg_owd_diff_all\n");
			}

			int offset = sizeof(measure_report_to_winapp_header);

			FILE* ip_csv_file_pointer = fopen(ip_csv_file, "w");
			if (ip_csv_file_pointer == NULL)
			{
				printf("can not open MRP ip csv file\n");
			}
			else
			{
				lte_wifi_ip* ip_addr = (lte_wifi_ip*)(recv_buf + offset);
				offset += sizeof(struct lte_wifi_ip);
				printf("[IP] client index: %d, lte_ip: %d.%d.%d.%d, wifi_ip: %d.%d.%d.%d\n", client_index, \
					(ntohl(ip_addr->lte_ip) >> 24) & 0xFF, (ntohl(ip_addr->lte_ip) >> 16) & 0xFF, (ntohl(ip_addr->lte_ip) >> 8) & 0xFF, (ntohl(ip_addr->lte_ip)) & 0xFF, \
					(ntohl(ip_addr->wifi_ip) >> 24) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 16) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 8) & 0xFF, (ntohl(ip_addr->wifi_ip)) & 0xFF);
				fprintf(ip_csv_file_pointer, "lte_addr,wifi_addr\n");
				fprintf(ip_csv_file_pointer, "%d.%d.%d.%d,%d.%d.%d.%d\n", \
					(ntohl(ip_addr->lte_ip) >> 24) & 0xFF, (ntohl(ip_addr->lte_ip) >> 16) & 0xFF, (ntohl(ip_addr->lte_ip) >> 8) & 0xFF, (ntohl(ip_addr->lte_ip)) & 0xFF, \
					(ntohl(ip_addr->wifi_ip) >> 24) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 16) & 0xFF, (ntohl(ip_addr->wifi_ip) >> 8) & 0xFF, (ntohl(ip_addr->wifi_ip)) & 0xFF);
				fclose(ip_csv_file_pointer);
			}

			dl_measurement_prefix* mrp = NULL;
			dl_measurement_opt* mrp_rt = NULL;
			dl_measurement_opt_v2* mrp_nrt = NULL;

			while (offset + sizeof(dl_measurement_prefix) <= pkt_len)
			{
				mrp = (dl_measurement_prefix*)(recv_buf + offset);

				printf("[MRP] count: %d, rtBit: %d, nrtBit: %d\n", mrp->count, (mrp->flag >> 7) & 1, (mrp->flag >> 6) & 1);
				if (csv_enable == 1)
				{
					fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
						ntohs(mrp->time_stamp), ntohs(mrp->total_throughput), ntohs(mrp->max_dl_tx_rate_wifi), ntohs(mrp->max_dl_tx_rate_lte), \
						mrp->wifi_rssi, mrp->lte_rssi, mrp->last_rtt_wifi, mrp->last_rtt_lte, mrp->num_of_tsu_message, mrp->reordering_timeout, \
						mrp->num_of_reordering_bufferoverflows, mrp->num_link_failures_wifi, mrp->num_link_failures_lte, mrp->min_owd_difference);
				}

				offset += sizeof(dl_measurement_prefix);
				if ((mrp->flag >> 7) & 1) {//rt
					mrp_rt = (dl_measurement_opt*)(recv_buf + offset);
					offset += sizeof(dl_measurement_opt);

					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,", \
							ntohs(mrp_rt->total_throughput), mrp_rt->wifi_throughput_ratio, mrp_rt->owd_range_wifi, mrp_rt->owd_range_lte, \
							mrp_rt->average_owd_difference, mrp_rt->pack_loss_wifi, mrp_rt->pack_loss_lte, mrp_rt->out_of_order_packet_count_wifi, mrp_rt->out_of_order_packet_count_lte);

					}
				}
				else {
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, ",,,,,,,,,");
					}
				}

				if ((mrp->flag >> 6) & 1) {//nrt
					mrp_nrt = (dl_measurement_opt_v2*)(recv_buf + offset);
					offset += sizeof(dl_measurement_opt_v2);
					if (csv_enable == 1)
					{
						fprintf(csv_file_pointer, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", \
							ntohs(mrp_nrt->total_throughput), mrp_nrt->wifi_throughput_ratio, mrp_nrt->owd_range_wifi, mrp_nrt->owd_range_lte, \
							mrp_nrt->average_owd_difference, mrp_nrt->pack_loss_wifi, mrp_nrt->pack_loss_lte, \
							mrp_nrt->out_of_order_packet_count_wifi, mrp_nrt->out_of_order_packet_count_lte, \
							mrp_nrt->owd_range_all, mrp_nrt->pack_loss_all, mrp_nrt->all_owd_difference);
					}
				}
				fprintf(csv_file_pointer, "\n");

			}
			fclose(csv_file_pointer);

			if (mrp != NULL) {//the fixed filed
				result_file_pointer = fopen(result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP result file\n");
					continue;
				}

				fprintf(result_file_pointer, "time_stamp=%d;total_throughput=%d;max_dl_tx_rate_wifi=%d;max_dl_tx_rate_lte=%d;"
					"wifi_rssi=%d;lte_rssi=%d;last_rtt_wifi=%d;last_rtt_lte=%d;num_of_tsu_message=%d;reordering_timeout=%d;"
					"num_of_reordering_bufferoverflows=%d;num_link_failures_wifi=%d;num_link_failures_lte=%d;min_owd_diff=%d;\n", \
					ntohs(mrp->time_stamp), ntohs(mrp->total_throughput), ntohs(mrp->max_dl_tx_rate_wifi), ntohs(mrp->max_dl_tx_rate_lte), \
					mrp->wifi_rssi, mrp->lte_rssi, mrp->last_rtt_wifi, mrp->last_rtt_lte, mrp->num_of_tsu_message, mrp->reordering_timeout, \
					mrp->num_of_reordering_bufferoverflows, mrp->num_link_failures_wifi, mrp->num_link_failures_lte, mrp->min_owd_difference);

				fclose(result_file_pointer);
			}

			if (mrp_rt != NULL) {//rt

				result_file_pointer = fopen(rt_result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP realtime result file\n");
					continue;
				}

				fprintf(result_file_pointer, "total_throughput=%d;wifi_throughput_ratio=%d;owd_range_wifi=%d;owd_range_lte=%d;"
					"average_owd_difference=%d;pack_loss_wifi=%d;pack_loss_lte=%d;out_of_order_packet_count_wifi=%d;out_of_order_packet_count_lte=%d;\n", \
					ntohs(mrp_rt->total_throughput), mrp_rt->wifi_throughput_ratio, mrp_rt->owd_range_wifi, mrp_rt->owd_range_lte, \
					mrp_rt->average_owd_difference, mrp_rt->pack_loss_wifi, mrp_rt->pack_loss_lte, mrp_rt->out_of_order_packet_count_wifi, mrp_rt->out_of_order_packet_count_lte);

				fclose(result_file_pointer);
			}


			if (mrp_nrt != NULL) {//nrt
				result_file_pointer = fopen(nrt_result_file, "w");
				if (result_file_pointer == NULL)
				{
					printf("can not open MRP non-realtime result file\n");
					continue;
				}

				fprintf(result_file_pointer, "total_throughput=%d;wifi_throughput_ratio=%d;owd_range_wifi=%d;owd_range_lte=%d;"
					"average_owd_difference=%d;pack_loss_wifi=%d;pack_loss_lte=%d;out_of_order_packet_count_wifi=%d;out_of_order_packet_count_lte=%d;\n", \
					ntohs(mrp_nrt->total_throughput), mrp_nrt->wifi_throughput_ratio, mrp_nrt->owd_range_wifi, mrp_nrt->owd_range_lte, \
					mrp_nrt->average_owd_difference, mrp_nrt->pack_loss_wifi, mrp_nrt->pack_loss_lte, mrp_nrt->out_of_order_packet_count_wifi, mrp_nrt->out_of_order_packet_count_lte);

				fclose(result_file_pointer);
			}
		}
		else 
		*/
		if (measure_report->type == TSC_MESSAGE_ACK)
		{
			printf("receive tsc message ack.\n");
		}
		else if (measure_report->type == TFC_MESSAGE_ACK)
		{
			printf("receive tfc message ack.\n");
		}
		else if (measure_report->type == TXC_MESSAGE_ACK)
		{
			printf("receive txc message ack.\n");
		}
		else if (measure_report->type == WINAPP_RESTART_ACK)
		{
		printf("receive restart message ack.\n");
		}
	}
	return 0;
}

int sock_init()
{
	int					pkt_len;
	unsigned int		socklen = sizeof(servaddr);
	char				recv_buf[BUFFER_MAX_SIZE];

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
	{
		printf("[error] Error at socket()");
		return -1;
	}

	// clear servaddr 
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(server_port);
	servaddr.sin_addr.s_addr = inet_addr(server_ip);
	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
	{
		printf("\n Error : Connect Failed \n");
		//exit(0);
		return -1;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	if (Params_Config_Load(CONFIG_FILE))
	{
		printf("read file successuful\n");
	}
	if (sock_init() < 0)
	{
		printf("init socket failed\n");
	}
	
	if (pthread_create(&talk_with_server_id, NULL, talk_with_server_thread, NULL))
	{
		printf("[error] Create talk_with_server_thread error\n");
		return -1;
	}
	printf("[keyboard inputs]\n[start: start measurement]\n[stop: stop measurement]\n[quit: quit the program]\n");

	while (!b_quit)
	{
		char buff[128];
		fgets(buff, sizeof(buff), stdin);
		buff[strlen(buff) - 1] = '\0';
		if (!strcmp(buff, "quit"))
		{
			b_quit = true;
			break;
		}
		else if (!strncmp(buff, "start", strlen("start")))
		{
			printf("send keep alive and start\n");
			if (!send_keep_alive)
			{
				send_keep_alive = true;
				if (pthread_create(&send_keep_alive_id, NULL, send_keep_alive_thread, NULL)) 
				{
					printf("[error] Create send_keep_alive_thread error\n");
					b_quit = true;
					break;
				}
			}
		}
		else if (!strncmp(buff, "stop", strlen("stop")))
		{
			send_stop_message_to_server();
			send_keep_alive = false;
			printf("stop\n");
		}
		else if (!strncmp(buff, "config", strlen("config")))
		{
			printf("update config request\n");
			send_update_config_request_to_server();
		}
		else if (!strncmp(buff, "restart", strlen("restart")))
		{
			printf("[winapp]: send restart request to server\n");
			send_restart_message_to_server();
		}
		else if (!strncmp(buff, "tsc", strlen("tsc")))
		{
			if (!send_tsc_message_to_server(buff))
				printf("Wrong format, e.g., [tsc clientIndex ulDupEnabled dlDynamicSplitEnabled K1 K2 L1]\n");
			else
				printf("send tsc req\n");
		}
		else if (!strncmp(buff, "tfc", strlen("tfc")))
		{
			if (!send_tfc_message_to_server(buff))
				printf("Wrong format, e.g., [tfc clientIndex flowId(1: HR, 2: RT, 3: NRT) protoType(0:disable, 1: tcp, 2: udp,  3: ICMP) portStart(0~65535) portEnd(0~65535)]\n");
			else
				printf("send tfc req\n");
		}
		else if (!strncmp(buff, "txc", strlen("txc")))
		{
			if (!send_txc_message_to_server(buff))
				printf("Wrong format, e.g., [txc clientIndex linkId maxRate(Mbit/s) rtQueueLimit(pkts) nrtDelay(ms)]\n");
			else
				printf("send txc req\n");
		}
	}
	pthread_cancel(talk_with_server_id);
	pthread_join(talk_with_server_id, NULL);
	if(send_keep_alive_id != 0)
	{
		pthread_cancel(send_keep_alive_id);
		pthread_join(send_keep_alive_id, NULL);
	}
	return 0;
}
