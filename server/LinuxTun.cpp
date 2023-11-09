//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : LinuxTun.cpp
//Description : c++ file for Generic Multi-Access Network Virtualization

#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include "IFOMServer.h"
#include <netinet/in.h>
#include <sys/wait.h>
#include <iostream>


struct tun_server tun;
pthread_t	tun_server_read_tun_thread_id;

unsigned int get_current_mstime()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (unsigned int)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

int tun_create(const char * dev, int flags)
{
	struct ifreq ifr;
	int fd, err;
	if((fd = open("/dev/net/tun", O_RDWR)) < 0)
	{
		printf("Ipen /dev/net/tun error\n\n");
		return fd;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;
	if(*dev)
	{
		strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	}
	if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
	{
		close(fd);
		return err;
	}
	return fd;
}
	

int tun_read(int tun_fd, char * tun_buf, int size)
{
	int maxfd = tun_fd;
	int ret;
	int nread = 0;
	fd_set rd_set;
	struct timeval timeout;
	timeout.tv_sec = 10;
	FD_ZERO(&rd_set);
	FD_SET(tun_fd, &rd_set);

	ret = select(maxfd+1, &rd_set, NULL, NULL, &timeout);

	if(ret < 0)
	{
		return -1;
	}

	if(FD_ISSET(tun_fd, &rd_set))
	{
		nread = read(tun_fd, tun_buf, size);
		if(nread < 0)
		{
			return -1;
		}
	}
	return nread;
}


int tun_write(int tun_fd, char * buf, int pkt_len)
{
	int nwrite = write(tun_fd, buf, pkt_len);
	if(nwrite < 0)
	{
		return -1;
	}
	return nwrite;
}


void vnic_tun_send_ctl_ack(struct sockaddr_in remote_addr, char *msg, int len)
{
	int vsock = -1;
	char ack_buf[100];
	int ack_len = 0;
	int ret;
	int t = 0;
	int linkCid = -1;

	u_int client_index;
	u_int array_index;
	memset(ack_buf, 0, 100);

	//set gma flag to 0, i.e., control msg
	struct virtual_message_header* header = (struct virtual_message_header*)ack_buf;
	*(u_short*)header->flag = 0;

	client_index = (u_int)(ntohl(remote_addr.sin_addr.s_addr) & 0x0000FFFF);
	
	if (client_index >= 2 && client_index < max_client_num + 2) {
		array_index = client_index - 2;
	}
	else {
		printf("[err] send ctl ack, no client\n");
		return;
	}
	client_info_arrays[array_index].client_vnic_addr.sin_family = AF_INET;
	client_info_arrays[array_index].client_vnic_addr.sin_addr.s_addr = remote_addr.sin_addr.s_addr;
	client_info_arrays[array_index].client_vnic_addr.sin_port = remote_addr.sin_port;
	if (msg[0] == PROBE_VNIC) {
		struct vnic_probe_req *probe = (struct vnic_probe_req *)msg;
		struct vnic_ack* vack = (struct vnic_ack*)(ack_buf + VIRTUAL_MESSAGE);
		vack->type    = ACK_VNIC;
		vack->cid     = probe->cid;
		vack->key	  = probe->key;
		vack->seq_num = probe->seq_num;

		/*if (Roll_Over_Diff(ntohs(probe->seq_num), client_info_arrays[array_index].last_tsu_sn, 2 ^ 16) >= 0)
		{
			client_info_arrays[array_index].last_tsu_sn = ntohs(probe->seq_num);
		}*/

		vack->time_stamp = htonl(client_info_arrays[array_index].start_time == 0 ? 0 : (get_current_mstime() + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);
		vack->reqType = PROBE_VNIC;
		ack_len = sizeof(vnic_ack);
		linkCid = probe->cid;

		client_info_arrays[array_index].linkStatusBitmap = probe->link_bitmap;

	} 
	else if (msg[0] == TSU_VNIC) {
		struct vnic_tsu_req *tsu = (struct vnic_tsu_req *)msg;
		struct traffic_split_ack *vack = (struct traffic_split_ack*)(ack_buf + VIRTUAL_MESSAGE);
		vack->type    = TSA_VNIC;
		vack->cid     = tsu->cid;
		vack->key	  = tsu->key;
		vack->seq_num = tsu->seq_num;
		vack->time_stamp = htonl(client_info_arrays[array_index].start_time == 0 ? 0 : (get_current_mstime() + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);

		vack->start_sn1 = (client_info_arrays[array_index].dl_sn + 1) & 0x00FFFFFF;
		ack_len = sizeof(traffic_split_ack);
		linkCid = tsu->cid;

		client_info_arrays[array_index].linkStatusBitmap = tsu->link_bitmap;
		client_info_arrays[array_index].wifi_link_used = true;
		client_info_arrays[array_index].lte_link_used = true;

		//if (Roll_Over_Diff(ntohs(tsu->seq_num), client_info_arrays[array_index].last_tsu_sn, 2^16) >= 0) 
		{
			//client_info_arrays[array_index].last_tsu_sn = ntohs(tsu->seq_num);

			if (tsu->flow_id1 == NON_REALTIME_FLOW_ID)
			{
					u_char split_factor = 1;
					client_info_arrays[array_index].tsu_wifi_split_size = tsu->K1 * split_factor;
					client_info_arrays[array_index].tsu_lte_split_size = tsu->K2 * split_factor;
					client_info_arrays[array_index].tsu_traffic_split_threshold = tsu->L1 * split_factor;
			}
			else
			{
				printf("[ERROR TSU], the first flow id is %d, the corroct one should be %d", tsu->flow_id1, NON_REALTIME_FLOW_ID);
			}

			

			if (tsu->flow_id2 == REALTIME_FLOW_ID)
			{
				if (tsu->K3 == 1 && tsu->K4 == 0)
				{
					client_info_arrays[array_index].rt_traffic_over_lte = false;

				}
				else if (tsu->K3 == 0 && tsu->K4 == 1)
				{
					client_info_arrays[array_index].rt_traffic_over_lte = true;
				}
				else
				{
					printf("[ERROR TSU], wrong format for second flow K3: %d, K4: %d, L2: %d", tsu->K3, tsu->K4, tsu->L2);

				}
			}
			else
			{
				printf("[ERROR TSU], the second flow id is %d, the corroct one should be %d", tsu->flow_id2, REALTIME_FLOW_ID);
			}

		}
		printf("[ok] [client index : %d, array index: %d]Got TSU, wifi traffic size: %d, lte traffic size: %d, total traffic size: %d, TSU sn: %d, rt_traffic_over_lte :%d\n",
			client_index, array_index, client_info_arrays[array_index].tsu_wifi_split_size, client_info_arrays[array_index].tsu_lte_split_size, client_info_arrays[array_index].tsu_traffic_split_threshold, ntohs(tsu->seq_num), client_info_arrays[array_index].rt_traffic_over_lte);
	}
	else if (msg[0] == ACK_VNIC) {
		struct vnic_ack* vack = (struct vnic_ack*)msg;
		switch (vack->reqType) {
		case 4: client_info_arrays[array_index].tscmsg.flag = 0;  printf("[ok] [client index : %d, array index: %d]Got TSC ACK\n", client_index, array_index); break;    //tsc
		case 6: client_info_arrays[array_index].tfcmsg.flag = 0;  printf("[ok] [client index : %d, array index: %d]Got TFC ACK\n", client_index, array_index); break;    //tfc
		default: break;
		}
		goto END;

	}
	else if ((msg[0] & 0xFF) == MEASURE_REPORT) {
		struct measure_report_req* measure_report = (struct measure_report_req*)msg;
		struct vnic_ack* vack = (struct vnic_ack*)(ack_buf + VIRTUAL_MESSAGE);
		vack->type = ACK_VNIC;
		vack->cid = measure_report->cid;
		vack->key = measure_report->key;
		vack->seq_num = measure_report->seq_num;
		vack->time_stamp = htonl(client_info_arrays[array_index].start_time == 0 ? 0 : (get_current_mstime() + client_info_arrays[array_index].start_time) & 0x7FFFFFFF);
		vack->reqType = MEASURE_REPORT;
		ack_len = sizeof(vnic_ack);
		linkCid = measure_report->cid;

		if (measure_report->sub_type == 1) {
			if (g_send_measurement_to_winapp) {
				send_measurement_report_to_winapp(MRP_REPORT, client_index, msg + sizeof(struct measure_report_req), len - sizeof(struct measure_report_req));
			}
			printf("MRP\n");
		}
		else if (measure_report->sub_type == 2) {
			if (g_send_measurement_to_winapp) {
				send_measurement_report_to_winapp(LRP_REPORT, client_index, msg + sizeof(struct measure_report_req), len - sizeof(struct measure_report_req));
			}
			printf("LPR\n");
		}
		else
		{
			if (g_send_measurement_to_winapp) {
				send_measurement_report_to_winapp(measure_report->sub_type, client_index, msg + sizeof(struct measure_report_req), len - sizeof(struct measure_report_req));
			}
			printf("MRPv2\n");
		}
	} else {
		printf("[err] ctl msg type\n");
		goto END;
	}
	
	switch (client_info_arrays[array_index].linkStatusBitmap) {
	case 0: client_info_arrays[array_index].wifi_link_ok = false;  client_info_arrays[array_index].lte_link_ok = false; break;
	case 1: client_info_arrays[array_index].wifi_link_ok = true; client_info_arrays[array_index].lte_link_ok = false; break;
	case 2: client_info_arrays[array_index].wifi_link_ok = false; client_info_arrays[array_index].lte_link_ok = true; break;
	case 3: client_info_arrays[array_index].wifi_link_ok = true; client_info_arrays[array_index].lte_link_ok = true; break;
	default: break;
	}

	struct sockaddr_in receiver_addr;
	if (linkCid == LTE_CID)
	{
		vsock = g_lte_tunnel_sockfd;
		receiver_addr = client_info_arrays[array_index].client_lte_addr;
	}
	else if (linkCid == WIFI_CID)
	{
		vsock = g_wifi_tunnel_sockfd;
		receiver_addr = client_info_arrays[array_index].client_wifi_addr;
	}
	else
	{
		printf("[err] unkown CID: %d \n", linkCid);
		return;
	}
	//printf("control: %d, wifi: %d, lte: %d , send to: %d\n", g_vnic_ctl_sockfd, g_wifi_tunnel_sockfd, g_lte_tunnel_sockfd, vsock);

	ret = sendto(vsock, (char *)&ack_buf, ack_len + VIRTUAL_MESSAGE, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr));
	while (ret == -1 && ++t < 3) {
		usleep(1);
		ret = sendto(vsock, (char *)&ack_buf, ack_len + VIRTUAL_MESSAGE, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr));
	}
	if (ret < 0) {
		printf("[err] vnic_tun_send_ctl_ack, msg type: %d", msg[0]);
	}

	if (linkCid == WIFI_CID)
	{
		if (client_info_arrays[array_index].tfcmsg.flag == 1)
		{ //retransmit TSC message

			char send_buf[100];
			//set gma flag to 0, i.e., control msg
			struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
			*(u_short*)header->flag = 0;
			tfc_msg_header* tfc_req = (tfc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
			tfc_req->type = 0xFF;
			tfc_req->vendor_id = 0;
			tfc_req->sub_type = 6;
			tfc_req->flow_id = client_info_arrays[array_index].tfcmsg.flow_id;
			tfc_req->proto_type = client_info_arrays[array_index].tfcmsg.proto_type;
			tfc_req->port_start = client_info_arrays[array_index].tfcmsg.port_start;
			tfc_req->port_end = client_info_arrays[array_index].tfcmsg.port_end;
			printf("[TFC] array_index = %d, flow_id = %d, proto_type = %d, port_start = %d,  port_end = %d\n",
				array_index, tfc_req->flow_id, tfc_req->proto_type, ntohs(tfc_req->port_start), ntohs(tfc_req->port_end));
			int len = sizeof(tfc_msg_header) + VIRTUAL_MESSAGE;
			if (sendto(g_wifi_tunnel_sockfd, send_buf, len, 0, (struct sockaddr*)&client_info_arrays[array_index].client_wifi_addr, sizeof(client_info_arrays[array_index].client_wifi_addr)) == -1)
			 printf("g_wifi_tunnel_sockfd send failed \n");
		}
		if (client_info_arrays[array_index].tscmsg.flag == 1 && msg[0] != TSU_VNIC)
		{ //retransmit TFC message
			char send_buf[100];
			//set gma flag to 0, i.e., control msg
			struct virtual_message_header* header = (struct virtual_message_header*)send_buf;
			*(u_short*)header->flag = 0;

			tsc_msg_header* tsc_req = (tsc_msg_header*)(send_buf + VIRTUAL_MESSAGE);
			tsc_req->type = 0xFF;
			tsc_req->vendor_id = 0;
			tsc_req->sub_type = 4;
			tsc_req->len = htons(sizeof(tsc_msg_header));
			tsc_req->ul_duplication_enable = client_info_arrays[array_index].tscmsg.ul_duplication_enable;
			tsc_req->dl_dynamic_split_enable = client_info_arrays[array_index].tscmsg.dl_dynamic_split_enable;
			tsc_req->flow_id = client_info_arrays[array_index].tscmsg.flow_id;
			tsc_req->K1 = client_info_arrays[array_index].tscmsg.K1;
			tsc_req->K2 = client_info_arrays[array_index].tscmsg.K2;
			tsc_req->L1 = client_info_arrays[array_index].tscmsg.L1;
			printf("[TSC] array_index = %d, ul_duplication_enable = %d, dl_dynamic_split_enable = %d, K1 = %d,  K2 = %d, L = %d\n",
				array_index, tsc_req->ul_duplication_enable, tsc_req->dl_dynamic_split_enable, tsc_req->K1, tsc_req->K2, tsc_req->L1);
			int len = sizeof(tsc_msg_header) + VIRTUAL_MESSAGE;
			if (sendto(g_wifi_tunnel_sockfd, send_buf, len, 0, (struct sockaddr*)&client_info_arrays[array_index].client_wifi_addr, sizeof(client_info_arrays[array_index].client_wifi_addr)) == -1)
			 printf("g_wifi_tunnel_sockfd send failed \n");
		}
	}


END:
	;
}

void * vnic_tun_read_thread(void * lpParam)
{
	u_int n_Bytes = 0;
	while (g_bServerRun) {

		if (g_cManager->PrepareTxBuffer() == false)//not ready: buffer full
		{
			usleep(10);
		}
		else
		{
			n_Bytes = tun_read(tun.tun_fd, g_cManager->GetTxBuffer(), MAX_PACKET_SIZE);
			if (n_Bytes <= 0)
				continue;
			g_cManager->ProcessPacket(n_Bytes);
		}

	}
	return NULL;
}

int tun_server_init(void)
{
	char tun_setup[200];
	int i = 0;
	char tun_name[8] = "tun0";
		tun.tun_fd = tun_create(tun_name, IFF_TUN|IFF_NO_PI);
		if(tun.tun_fd < 0)
		{
			//close(tun.tun_fd);
			return -1;
		}
		else
		return 0;
}

//all address params is network order
bool config_tun_interface(u_char* tun_ip,
	u_char* tun_mask, u_int tun_mtu, const char* forward_interface)
{
	char conf[500] = { 0 };
	char ip[50] = { 0 };
	char mask[50] = { 0 };
	int mask_num = 0;
	char subnet[50] = { 0 };
	char tun_name[8] = "tun0";

	sprintf(ip, "%d.%d.%d.%d", tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3]);
	sprintf(mask, "%d.%d.%d.%d", tun_mask[0], tun_mask[1], tun_mask[2], tun_mask[3]);

	u_char net[4];
	*(u_int*)net = (*(u_int*)tun_ip) & (*(u_int*)tun_mask);
	sprintf(subnet, "%d.%d.%d.%d", net[0], net[1], net[2], net[3]);

	for (int i = 0, n = *(int*)tun_mask; i < 32; i++) {
		if ((n & 1) == 1) {
			++mask_num;
			n >>= 1;
		}
		else {
			break;
		}
	}
	printf("tun ip: %s, tun subnet: %s, tun mask_num: %d \n", ip, subnet, mask_num);

	memset(conf, 0, sizeof(conf));
	sprintf(conf, "ifconfig %s %s netmask %s up", tun_name, ip, mask);
	printf("tun config #1: %s \n", conf);
	popen_no_msg(conf, 500);

	memset(conf, 0, sizeof(conf));
	sprintf(conf, "ifconfig %s mtu %d\n", tun_name, tun_mtu);
	printf("tun config #2: %s", conf);
	popen_no_msg(conf, 500);

	memset(conf, 0, sizeof(conf));
	sprintf(conf, "iptables -I FORWARD -i %s -o %s -s %s/%d -m conntrack --ctstate NEW -j ACCEPT",
		tun_name, forward_interface, subnet, mask_num);
	printf("tun config #3: %s \n", conf);
	popen_no_msg(conf, 500);

	popen_no_msg("iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", 73);

	memset(conf, 0, sizeof(conf));
	sprintf(conf, "iptables -t nat -I POSTROUTING -o %s -s %s/%d -j MASQUERADE",
		forward_interface, subnet, mask_num);
	printf("tun config #4: %s \n", conf);
	popen_no_msg(conf, 500);

	if (pthread_create(&tun_server_read_tun_thread_id, NULL,
		vnic_tun_read_thread, NULL)) {
		close(tun.tun_fd);
		return false;
	}
	else {
		return true;
	}

}

void tun_server_exit(void)
{
		close(tun.tun_fd);
		tun.tun_fd = -1;
		popen_no_msg("ip link delete tun0", 20);
		pthread_cancel(tun_server_read_tun_thread_id);
}

int Roll_Over_Diff(int x, int y, int max) {
	int diff = x - y;
	if (diff > (max / 2)) {
		diff = diff - max;
	}
	else if (diff < -(max / 2)) {
		diff = diff + max;
	}
	return diff;
}

std::string popen_msg(const char* cmd, u_int size) {
	if(size > 500)
	{
		printf("[error] cmd too long: %s", cmd);
		return "cmd too long!";
	}
	else
	{
		char dst[501] = "";
		strncpy(dst, cmd, 500); /* OK ... but `dst` needs to be NUL terminated */
		dst[500] = '\0';
		printf("excute cmd: %s\n", dst);

		std::array<char, 128> buffer;
		std::string result;
		std::shared_ptr<FILE> pipe(popen(dst, "r"), pclose);
		if (!pipe) 
		{
			printf("popen failed!");
			return "popen failed!";
		}

		while (!feof(pipe.get())) {
			if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
				result += buffer.data();
		}
		return result;
	}
}

void popen_no_msg(const char* cmd, u_int size) {
	if(size > 500)
	{
		printf("[error] cmd too long: %s", cmd);
	}
	else
	{
		char dst[501] = "";
		strncpy(dst, cmd, 500); /* OK ... but `dst` needs to be NUL terminated */
      	dst[500] = '\0';
		printf("excute cmd: %s\n", dst);

		std::array<char, 128> buffer;
		std::string result;
		std::shared_ptr<FILE> pipe(popen(dst, "r"), pclose);
		if (!pipe) 
		{
			printf("popen failed!");
			return;
		}

		while (!feof(pipe.get())) {
			if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
				result += buffer.data();
		}
		if(!result.empty())
		{
			std::cout << result << "\n";
		}

	}
    
}
