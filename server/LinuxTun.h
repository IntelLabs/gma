//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : LinuxTun.h
//Description : c++ header file for Generic Multi-Access Network Virtualization

#ifndef _LINUX_TUN_H_
#define _LINUX_TUN_H_


#define DST_INDEX_IP_OFFSET	19

struct dl_tpt
{
	u_long	dl_lte_bytes;
	u_long	dl_fiveG_bytes;
};

struct tun_server
{
	int	tun_fd;
};

extern struct tun_server tun;



std::string popen_msg(const char* cmd, u_int size);
void popen_no_msg(const char* cmd, u_int size);

int tun_create(const char * dev, int flags);
int tun_write(int tun_fd, char * buff, int pkt_len);

int tun_server_init(void);

void tun_server_exit(void);

bool config_tun_interface(u_char *tun_ip, 
		          u_char *tun_mask, u_int tun_mtu, const char *forward_interface);
void vnic_tun_send_ctl_ack(struct sockaddr_in remote_addr, char *msg, int len);
int Roll_Over_Diff(int x, int y, int max);
#endif
