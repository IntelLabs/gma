//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : ReportHeader.h
//Description : c++ header file for Generic Multi-Access Network Virtualization
#pragma once

struct dl_measurement_prefix //mrp fixed msg field
{
	unsigned char  count;
	unsigned short time_stamp;
	unsigned short total_throughput;
	unsigned short max_dl_tx_rate_wifi;
	unsigned short max_dl_tx_rate_lte;
	char wifi_rssi;
	char lte_rssi;
	unsigned char last_rtt_wifi;
	unsigned char last_rtt_lte;
	unsigned char num_of_tsu_message;
	unsigned char reordering_timeout;
	unsigned char num_of_reordering_bufferoverflows;
	unsigned char num_link_failures_wifi;
	unsigned char num_link_failures_lte;
	char min_owd_difference;
	unsigned char flag; //first bit nrt, second bit rt.
}__attribute__((packed));

struct dl_measurement_opt //mor optional field, used by non-realtime or realtime
{
	unsigned short total_throughput;
	unsigned char wifi_throughput_ratio;
	char owd_range_wifi;
	char owd_range_lte;
	char average_owd_difference;
	char pack_loss_wifi;
	char pack_loss_lte;
	unsigned char out_of_order_packet_count_wifi;
	unsigned char out_of_order_packet_count_lte;
}__attribute__((packed));

struct dl_measurement_opt_v2 //mor optional field, used by non-realtime or realtime
{
	unsigned short total_throughput;
	unsigned char wifi_throughput_ratio;
	char owd_range_wifi;
	char owd_range_lte;
	char average_owd_difference;
	char pack_loss_wifi;
	char pack_loss_lte;
	unsigned char out_of_order_packet_count_wifi;
	unsigned char out_of_order_packet_count_lte;
	char owd_range_all;
	char pack_loss_all;
	char all_owd_difference;
}__attribute__((packed));


struct ul_measurement_prefix //urp info message
{
	unsigned short UE_index;
	unsigned short time_stamp;
	unsigned char num_of_output_bufferoverflows;
	unsigned char num_of_reordering_bufferoverflows;
	unsigned char reordering_timeout;
	unsigned char	flag; // bit 0: rt, bit 1: nrt, bit 2: hr
}__attribute__((packed));

struct ul_measurement_ext_a //urp extention format a: for nrt and rt flow
{
	unsigned short total_throughput;
	unsigned char  wifi_percent; //wifi/total*100
	char    ave_owd_diff; //wifi - lte
	char    wifi_owd_range; // max - min
	char	lte_owd_range; //max - min
	unsigned char  wifi_neg_log_loss; //-log(LRP)
	unsigned char  lte_neg_log_loss;//-log(LRP)
	unsigned char  wifi_outoforder;
	unsigned char lte_outoforder;
}__attribute__((packed));

struct ul_measurement_ext_b //urp extention format b: for nrt and rt flow
{
	unsigned short total_throughput;
	char    ave_owd_diff; //wifi - lte
	char    all_ave_owd_diff; //all - lte
	char    wifi_owd_range; // max - min
	char	lte_owd_range; //max - min
	char	all_owd_range; //max - min
	unsigned char  wifi_neg_log_loss; //-log(LRP)
	unsigned char  lte_neg_log_loss;//-log(LRP)
	unsigned char  all_neg_log_loss;//-log(LRP)
	unsigned char  wifi_outoforder;
	unsigned char lte_outoforder;
	unsigned char all_outoforder;//for realtime flow, the outoforder number is alreay 0, because it is dropped due to reordering

}__attribute__((packed));

struct server_measurement //srp
{
	unsigned short time_stamp;
	unsigned short num_of_active_clients_last;
	unsigned short num_of_active_clients_current_max;
	unsigned short num_of_active_clients_last_max;
	unsigned short dl_throughput_last;
	unsigned short dl_throughput_current_max;
	unsigned short dl_throughput_last_max;
	unsigned short ul_throughput_last;
	unsigned short ul_throughput_current_max;
	unsigned short ul_throughput_last_max;
	unsigned short total_throughput_last;
	unsigned short total_throughput_current_max;
	unsigned short total_throughput_last_max;
	unsigned char dl_wifi_ratio_last;
	unsigned char dl_wifi_ratio_current_average;
	unsigned char dl_wifi_ratio_last_average;
	unsigned char ul_wifi_ratio_last;
	unsigned char ul_wifi_ratio_current_average;
	unsigned char ul_wifi_ratio_last_average;
	unsigned char total_wifi_ratio_last;
	unsigned char total_wifi_ratio_current_average;
	unsigned char total_wifi_ratio_last_average;
	unsigned short num_of_dl_tx_ringbufferoverflow_last;
	unsigned short num_of_dl_tx_ringbufferoverflow_current_max;
	unsigned short num_of_dl_tx_ringbufferoverflow_last_max;
	unsigned short num_of_ul_rx_ringbufferoverflow_last;
	unsigned short num_of_ul_rx_ringbufferoverflow_current_max;
	unsigned short num_of_ul_rx_ringbufferoverflow_last_max;
	unsigned short num_of_ul_ue_rx_ringbufferoverflow_last;
	unsigned short num_of_ul_ue_rx_ringbufferoverflow_current_max;
	unsigned short num_of_ul_ue_rx_ringbufferoverflow_last_max;
}__attribute__((packed));

struct lrp_report
{
	unsigned short time_stamp;
	unsigned char bssid[6];
	unsigned char code;
}__attribute__((packed));

struct measure_report_to_winapp_header
{
	unsigned char  type;
	unsigned short UE_index;
}__attribute__((packed));

struct lte_wifi_ip
{
	int  lte_ip;
	int wifi_ip;
}__attribute__((packed));

struct winapp_ctl_msg
{
	unsigned int  key;
	unsigned int  flag;
}__attribute__((packed));

struct tsc_msg {
	unsigned int client_index;
	unsigned char UL_duplication_enabled;
	unsigned char DL_dynamic_Splitting_Enabled;
	unsigned char K1;
	unsigned char K2;
	unsigned char L1;
}__attribute__((packed));

struct tfc_msg {
	unsigned int client_index;
	unsigned char flow_id;
	unsigned char proto_type;
	unsigned short port_start;
	unsigned short port_end;
}__attribute__((packed));

struct txc_msg {
	unsigned int client_index;
	unsigned char link_id;
	unsigned int max_rate;
	unsigned int nrt_rate;
	unsigned int max_delay;
}__attribute__((packed));

#define CTL_MSG 8
#define TSC_MSG 9
#define TFC_MSG 10
#define TXC_MSG 17