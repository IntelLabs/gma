//Copyright(C) 2022 Intel Corporation
//SPDX-License-Identifier: Apache-2.0
//File : Setup1.h
//Description : c++ header file for Generic Multi-Access Network Virtualization
#pragma once

#define BUFFER_MAX_SIZE			1500
#define CONFIG_STR_MAX_LEN	100
#define CONFIG_STR_MAX_LEN2	200
#define IP_MAX_SIZE		20

#define STOP_FLAG  0
#define START_FLAG 1
#define UPDATE_CFG_FLAG 2
#define RESTART_FLAG 3

#define TSC_MESSAGE_REQ	29
#define TSC_MESSAGE_ACK	30
#define TXC_MESSAGE_REQ 37
#define TXC_MESSAGE_ACK 38
#define TFC_MESSAGE_REQ 39
#define TFC_MESSAGE_ACK 40

#define WINAPP_RESTART_ACK 42


#define MRP_REPORT 0
#define LRP_REPORT 1
#define URP_REPORT 2
#define SRP_REPORT 3
#define MRP_REPORT_V2 4

#define WIN_APP_KEY 1234

#ifdef __cplusplus
extern "C" {
#endif
#define CONFIG_FILE "Params_config.txt"


typedef enum CONFIG_INDEX
{
	SERVER_IP_INDEX,
	SERVER_PORT_INDEX,
	ROOT_LOCATION_INDEX,
	SEND_KEEP_ALIVE_TIME_INDEX,
	CSV_ENABLE_INDEX,
	END_INDEX
}CONFIG_INDEX;

#ifdef __cplusplus
}
#endif