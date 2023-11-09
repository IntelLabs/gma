#Copyright(C) 2022 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
#File : ncm_ws38.py
#Description: This script manages control message exchange 
#             for Generic Multi-Access Network Virtualization

import asyncio
import websockets
import websockets.legacy.server
import json
import ssl
import socket
import select
import configparser
import os
import threading
import netifaces as ni
from base64 import b64encode

from Cryptodome.Cipher import AES
import binascii
from Cryptodome.Random import get_random_bytes

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3

# ctx.set_ciphers("AES256-SHA")
ctx.set_ciphers("AES256-GCM-SHA384")
# ctx.load_verify_locations("server.crt")
# ctx.check_hostname = False
certfile = "server.crt"
keyfile = "server.key"
ctx.load_cert_chain(certfile, keyfile)  # , password=None)
# global config
    
'''
MXCapabilityReq = { 'version':'1.0',
                    'message_type':'mx_capability_req',
                    'FeatureActive':[{'feature_name':'fragmentation', 'active':'yes'},
                                     {'feature_name':'lossless_switching', 'active':'yes'}],
                    'num_anchor_connections':1,
                    'anchor_connections':[{'connection_id':0, 'connection_type':'lte'}],
                    'num_delivery_connections':1,
                    'delivery_connections':[{'connection_id':1, 'connection_type':"wifi"}],
                    'convergence_methods':[{'method':'trailer_based', 'supported':'true'}],
                    'adaptation_methods':[{'method':'client_nat', 'supported':'false'}]
}
'''


def jsonMsg_init(path):
    with open(path, 'r', encoding='utf8') as f:
        msgs = json.load(f)

    # global MX_Discover_Msg
    global MX_Capability_Req_Msg
    global MX_System_Update_Msg
    global MX_Capability_Rsp_Msg
    global MX_Capability_ACK_Msg
    global MX_LTE_Reconfig_Req_Msg
    global MX_LTE_Reconfig_Rsp_Msg
    global MX_Wifi_Reconfig_Req_Msg
    global MX_Wifi_Reconfig_Rsp_Msg
    global MX_UP_Setup_Config_Req_Msg
    global MX_UP_Setup_Confirm_Msg
    global MX_Session_Resume_Rsp
    global MX_Test_Ack
    global MX_Session_Suspend_Rsp
    global MX_Session_Termination_Rsp
    global MX_GMA_Wifi_List
    global MX_Qos_Flow_Conf
    global MX_Gma_Client_Conf

    global MX_Measure_Config_Msg
    global MX_Measure_Report_Msg

    global Set_LTE_Anchor_Msg
    global Set_WiFi_Anchor_Msg
    global Set_VNIC_Anchor_Msg

    global Create_Client_Req_Msg
    global WiFi_Link_Up_Msg
    global WiFi_Link_Down_Msg
    global LTE_Link_Up_Msg
    global LTE_Link_Down_Msg
    global Client_Suspend_Begin_Req
    global Client_Suspend_Stop_Req
    global Client_Resume_Req
    global Tun_Setup_Req
    global LTE_Switch_To_WiFi_Rsp_Msg
    global WiFi_Switch_To_LTE_Rsp_Msg
    global Reordering_On_Rsp_Msg
    global Reordering_Off_Rsp_Msg
    global Close_Client_Req_Msg
    global User_Plan_Setup_Cnf

    global g_meas_on
    global ws
    global last_ip_address

    global client_info_index
    global client_ip_index
    global ip_address_index
    global session_id_index
    global aes_key_index
    global websockets_connection_index

    global sn_num_arrays_begin
    global sn_num_arrays_end

    global TSC_MSG_REQ
    global TXC_MSG_REQ
    global TFC_MSG_REQ
    global CCU_MSG_REQ
    global SCU_MSG_REQ
    global ws_array_index_dict

    global SERVER_AESKEY_REQ
    global SERVER_AESKEY_LEN
    global server_aeskey

    last_ip_address = ""
    g_meas_on = False
    ws = None

    MX_System_Update_Msg = msgs['MX_System_Update']
    MX_Capability_Rsp_Msg = msgs['MX_Capability_Response']

    MX_LTE_Reconfig_Rsp_Msg = msgs['MX_Reconfiguration_Response'][0]
    MX_Wifi_Reconfig_Rsp_Msg = msgs['MX_Reconfiguration_Response'][1]

    MX_UP_Setup_Config_Req_Msg = msgs['MX_UP_Setup_Configuration_Request']

    MX_Measure_Config_Msg = msgs['MX_Measurements_Configuration']

    MX_Session_Resume_Rsp = msgs['MX_Session_Resume_Rsp']
    MX_Test_Ack = msgs['MX_Test_Ack']
    MX_Session_Suspend_Rsp = msgs['MX_Session_Suspend_Rsp']
    MX_Session_Termination_Rsp = msgs['MX_Session_Termination_Rsp']
    MX_GMA_Wifi_List = msgs['MX_GMA_Wifi_List']
    MX_Qos_Flow_Conf = msgs['MX_Qos_Flow_Conf']
    MX_Gma_Client_Conf = msgs['MX_Gma_Client_Conf']

    Set_LTE_Anchor_Msg = b'\x0d\x00\x00\x12\x00\x00\x00'
    Set_WiFi_Anchor_Msg = b'\x0d\x00\x00\x12\x00\x00\x01'
    Set_VNIC_Anchor_Msg = b'\x0d\x00\x00\x12\x00\x00\x02'

    Create_Client_Req_Msg = b'\x0c\x00\x00\x13\x00\x00'

    '''byte 2 is the flag, to indicate wifi link up(1) or down(0)'''
    WiFi_Link_Up_Msg = b'\x0c\x00\x01\x03\x00\x00'
    WiFi_Link_Down_Msg = b'\x0c\x00\x00\x03\x00\x00'

    LTE_Link_Up_Msg = b'\x0c\x00\x01\x17\x00\x00'
    LTE_Link_Down_Msg = b'\x0c\x00\x00\x17\x00\x00'

    Client_Suspend_Begin_Req = b'\x06\x00\x01\x1a\x00\x00'
    Client_Suspend_Stop_Req = b'\x06\x00\x00\x1a\x00\x00'
    Client_Resume_Req = b'\x06\x00\x00\x1c\x00\x00'

    Tun_Setup_Req = b'\x16\x00\x00\x1b\x00\x00'

    WiFi_Switch_To_LTE_Rsp_Msg = b'\x06\x00\x00\x08\x00\x00'
    LTE_Switch_To_WiFi_Rsp_Msg = b'\x06\x00\x00\x0a\x00\x00'
    Reordering_On_Rsp_Msg = b'\x06\x00\x00\x0f\x00\x00'
    Reordering_Off_Rsp_Msg = b'\x06\x00\x00\x0f\x00\x00'
    Close_Client_Req_Msg = b'\x06\x00\x00\x15\x00\x00'
    User_Plan_Setup_Cnf = b'\x0d\x00\x00\x16\x00\x00'

    TSC_MSG_REQ = b'\x0f\x00\x00\x1d\x00\x00'
    TXC_MSG_REQ = b'\x15\x00\x00\x25\x00\x00'
    TFC_MSG_REQ = b'\x15\x00\x00\x27\x00\x00'
    CCU_MSG_REQ = b'\xe6\x00\x00\x1f\x00\x00'
    SCU_MSG_REQ = b'\x26\x00\x00\x21\x00\x00'

    SERVER_AESKEY_REQ = b'\x06\x00\x00\x29\x00\x00'
    SERVER_AESKEY_LEN = 32

    client_info_index = 0
    client_ip_index = 0
    ip_address_index = 1
    session_id_index = 2
    websockets_connection_index = 3
    aes_key_index = 4
    '''
                         |client_ip_index  | vnic_ip | session_id | websocket connection | aes_key ....
    client               |                 |         |            |						 |
    client               |                 |         |            |                      |
    client               |                 |         |            |                      |
    client               |                 |         |            |                      |
    '''
    sn_num_arrays_begin = 0
    sn_num_arrays_end = 0
    ws_array_index_dict = dict()


'''get unique session id'''


def get_session_id(msg):
    return msg['unique_session_id']['session_id']


'''add client index to rsv bytes'''


def add_index(msg, index):
    msg_list = list(msg)
    msg_list[4] = index[1]
    msg_list[5] = index[0]
    msg = bytes(msg_list)
    return msg


def get_attr(msg, attr):
    if attr in msg.keys():
        return msg[attr]
    else:
        return None


def udp_init(out_ip, out_port, in_ip, in_port):
    try:
        # global sock_send
        global sock_recv

        global local_in
        global local_out

        local_out = (out_ip, out_port)
        local_in = (in_ip, in_port)

        # sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # make socket reuseble
        # sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Allow incoming broadcasts
        sock_recv.setblocking(0)
        sock_recv.bind(local_in)

    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] udp_init')


def udp_release():
    try:
        # sock_send.close()
        sock_recv.close()
    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] udp_release')


def sendto_server(msg):
    try:
        # sock_send.sendto(msg, local_out)
        # sock_recv.sendto(msg, local_out)
        iv = get_random_bytes(12)
        aesCipher = AES.new(server_aeskey, AES.MODE_GCM, mac_len=16, nonce=iv)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        iv = aesCipher.nonce
        encrypted_msg = ciphertext + authTag + iv

        sock_recv.sendto(encrypted_msg, local_out)

    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] SendToGMAClient:' + msg)


def type_match(recvMsg, msgType):
    '''
    recvMsg type is a dict, msgType is a string.
    '''
    if 'message_type' in recvMsg.keys():
        if recvMsg['message_type'] == msgType:
            print('Recieved message:{}'.format(recvMsg['message_type']))
            return True
        else:
            return False
    else:
        return False


def create_req_sn():
    global sn_num_arrays_end
    global sn_num_arrays_begin

    sn_num_arrays_end = (sn_num_arrays_end + 1) % max_client_num
    sn_num_arrays_begin = sn_num_arrays_end

    while sn_num_arrays[sn_num_arrays_end] != 0:
        sn_num_arrays_end = (sn_num_arrays_end + 1) % max_client_num
        if sn_num_arrays_end == sn_num_arrays_begin:
            return -1

    return sn_num_arrays_end


def send_key_req():
    global server_aeskey
    try:
        print('[NCM->Server] udp socket aeskey req')
        server_aeskey = get_random_bytes(SERVER_AESKEY_LEN)
        print("Key length is " + str(SERVER_AESKEY_LEN))
        aeskey_req_msg = SERVER_AESKEY_REQ + server_aeskey
        sock_recv.sendto(aeskey_req_msg, local_out)
        sock_recv.settimeout(10.0)
        msg = sock_recv.recv(SERVER_AESKEY_LEN)
        print("[Server->NCM] aes-key ack")
        if (server_aeskey == msg):
            print("[Server->NCM] aes-key verified success!")
        else:
            print("[error] aes-key verified failed!!!")
    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] server udp socket aeskey req')

def load_config():
    config.read('/home/ncm_ws/conf.ini')
    max_client_num = int(config['SERVER_PARAMETERS']['MAX_CLIENT_NUM'])
    rows, cols = (max_client_num, 5)
    client_info_arrays = [[0 for i in range(cols)] for j in range(rows)]
    sn_num_arrays = [0 for i in range(rows)]
    

def send_build_tun_req():
    try:
        split_symbol = ';'
        WLAN_INTERFACE_CONFIG = config['SERVER_PARAMETERS']['WLAN_INTERFACE_CONFIG']
        LTE_INTERFACE_CONFIG = config['SERVER_PARAMETERS']['LTE_INTERFACE_CONFIG']
        FORWARD_INTERFACE_CONFIG = config['SERVER_PARAMETERS']['FORWARD_INTERFACE_CONFIG']
        LTE_INTERFACE_MTU_CONFIG = config['SERVER_PARAMETERS']['LTE_INTERFACE_MTU_CONFIG']
        WLAN_INTERFACE_MTU_CONFIG = config['SERVER_PARAMETERS']['WLAN_INTERFACE_MTU_CONFIG']
        VNIC_INTERFACE_MTU_CONFIG = config['SERVER_PARAMETERS']['VNIC_INTERFACE_MTU_CONFIG']
        WIFI_INTERFACE_IP_ADDRESS = config['SERVER_PARAMETERS']['WIFI_INTERFACE_IP_ADDRESS']
        WIFI_INTERFACE_IP_PPORT = config['SERVER_PARAMETERS']['WIFI_INTERFACE_IP_PPORT']
        LTE_INTERFACE_IP_ADDRESS = config['SERVER_PARAMETERS']['LTE_INTERFACE_IP_ADDRESS']
        LTE_INTERFACE_IP_PORT = config['SERVER_PARAMETERS']['LTE_INTERFACE_IP_PORT']
        SERVER_VNIC_IP = config['SERVER_PARAMETERS']['SERVER_VNIC_IP']
        SERVER_VNIC_GW = config['SERVER_PARAMETERS']['SERVER_VNIC_GW']
        SERVER_VNIC_MSK = config['SERVER_PARAMETERS']['SERVER_VNIC_MSK']
        SERVER_VNIC_DNS = config['SERVER_PARAMETERS']['SERVER_VNIC_DNS']
        UDP_PORT = config['SERVER_PARAMETERS']['UDP_PORT']
        TCP_PORT = config['SERVER_PARAMETERS']['TCP_PORT']
        MAX_KEEP_CLIENT_TIME = config['SERVER_PARAMETERS']['MAX_KEEP_CLIENT_TIME']
        MAX_CLIENT_NUM = config['SERVER_PARAMETERS']['MAX_CLIENT_NUM']
        MAX_TX_BUFFER_SIZE_CONFIG = config['SERVER_PARAMETERS']['MAX_TX_BUFFER_SIZE_CONFIG']
        MAX_RX_BUFFER_SIZE_CONFIG = config['SERVER_PARAMETERS']['MAX_RX_BUFFER_SIZE_CONFIG']
        CLIENT_RX_BUFFER_SIZE_CONFIG = config['SERVER_PARAMETERS']['CLIENT_RX_BUFFER_SIZE_CONFIG']
        REORDERING_TIMEOUT_CONFIG = config['SERVER_PARAMETERS']['REORDERING_TIMEOUT_CONFIG']
        WIFI_RATE_MBPS_CONFIG = config['SERVER_PARAMETERS']['WIFI_RATE_MBPS_CONFIG']
        WIFI_NRT_RATE_MBPS_CONFIG = config['SERVER_PARAMETERS']['WIFI_NRT_RATE_MBPS_CONFIG']
        WIFI_DELAY_MS_CONFIG = config['SERVER_PARAMETERS']['WIFI_DELAY_MS_CONFIG']
        LTE_RATE_MBPS_CONFIG = config['SERVER_PARAMETERS']['LTE_RATE_MBPS_CONFIG']
        LTE_NRT_RATE_MBPS_CONFIG = config['SERVER_PARAMETERS']['LTE_NRT_RATE_MBPS_CONFIG']
        LTE_DELAY_MS_CONFIG = config['SERVER_PARAMETERS']['LTE_DELAY_MS_CONFIG']
        MAX_RATE_MBPS_CONFIG = config['SERVER_PARAMETERS']['MAX_RATE_MBPS_CONFIG']
        SLEEP_TIME_UNIT_US_CONFIG = config['SERVER_PARAMETERS']['SLEEP_TIME_UNIT_US_CONFIG']
        PKT_BURST_SIZE_KB_CONFIG = config['SERVER_PARAMETERS']['PKT_BURST_SIZE_KB_CONFIG']
        MEASURE_INTERVAL_S_CONFIG = config['SERVER_PARAMETERS']['MEASURE_INTERVAL_S_CONFIG']
        SERVER_REPORT_CYCLE_CONFIG = config['SERVER_PARAMETERS']['SERVER_REPORT_CYCLE_CONFIG']
        ENABLE_DL_QOS_CONFIG = config['SERVER_PARAMETERS']['ENABLE_DL_QOS_CONFIG']
        ENABLE_MEASUREMENT_CONFIG = config['SERVER_PARAMETERS']['ENABLE_MEASUREMENT_CONFIG']
        ENABLE_MEASURE_REPORT_CONFIG = config['SERVER_PARAMETERS']['ENABLE_MEASURE_REPORT_CONFIG']
        ENABLE_UL_REORDERING_CONFIG = config['SERVER_PARAMETERS']['ENABLE_UL_REORDERING_CONFIG']
        ENABLE_UL_ENCRYPT_CONFIG = config['SERVER_PARAMETERS']['ENABLE_UL_ENCRYPT_CONFIG']
        WIFI_WAKEUP_TIMEOUT_S_CONFIG = config['SERVER_PARAMETERS']['WIFI_WAKEUP_TIMEOUT_S_CONFIG']
        LTE_WAKEUP_TIMEOUT_S_CONFIG = config['SERVER_PARAMETERS']['LTE_WAKEUP_TIMEOUT_S_CONFIG']
        WIFI_TCP_KEEP_ALIVE_S_CONFIG = config['SERVER_PARAMETERS']['WIFI_TCP_KEEP_ALIVE_S_CONFIG']
        LTE_TCP_KEEP_ALIVE_S_CONFIG = config['SERVER_PARAMETERS']['LTE_TCP_KEEP_ALIVE_S_CONFIG']
        MEASURE_REPORT_PORT = config['SERVER_PARAMETERS']['MEASURE_REPORT_PORT']
        MEASURE_REPORT_NIC = config['SERVER_PARAMETERS']['MEASURE_REPORT_NIC']
        RT_FLOW_DSCP = config['SERVER_PARAMETERS']['RT_FLOW_DSCP']
        HR_FLOW_DSCP = config['SERVER_PARAMETERS']['HR_FLOW_DSCP']
        
        config_list = split_symbol + WLAN_INTERFACE_CONFIG + split_symbol + \
                      LTE_INTERFACE_CONFIG + split_symbol + \
                      FORWARD_INTERFACE_CONFIG + split_symbol + \
                      LTE_INTERFACE_MTU_CONFIG + split_symbol + \
                      WLAN_INTERFACE_MTU_CONFIG + split_symbol + \
                      VNIC_INTERFACE_MTU_CONFIG + split_symbol + \
                      WIFI_INTERFACE_IP_ADDRESS + split_symbol + \
                      WIFI_INTERFACE_IP_PPORT + split_symbol + \
                      LTE_INTERFACE_IP_ADDRESS + split_symbol + \
                      LTE_INTERFACE_IP_PORT + split_symbol + \
                      SERVER_VNIC_IP + split_symbol + \
                      SERVER_VNIC_GW + split_symbol + \
                      SERVER_VNIC_MSK + split_symbol + \
                      SERVER_VNIC_DNS + split_symbol + \
                      UDP_PORT + split_symbol + \
                      TCP_PORT + split_symbol + \
                      MAX_KEEP_CLIENT_TIME + split_symbol + \
                      MAX_CLIENT_NUM + split_symbol + \
                      MAX_TX_BUFFER_SIZE_CONFIG + split_symbol + \
                      MAX_RX_BUFFER_SIZE_CONFIG + split_symbol + \
                      CLIENT_RX_BUFFER_SIZE_CONFIG + split_symbol + \
                      REORDERING_TIMEOUT_CONFIG + split_symbol + \
                      WIFI_RATE_MBPS_CONFIG + split_symbol + \
                      WIFI_NRT_RATE_MBPS_CONFIG + split_symbol + \
                      WIFI_DELAY_MS_CONFIG + split_symbol + \
                      LTE_RATE_MBPS_CONFIG + split_symbol + \
                      LTE_NRT_RATE_MBPS_CONFIG + split_symbol + \
                      LTE_DELAY_MS_CONFIG + split_symbol + \
                      MAX_RATE_MBPS_CONFIG + split_symbol + \
                      SLEEP_TIME_UNIT_US_CONFIG + split_symbol + \
                      PKT_BURST_SIZE_KB_CONFIG + split_symbol + \
                      MEASURE_INTERVAL_S_CONFIG + split_symbol + \
                      SERVER_REPORT_CYCLE_CONFIG + split_symbol + \
                      ENABLE_DL_QOS_CONFIG + split_symbol + \
                      ENABLE_MEASUREMENT_CONFIG + split_symbol + \
                      ENABLE_MEASURE_REPORT_CONFIG + split_symbol + \
                      ENABLE_UL_REORDERING_CONFIG + split_symbol + \
                      ENABLE_UL_ENCRYPT_CONFIG + split_symbol + \
                      WIFI_WAKEUP_TIMEOUT_S_CONFIG + split_symbol + \
                      LTE_WAKEUP_TIMEOUT_S_CONFIG + split_symbol + \
                      WIFI_TCP_KEEP_ALIVE_S_CONFIG + split_symbol + \
                      LTE_TCP_KEEP_ALIVE_S_CONFIG + split_symbol + \
                      MEASURE_REPORT_PORT + split_symbol + \
                      MEASURE_REPORT_NIC + split_symbol + \
					  RT_FLOW_DSCP + split_symbol + \
 					  HR_FLOW_DSCP + split_symbol
					  
        tun_setup_req = Tun_Setup_Req + config_list.encode('utf-8')
        print('[NCM->Server] tun setup req')
        print(tun_setup_req)
        sendto_server(tun_setup_req)
    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] send build tun msg:' + msg)


class read_from_keyboard(threading.Thread):
    def run(self):
        try:
            while 1:
                input_str = input()
                input_list = input_str.split()
                if input_list[0] == "tsc":
                    if len(input_list) == 7:
                        client_index = int(input_list[1]).to_bytes(4, 'little')
                        UL_duplication_enabled = int(input_list[2]).to_bytes(1, 'little')
                        DL_Dynamic_Splitting_Enabled = int(input_list[3]).to_bytes(1, 'little')
                        K1 = int(input_list[4]).to_bytes(1, 'little')
                        K2 = int(input_list[5]).to_bytes(1, 'little')
                        L1 = int(input_list[6]).to_bytes(1, 'little')

                        tsc_msg_req = TSC_MSG_REQ + \
                                      client_index + \
                                      UL_duplication_enabled + \
                                      DL_Dynamic_Splitting_Enabled + \
                                      K1 + \
                                      K2 + \
                                      L1
                        sendto_server(tsc_msg_req)
                        print("send tsc req")
                    else:
                        print("Wrong format, e.g., [tsc clientIndex ulDupEnabled dlDynamicSplitEnabled K1 K2 L1]")
                elif input_list[0] == "tfc":
                    if len(input_list) == 6:
                        client_index = int(input_list[1]).to_bytes(4, 'little')
                        flow_id = int(input_list[2]).to_bytes(1, 'little')
                        proto_type = int(input_list[3]).to_bytes(1, 'little')
                        port_start = int(input_list[4]).to_bytes(2, 'little')
                        port_end = int(input_list[5]).to_bytes(2, 'little')

                        tfc_msg_req = TFC_MSG_REQ + \
                                      client_index + \
                                      flow_id + \
                                      proto_type + \
                                      port_start + \
                                      port_end
                        sendto_server(tfc_msg_req)
                        print("send tfc req")
                    else:
                        print(
                            "Wrong format, e.g., [tfc clientIndex flowId(1: HR, 2: RT, 3: NRT) protoType(0:disable, 1: tcp, 2: udp,  3: ICMP) portStart(0~65535) portEnd(0~65535)]")
                elif input_list[0] == "txc":
                    if len(input_list) == 6:
                        if int(input_list[3]) <= 0 or int(input_list[4]) <= 0 or int(input_list[3]) <= int(
                            input_list[4]) or int(input_list[5]) <= 0:
                            print("Wrong rate configuration, all rate and delay should be greater than 0!!")
                            continue

                        client_index = int(input_list[1]).to_bytes(4, 'little')
                        link_id = int(input_list[2]).to_bytes(1, 'little')
                        max_rate = int(input_list[3]).to_bytes(4, 'little')
                        nrt_rate = int(input_list[4]).to_bytes(4, 'little')
                        max_delay = int(input_list[5]).to_bytes(4, 'little')

                        txc_msg_req = TXC_MSG_REQ + \
                                      client_index + \
                                      link_id + \
                                      max_rate + \
                                      nrt_rate + \
                                      max_delay
                        sendto_server(txc_msg_req)
                        print("send txc req")
                    else:
                        print("Wrong format, e.g., [txc clientIndex linkId maxRate nrtRate maxDelay]")
                elif input_list[0] == "ccu" and len(input_list) == 3:
                    confiure_file = input_list[2]
                    if not os.path.exists(confiure_file):
                        print("not this configure file")
                        continue

                    new_config = configparser.ConfigParser()
                    new_config.read(confiure_file)
                    # configure client parameters
                    network_interface_minMTU = int(new_config['CLIENT_PARAMETERS']['network_interface_minMTU'])
                    dynamic_split_flag = int(new_config['CLIENT_PARAMETERS']['dynamic_split_flag'])
                    Lte_always_on_flag = int(new_config['CLIENT_PARAMETERS']['Lte_always_on_flag'])
                    congest_detect_loss_threshold = int(
                        new_config['CLIENT_PARAMETERS']['congest_detect_loss_threshold'])
                    congest_detect_utilization_threshold = int(
                        new_config['CLIENT_PARAMETERS']['congest_detect_utilization_threshold'])
                    lte_probe_interval_screen_off = int(
                        new_config['CLIENT_PARAMETERS']['lte_probe_interval_screen_off'])
                    lte_probe_interval_screen_on = int(new_config['CLIENT_PARAMETERS']['lte_probe_interval_screen_on'])
                    lte_probe_interval_active = int(new_config['CLIENT_PARAMETERS']['lte_probe_interval_active'])
                    lte_rssi_measurement = int(new_config['CLIENT_PARAMETERS']['lte_rssi_measurement'])
                    wifi_probe_interval_screen_off = int(
                        new_config['CLIENT_PARAMETERS']['wifi_probe_interval_screen_off'])
                    wifi_probe_interval_screen_on = int(
                        new_config['CLIENT_PARAMETERS']['wifi_probe_interval_screen_on'])
                    wifi_probe_interval_active = int(new_config['CLIENT_PARAMETERS']['wifi_probe_interval_active'])
                    param_l = int(new_config['CLIENT_PARAMETERS']['param_l'])
                    wifi_low_rssi = int(new_config['CLIENT_PARAMETERS']['wifi_low_rssi']) & 0xFFFFFFFF
                    wifi_high_rssi = int(new_config['CLIENT_PARAMETERS']['wifi_high_rssi']) & 0xFFFFFFFF
                    MRP_interval_active = int(new_config['CLIENT_PARAMETERS']['MRP_interval_active'])
                    MRP_interval_idle = int(new_config['CLIENT_PARAMETERS']['MRP_interval_idle'])
                    MRP_size = int(new_config['CLIENT_PARAMETERS']['MRP_size'])
                    max_reordering_delay = int(new_config['CLIENT_PARAMETERS']['max_reordering_delay'])
                    min_reordering_delay = int(new_config['CLIENT_PARAMETERS']['min_reordering_delay'])
                    reorder_buffer_size = int(new_config['CLIENT_PARAMETERS']['reorder_buffer_size'])
                    reorder_Lsn_enhance_flag = int(new_config['CLIENT_PARAMETERS']['reorder_Lsn_enhance_flag'])
                    reorder_drop_out_of_order_pkt = int(
                        new_config['CLIENT_PARAMETERS']['reorder_drop_out_of_order_pkt'])
                    min_tpt = int(new_config['CLIENT_PARAMETERS']['min_tpt'])
                    idle_timer = int(new_config['CLIENT_PARAMETERS']['idle_timer'])
                    allow_app_list_enable = int(new_config['CLIENT_PARAMETERS']['allow_app_list_enable'])
                    wifi_owd_offset = int(new_config['CLIENT_PARAMETERS']['wifi_owd_offset'])
                    ul_duplicate_flag = int(new_config['CLIENT_PARAMETERS']['ul_duplicate_flag'])

                    OWD_CONVERGE_THRESHOLD = int(new_config['CLIENT_PARAMETERS']['OWD_CONVERGE_THRESHOLD'])
                    MAX_MEASURE_INTERVAL_NUM = int(new_config['CLIENT_PARAMETERS']['MAX_MEASURE_INTERVAL_NUM'])
                    MIN_PACKET_NUM_PER_INTERVAL = int(new_config['CLIENT_PARAMETERS']['MIN_PACKET_NUM_PER_INTERVAL'])
                    MAX_MEASURE_INTERVAL_DURATION = int(
                        new_config['CLIENT_PARAMETERS']['MAX_MEASURE_INTERVAL_DURATION'])
                    MIN_MEASURE_INTERVAL_DURATION = int(
                        new_config['CLIENT_PARAMETERS']['MIN_MEASURE_INTERVAL_DURATION'])
                    BURST_SAMPLE_FREQUENCY = int(new_config['CLIENT_PARAMETERS']['BURST_SAMPLE_FREQUENCY'])
                    MAX_RATE_ESTIMATE = int(new_config['CLIENT_PARAMETERS']['MAX_RATE_ESTIMATE'])
                    RATE_ESTIMATE_K = int(new_config['CLIENT_PARAMETERS']['RATE_ESTIMATE_K'])
                    MIN_PACKET_COUNT_PER_BURST = int(new_config['CLIENT_PARAMETERS']['MIN_PACKET_COUNT_PER_BURST'])
                    BURST_INCREASING_ALPHA = int(new_config['CLIENT_PARAMETERS']['BURST_INCREASING_ALPHA'])
                    STEP_ALPHA_THRESHOLD = int(new_config['CLIENT_PARAMETERS']['STEP_ALPHA_THRESHOLD'])
                    TOLERANCE_LOSS_BOUND = int(new_config['CLIENT_PARAMETERS']['TOLERANCE_LOSS_BOUND'])
                    TOLERANCE_DELAY_BOUND = int(new_config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_BOUND'])
                    TOLERANCE_DELAY_H = int(new_config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_H'])
                    TOLERANCE_DELAY_L = int(new_config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_L'])
                    SPLIT_ALGORITHM = int(new_config['CLIENT_PARAMETERS']['SPLIT_ALGORITHM'])
                    INITIAL_PACKETS_BEFORE_LOSS = int(new_config['CLIENT_PARAMETERS']['INITIAL_PACKETS_BEFORE_LOSS'])
                    icmp_flow_type = int(new_config['CLIENT_PARAMETERS']['icmp_flow_type'])
                    tcp_rt_port_start = int(new_config['CLIENT_PARAMETERS']['tcp_rt_port_start'])
                    tcp_rt_port_end = int(new_config['CLIENT_PARAMETERS']['tcp_rt_port_end'])
                    tcp_hr_port_start = int(new_config['CLIENT_PARAMETERS']['tcp_hr_port_start'])
                    tcp_hr_port_end = int(new_config['CLIENT_PARAMETERS']['tcp_hr_port_end'])
                    udp_rt_port_start = int(new_config['CLIENT_PARAMETERS']['udp_rt_port_start'])
                    udp_rt_port_end = int(new_config['CLIENT_PARAMETERS']['udp_rt_port_end'])
                    udp_hr_port_start = int(new_config['CLIENT_PARAMETERS']['udp_hr_port_start'])
                    udp_hr_port_end = int(new_config['CLIENT_PARAMETERS']['udp_hr_port_end'])
                    ul_qos_flow_enable = int(new_config['CLIENT_PARAMETERS']['ul_qos_flow_enable'])

                    client_index = int(input_list[1])
                    ccu_msg_req = CCU_MSG_REQ + client_index.to_bytes(4, 'little') + \
                                  network_interface_minMTU.to_bytes(4, 'little') + \
                                  dynamic_split_flag.to_bytes(4, 'little') + \
                                  Lte_always_on_flag.to_bytes(4, 'little') + \
                                  congest_detect_loss_threshold.to_bytes(4, 'little') + \
                                  congest_detect_utilization_threshold.to_bytes(4, 'little') + \
                                  lte_probe_interval_screen_off.to_bytes(4, 'little') + \
                                  lte_probe_interval_screen_on.to_bytes(4, 'little') + \
                                  lte_probe_interval_active.to_bytes(4, 'little') + \
                                  lte_rssi_measurement.to_bytes(4, 'little') + \
                                  wifi_probe_interval_screen_off.to_bytes(4, 'little') + \
                                  wifi_probe_interval_screen_on.to_bytes(4, 'little') + \
                                  wifi_probe_interval_active.to_bytes(4, 'little') + \
                                  param_l.to_bytes(4, 'little') + \
                                  wifi_low_rssi.to_bytes(4, 'little') + \
                                  wifi_high_rssi.to_bytes(4, 'little') + \
                                  MRP_interval_active.to_bytes(4, 'little') + \
                                  MRP_interval_idle.to_bytes(4, 'little') + \
                                  MRP_size.to_bytes(4, 'little') + \
                                  max_reordering_delay.to_bytes(4, 'little') + \
                                  min_reordering_delay.to_bytes(4, 'little') + \
                                  reorder_buffer_size.to_bytes(4, 'little') + \
                                  reorder_Lsn_enhance_flag.to_bytes(4, 'little') + \
                                  reorder_drop_out_of_order_pkt.to_bytes(4, 'little') + \
                                  min_tpt.to_bytes(4, 'little') + \
                                  idle_timer.to_bytes(4, 'little') + \
                                  allow_app_list_enable.to_bytes(4, 'little') + \
                                  wifi_owd_offset.to_bytes(4, 'little') + \
                                  ul_duplicate_flag.to_bytes(4, 'little') + \
                                  OWD_CONVERGE_THRESHOLD.to_bytes(4, 'little') + \
                                  MAX_MEASURE_INTERVAL_NUM.to_bytes(4, 'little') + \
                                  MIN_PACKET_NUM_PER_INTERVAL.to_bytes(4, 'little') + \
                                  MAX_MEASURE_INTERVAL_DURATION.to_bytes(4, 'little') + \
                                  MIN_MEASURE_INTERVAL_DURATION.to_bytes(4, 'little') + \
                                  BURST_SAMPLE_FREQUENCY.to_bytes(4, 'little') + \
                                  MAX_RATE_ESTIMATE.to_bytes(4, 'little') + \
                                  RATE_ESTIMATE_K.to_bytes(4, 'little') + \
                                  MIN_PACKET_COUNT_PER_BURST.to_bytes(4, 'little') + \
                                  BURST_INCREASING_ALPHA.to_bytes(4, 'little') + \
                                  STEP_ALPHA_THRESHOLD.to_bytes(4, 'little') + \
                                  TOLERANCE_LOSS_BOUND.to_bytes(4, 'little') + \
                                  TOLERANCE_DELAY_BOUND.to_bytes(4, 'little') + \
                                  TOLERANCE_DELAY_H.to_bytes(4, 'little') + \
                                  TOLERANCE_DELAY_L.to_bytes(4, 'little') + \
                                  SPLIT_ALGORITHM.to_bytes(4, 'little') + \
                                  INITIAL_PACKETS_BEFORE_LOSS.to_bytes(4, 'little') + \
                                  icmp_flow_type.to_bytes(4, 'little') + \
                                  tcp_rt_port_start.to_bytes(4, 'little') + \
                                  tcp_rt_port_end.to_bytes(4, 'little') + \
                                  tcp_hr_port_start.to_bytes(4, 'little') + \
                                  tcp_hr_port_end.to_bytes(4, 'little') + \
                                  udp_rt_port_start.to_bytes(4, 'little') + \
                                  udp_rt_port_end.to_bytes(4, 'little') + \
                                  udp_hr_port_start.to_bytes(4, 'little') + \
                                  udp_hr_port_end.to_bytes(4, 'little') + \
                                  ul_qos_flow_enable.to_bytes(4, 'little')

                    sendto_server(ccu_msg_req)
                    print("send ccu req")
                elif input_list[0] == "scu" and len(input_list) == 2:
                    confiure_file = input_list[1]
                    if not os.path.exists(confiure_file):
                        print("not this configure file")
                        continue
                    new_config = configparser.ConfigParser()
                    new_config.read(confiure_file)
                    # configure server parameters
                    REORDERING_TIMEOUT_CONFIG = int(new_config['SERVER_PARAMETERS']['REORDERING_TIMEOUT_CONFIG'])
                    WIFI_RATE_MBPS_CONFIG = int(new_config['SERVER_PARAMETERS']['WIFI_RATE_MBPS_CONFIG'])
                    WIFI_NRT_RATE_MBPS_CONFIG = int(new_config['SERVER_PARAMETERS']['WIFI_NRT_RATE_MBPS_CONFIG'])
                    WIFI_DELAY_MS_CONFIG = int(new_config['SERVER_PARAMETERS']['WIFI_DELAY_MS_CONFIG'])
                    LTE_RATE_MBPS_CONFIG = int(new_config['SERVER_PARAMETERS']['LTE_RATE_MBPS_CONFIG'])
                    LTE_NRT_RATE_MBPS_CONFIG = int(new_config['SERVER_PARAMETERS']['LTE_NRT_RATE_MBPS_CONFIG'])
                    LTE_DELAY_MS_CONFIG = int(new_config['SERVER_PARAMETERS']['LTE_DELAY_MS_CONFIG'])
                    MAX_RATE_MBPS_CONFIG = int(new_config['SERVER_PARAMETERS']['MAX_RATE_MBPS_CONFIG'])
                    SLEEP_TIME_UNIT_US_CONFIG = int(new_config['SERVER_PARAMETERS']['SLEEP_TIME_UNIT_US_CONFIG'])
                    PKT_BURST_SIZE_KB_CONFIG = int(new_config['SERVER_PARAMETERS']['PKT_BURST_SIZE_KB_CONFIG'])
                    MEASURE_INTERVAL_S_CONFIG = int(new_config['SERVER_PARAMETERS']['MEASURE_INTERVAL_S_CONFIG'])
                    SERVER_REPORT_CYCLE_CONFIG = int(new_config['SERVER_PARAMETERS']['SERVER_REPORT_CYCLE_CONFIG'])
                    ENABLE_MEASURE_REPORT_CONFIG = int(new_config['SERVER_PARAMETERS']['ENABLE_MEASURE_REPORT_CONFIG'])

                    scu_msg_req = SCU_MSG_REQ + REORDERING_TIMEOUT_CONFIG.to_bytes(4, 'little') + \
                                  WIFI_RATE_MBPS_CONFIG.to_bytes(4, 'little') + \
                                  WIFI_NRT_RATE_MBPS_CONFIG.to_bytes(4, 'little') + \
                                  WIFI_DELAY_MS_CONFIG.to_bytes(4, 'little') + \
                                  LTE_RATE_MBPS_CONFIG.to_bytes(4, 'little') + \
                                  LTE_NRT_RATE_MBPS_CONFIG.to_bytes(4, 'little') + \
                                  LTE_DELAY_MS_CONFIG.to_bytes(4, 'little') + \
                                  MAX_RATE_MBPS_CONFIG.to_bytes(4, 'little') + \
                                  SLEEP_TIME_UNIT_US_CONFIG.to_bytes(4, 'little') + \
                                  PKT_BURST_SIZE_KB_CONFIG.to_bytes(4, 'little') + \
                                  MEASURE_INTERVAL_S_CONFIG.to_bytes(4, 'little') + \
                                  SERVER_REPORT_CYCLE_CONFIG.to_bytes(4, 'little') + \
                                  ENABLE_MEASURE_REPORT_CONFIG.to_bytes(4, 'little')
                    print(scu_msg_req)

                    sendto_server(scu_msg_req)
                    print("send scu req")

                elif input_list[0] == "restart":
                    start_ws_listening.close()
                    start_virtual_server.close()
                    load_config()
                    send_build_tun_req()
                    global max_client_num
                    global client_info_arrays
                    global sn_num_arrays
                    global ws_array_index_dict
                    
                    ws_array_index_dict.clear()
                    client_info_arrays.clear()
                    sn_num_arrays.clear()
                    rows, cols = (max_client_num, 5)
                    client_info_arrays = [[0 for i in range(cols)] for j in range(rows)]
                    sn_num_arrays = [0 for i in range(rows)]
                    print("send restart req(tun setup req)")

                else:
                    print("wrong message format")
        except Exception as e:
            print('error:{0}'.format(e))
            print("quit keyboard listening")
        finally:
            print('close keyboard listening')


async def discover(ws1, path):
    try:
        print('discover ws:', ws1)
        while True:
            json_message = await ws1.recv()
            message = json.loads(json_message)
            '''
            Init handshake
            '''
            print("discovery msg")
            if type_match(message, 'mx_discover'):
                # global ccm_end_point_ip
                # ccm_end_point_ip, ccm_end_point_port = ws1.remote_address
                await ws1.send(json.dumps(MX_System_Update_Msg))
                config = configparser.ConfigParser()
                config.read('/home/ncm_ws/conf.ini')
                server_vnic_ip = config['SERVER_PARAMETERS']['SERVER_VNIC_IP']
                server_vnic_gw = config['SERVER_PARAMETERS']['SERVER_VNIC_GW']
                server_vnic_msk = config['SERVER_PARAMETERS']['SERVER_VNIC_MSK']
                server_vnic_dns = config['SERVER_PARAMETERS']['SERVER_VNIC_DNS']

                server_vnic_ip_bytes = socket.inet_aton(server_vnic_ip)
                server_vnic_gw_bytes = socket.inet_aton(server_vnic_gw)
                server_vnic_msk_bytes = socket.inet_aton(server_vnic_msk)
                server_vnic_dns_bytes = socket.inet_aton(server_vnic_dns)
                tun_setup_req = Tun_Setup_Req + \
                                server_vnic_ip_bytes + \
                                server_vnic_gw_bytes + \
                                server_vnic_msk_bytes + \
                                server_vnic_dns_bytes
                print('[NCM->Server] tun setup req')
                sendto_server(tun_setup_req)
                break
    except Exception as e:
        print('error:{0}'.format(e))
        print("client disconnected")
    finally:
        print('close discover ws')
        await ws1.close()


def recvfrom_server():
    try:
        r, w, e = select.select([sock_recv, ], [], [], 0.0001)
        if sock_recv in r:
            msg, addr = sock_recv.recvfrom(1024)
            ciphertext, authTag, nonce = msg[:-28], msg[-28:-12], msg[-12:]
            try:
                aesCipher = AES.new(server_aeskey, AES.MODE_GCM, nonce, mac_len=16)
                plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
            except ValueError:
                print("Key incorrect or message corrupted")
                return [0, 0, 0, 0, 0, 0, 0]
            print(plaintext)
            print(plaintext[3])
            return plaintext

        return [0, 0, 0, 0, 0, 0, 0]
    except Exception as e:
        print('error:{0}'.format(e))
        print('talk with GMA client stopped')
        return [0, 0, 0, 0, 0, 0, 0]


async def periodic_meas():
    try:
        while 1:
            if g_meas_on == False:
                await asyncio.sleep(0.5)
                continue
            await g_ws.send(json.dumps(MX_Measure_Config_Msg))
            await asyncio.sleep(meas_periodic)

    except Exception as e:
        print('error:{0}'.format(e))
        print('periodic_meas stopped')


async def ws_listening(g_ws, path):
    # global ws
    # ws = g_ws
    global last_ip_address
    client_vnic_ip = ""  # client tun ip address
    vnic_index = 0
    session_id = 0
    Client_Index = 0
    array_index = -1

    try:
        while 1:
            '''Listening to CCM'''
            json_message = await g_ws.recv()
            # print(json_message)
            message = json.loads(json_message)
            if type_match(message, 'mx_capability_req'):
                request_sn = create_req_sn()
                if request_sn == -1:
                    MX_Capability_Rsp_Msg['num_anchor_connections'] = 0
                    await g_ws.send(json.dumps(MX_Capability_Rsp_Msg))
                    break

                MX_Capability_Req_Msg = message
                anchor_mode = MX_Capability_Req_Msg['anchor_connections'][0]['connection_type']
                if anchor_mode != 'vnic':
                    print('[err] wrong anchor mode, plz check')
                    break

                client_last_ip_address = message['anchor_connections'][0]['last_ip_address']
                client_last_ip_address_list = client_last_ip_address.split('.')
                Client_Index = int(client_last_ip_address_list[2]) * 256 + int(client_last_ip_address_list[3])
                if Client_Index > 1 and Client_Index < max_client_num + 2:
                    array_index = Client_Index - 2
                    client_last_session_id = message['anchor_connections'][0]['last_session_id']
                    if client_info_arrays[array_index][session_id_index] == client_last_session_id:
                        client_info_arrays[array_index][websockets_connection_index] = g_ws
                    else:
                        Client_Index = 0
                        array_index = -1
                else:
                    Client_Index = 0

                sn_num_arrays[request_sn] = g_ws
                create_client_msg = Create_Client_Req_Msg + request_sn.to_bytes(4, 'little') + Client_Index.to_bytes(4,
                                                                                                                     'little')
                sendto_server(create_client_msg)

            if type_match(message, 'mx_capability_ack'):
                print('[CCM->NCM] Recv mx_capability_ack')
                MX_Capability_ACK_Msg = message
                config = configparser.ConfigParser()
                config.read('/home/ncm_ws/conf.ini')
                preconfig_ncm_ip = config['WEBSOCK']['ip']
                preconfig_ncm_port = int(config['WEBSOCK']['ncm_port'])
                preconfig_interface = config['WEBSOCK']['interface']
                if preconfig_ncm_ip == "0.0.0.0":
                    preconfig_ncm_ip = ni.ifaddresses(preconfig_interface)[ni.AF_INET][0]['addr']
                ws_port_bytes = preconfig_ncm_port.to_bytes(2, 'little')
                ws_ip_bytes = socket.inet_aton(preconfig_ncm_ip)

                vnic_anchor_msg = Set_VNIC_Anchor_Msg + ws_port_bytes + ws_ip_bytes
                sendto_server(vnic_anchor_msg)
                print('[NCM->server] send anchor mode message')

                if g_ws in ws_array_index_dict:
                    array_index = ws_array_index_dict[g_ws]
                    ws_array_index_dict.pop(g_ws)

                if array_index == -1:
                    continue

                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['ip'] = \
                client_info_arrays[array_index][ip_address_index]
                config = configparser.ConfigParser()
                config.read('/home/ncm_ws/conf.ini')
                # configure client parameters
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['udp_port'] = config['SERVER_PARAMETERS'][
                    'UDP_PORT']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['tcp_port'] = config['SERVER_PARAMETERS'][
                    'TCP_PORT']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['gateway'] = \
                config['SERVER_PARAMETERS']['SERVER_VNIC_GW']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['mask'] = config['SERVER_PARAMETERS'][
                    'SERVER_VNIC_MSK']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['dns'] = config['SERVER_PARAMETERS'][
                    'SERVER_VNIC_DNS']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['vnic_port'] = config['WEBSOCK'][
                    'virtual_port']
                lte_ip = config['SERVER_PARAMETERS']['LTE_INTERFACE_IP_ADDRESS']
                wifi_ip = config['SERVER_PARAMETERS']['WIFI_INTERFACE_IP_ADDRESS']
                if lte_ip == "0.0.0.0":
                    lte_ip = ni.ifaddresses(config['SERVER_PARAMETERS']['LTE_INTERFACE_CONFIG'])[ni.AF_INET][0]['addr']
                if wifi_ip == "0.0.0.0":
                    wifi_ip = ni.ifaddresses(config['SERVER_PARAMETERS']['WLAN_INTERFACE_CONFIG'])[ni.AF_INET][0][
                        'addr']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['delivery_connections'][0][
                    'adaptation_method_params']['tunnel_ip_addr'] = lte_ip
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['delivery_connections'][0][
                    'adaptation_method_params']['tunnel_end_port'] = config['SERVER_PARAMETERS'][
                    'LTE_INTERFACE_IP_PORT']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['delivery_connections'][0][
                    'adaptation_method_params']['mx_header_optimization'] = config['SERVER_PARAMETERS'][
                    'LTE_TUNNEL_IP_ENABLED']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['delivery_connections'][1][
                    'adaptation_method_params']['tunnel_ip_addr'] = wifi_ip
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['delivery_connections'][1][
                    'adaptation_method_params']['tunnel_end_port'] = config['SERVER_PARAMETERS'][
                    'WIFI_INTERFACE_IP_PPORT']

                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['network_interface_minMTU'] = \
                config['CLIENT_PARAMETERS']['network_interface_minMTU']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['dynamic_split_flag'] = \
                config['CLIENT_PARAMETERS']['dynamic_split_flag']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['Lte_always_on_flag'] = \
                config['CLIENT_PARAMETERS']['Lte_always_on_flag']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['congest_detect_loss_threshold'] = \
                config['CLIENT_PARAMETERS']['congest_detect_loss_threshold']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config'][
                    'congest_detect_utilization_threshold'] = config['CLIENT_PARAMETERS'][
                    'congest_detect_utilization_threshold']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['lte_probe_interval_screen_off'] = \
                config['CLIENT_PARAMETERS']['lte_probe_interval_screen_off']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['lte_probe_interval_screen_on'] = \
                config['CLIENT_PARAMETERS']['lte_probe_interval_screen_on']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['lte_probe_interval_active'] = \
                config['CLIENT_PARAMETERS']['lte_probe_interval_active']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['lte_rssi_measurement'] = \
                config['CLIENT_PARAMETERS']['lte_rssi_measurement']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_probe_interval_screen_off'] = \
                config['CLIENT_PARAMETERS']['wifi_probe_interval_screen_off']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_probe_interval_screen_on'] = \
                config['CLIENT_PARAMETERS']['wifi_probe_interval_screen_on']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_probe_interval_active'] = \
                config['CLIENT_PARAMETERS']['wifi_probe_interval_active']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['param_l'] = \
                config['CLIENT_PARAMETERS']['param_l']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_low_rssi'] = \
                config['CLIENT_PARAMETERS']['wifi_low_rssi']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_high_rssi'] = \
                config['CLIENT_PARAMETERS']['wifi_high_rssi']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MRP_interval_active'] = \
                config['CLIENT_PARAMETERS']['MRP_interval_active']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MRP_interval_idle'] = \
                config['CLIENT_PARAMETERS']['MRP_interval_idle']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MRP_size'] = \
                config['CLIENT_PARAMETERS']['MRP_size']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['max_reordering_delay'] = \
                config['CLIENT_PARAMETERS']['max_reordering_delay']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['min_reordering_delay'] = \
                config['CLIENT_PARAMETERS']['min_reordering_delay']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['reorder_buffer_size'] = \
                config['CLIENT_PARAMETERS']['reorder_buffer_size']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['reorder_Lsn_enhance_flag'] = \
                config['CLIENT_PARAMETERS']['reorder_Lsn_enhance_flag']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['reorder_drop_out_of_order_pkt'] = \
                config['CLIENT_PARAMETERS']['reorder_drop_out_of_order_pkt']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['min_tpt'] = \
                config['CLIENT_PARAMETERS']['min_tpt']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['idle_timer'] = \
                config['CLIENT_PARAMETERS']['idle_timer']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['allow_app_list_enable'] = \
                config['CLIENT_PARAMETERS']['allow_app_list_enable']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['wifi_owd_offset'] = \
                config['CLIENT_PARAMETERS']['wifi_owd_offset']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['ul_duplicate_flag'] = \
                config['CLIENT_PARAMETERS']['ul_duplicate_flag']

                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['OWD_CONVERGE_THRESHOLD'] = \
                config['CLIENT_PARAMETERS']['OWD_CONVERGE_THRESHOLD']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MAX_MEASURE_INTERVAL_NUM'] = \
                config['CLIENT_PARAMETERS']['MAX_MEASURE_INTERVAL_NUM']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MIN_PACKET_NUM_PER_INTERVAL'] = \
                config['CLIENT_PARAMETERS']['MIN_PACKET_NUM_PER_INTERVAL']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MAX_MEASURE_INTERVAL_DURATION'] = \
                config['CLIENT_PARAMETERS']['MAX_MEASURE_INTERVAL_DURATION']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MIN_MEASURE_INTERVAL_DURATION'] = \
                config['CLIENT_PARAMETERS']['MIN_MEASURE_INTERVAL_DURATION']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['BURST_SAMPLE_FREQUENCY'] = \
                config['CLIENT_PARAMETERS']['BURST_SAMPLE_FREQUENCY']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MAX_RATE_ESTIMATE'] = \
                config['CLIENT_PARAMETERS']['MAX_RATE_ESTIMATE']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['RATE_ESTIMATE_K'] = \
                config['CLIENT_PARAMETERS']['RATE_ESTIMATE_K']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['MIN_PACKET_COUNT_PER_BURST'] = \
                config['CLIENT_PARAMETERS']['MIN_PACKET_COUNT_PER_BURST']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['BURST_INCREASING_ALPHA'] = \
                config['CLIENT_PARAMETERS']['BURST_INCREASING_ALPHA']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['STEP_ALPHA_THRESHOLD'] = \
                config['CLIENT_PARAMETERS']['STEP_ALPHA_THRESHOLD']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['TOLERANCE_LOSS_BOUND'] = \
                config['CLIENT_PARAMETERS']['TOLERANCE_LOSS_BOUND']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['TOLERANCE_DELAY_BOUND'] = \
                config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_BOUND']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['TOLERANCE_DELAY_H'] = \
                config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_H']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['TOLERANCE_DELAY_L'] = \
                config['CLIENT_PARAMETERS']['TOLERANCE_DELAY_L']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['SPLIT_ALGORITHM'] = \
                config['CLIENT_PARAMETERS']['SPLIT_ALGORITHM']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['INITIAL_PACKETS_BEFORE_LOSS'] = \
                config['CLIENT_PARAMETERS']['INITIAL_PACKETS_BEFORE_LOSS']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['icmp_flow_type'] = \
                config['CLIENT_PARAMETERS']['icmp_flow_type']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['tcp_rt_port_start'] = \
                config['CLIENT_PARAMETERS']['tcp_rt_port_start']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['tcp_rt_port_end'] = \
                config['CLIENT_PARAMETERS']['tcp_rt_port_end']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['tcp_hr_port_start'] = \
                config['CLIENT_PARAMETERS']['tcp_hr_port_start']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['tcp_hr_port_end'] = \
                config['CLIENT_PARAMETERS']['tcp_hr_port_end']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['udp_rt_port_start'] = \
                config['CLIENT_PARAMETERS']['udp_rt_port_start']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['udp_rt_port_end'] = \
                config['CLIENT_PARAMETERS']['udp_rt_port_end']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['udp_hr_port_start'] = \
                config['CLIENT_PARAMETERS']['udp_hr_port_start']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['udp_hr_port_end'] = \
                config['CLIENT_PARAMETERS']['udp_hr_port_end']
                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['client_config']['ul_qos_flow_enable'] = \
                config['CLIENT_PARAMETERS']['ul_qos_flow_enable']
                
                filename = config['CLIENT_PARAMETERS']['ALLOW_ANDROID_APP_LIST']
                allow_android_app_list = ""
                split_symbol = ';'

                MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['allow_application_list'] = allow_android_app_list
                await g_ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                print('[NCM->CCM] send VNIC UP setup config request')

                # await g_ws.send(json.dumps(MX_Measure_Config_Msg))
                # print('[NCM -> CCM] Send mx_measurement_conf')

                # await g_ws.send(json.dumps(MX_GMA_Wifi_List))
                # print('[NCM -> CCM] Send mx_gma_wifi_list')

            '''
            UE reports its LTE&WiFi connection parameters
            '''
            if type_match(message, 'mx_reconf_req'):
                if message['sequence_num'] == MX_LTE_Reconfig_Rsp_Msg['sequence_num']:
                    MX_LTE_Reconfig_Req_Msg = message
                    server_lte_header_opt_bytes = b'\x00'
                    if message['connection_status'] == 'connected':

                        client_lte_ip = message['ip_address']
                        client_lte_ip_bytes = socket.inet_aton(client_lte_ip)

                        server_lte_tunnel_ip = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['tunnel_ip_addr']
                        server_lte_tunnel_port = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['tunnel_end_port']
                        server_lte_header_opt = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['mx_header_optimization']
						
                        server_lte_tunnel_ip_bytes = socket.inet_aton(server_lte_tunnel_ip)
                        server_lte_tunnel_port_bytes = server_lte_tunnel_port.to_bytes(2, 'little')
                        
                        # MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['ip'] = client_info_arrays[array_index][ip_address_index]
                        config = configparser.ConfigParser()
                        config.read('/home/ncm_ws/conf.ini')
                        server_udp_port = config['SERVER_PARAMETERS']['UDP_PORT']
                        server_tcp_port = config['SERVER_PARAMETERS']['TCP_PORT']

                        server_udp_port_bytes = server_udp_port.to_bytes(2, 'little')

                        server_tcp_port_bytes = server_tcp_port.to_bytes(2, 'little')

                        if config['SERVER_PARAMETERS']['LTE_TUNNEL_IP_ENABLED'] == 1:	
                            server_lte_header_opt_bytes = b'\x01'
                        else:
                            server_lte_header_opt_bytes = b'\x00'

                        # Client_Index = client_lte_ip_bytes[3]
                        create_client_msg = Create_Client_Req_Msg + \
                                            client_lte_ip_bytes + \
                                            server_lte_tunnel_ip_bytes + \
                                            server_lte_tunnel_port_bytes + \
                                            server_lte_header_opt_bytes + \
                                            server_udp_port_bytes + \
                                            server_tcp_port_bytes

                        print('[CCM->NCM] Recv mx_reconf_req(LTE)')
                        # sendto_server(add_index(create_client_msg, Client_Index))
                        print('[NCM->Server] Send Create Client Req')
                    else:
                        # sendto_server(add_index(LTE_Link_Down_Msg, Client_Index))
                        print('[NCM->Server] Send LTE Link Down Req Msg')

                else:
                    MX_Wifi_Reconfig_Req_Msg = message
                    server_wifi_header_opt_bytes = b'\x00'

                    if message['connection_status'] == 'connected':
                        client_wifi_ip = message['ip_address']
                        client_wifi_ip_bytes = socket.inet_aton(client_wifi_ip)

                        server_wifi_tunnel_ip = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['tunnel_ip_addr']
                        server_wifi_tunnel_port = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['tunnel_end_port']
                        server_wifi_header_opt = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['mx_header_optimization']

                        server_wifi_tunnel_ip_bytes = socket.inet_aton(server_wifi_tunnel_ip)
                        server_wifi_tunnel_port_bytes = server_wifi_tunnel_port.to_bytes(2, 'little')
                        if server_wifi_header_opt == True:
                            server_wifi_header_opt_bytes = b'\x01'
                        else:
                            server_wifi_header_opt_bytes = b'\x00'

                        wifi_link_up_msg = WiFi_Link_Up_Msg + \
                                           client_wifi_ip_bytes + \
                                           server_wifi_tunnel_ip_bytes + \
                                           server_wifi_tunnel_port_bytes + \
                                           server_wifi_header_opt_bytes
                        print('[CCM->NCM] Recv mx_reconf_req(wifi)')
                        # sendto_server(add_index(wifi_link_up_msg, Client_Index))
                        print('[NCM->Server] Send WiFi Link Up Req Msg')
                    else:
                        # sendto_server(add_index(WiFi_Link_Down_Msg, Client_Index))
                        print('[NCM->Server] Send WiFi Link Down Req Msg')

            '''
            User Plan Setting for LTE anchor or WiFi anchor
            '''
            if type_match(message, 'mx_up_setup_cnf'):
                if array_index == -1:
                    break
                client_lte_adapt_port = message['client_params'][0]['adapt_param']['udp_adapt_port']
                client_wifi_adapt_port = message['client_params'][1]['adapt_param']['udp_adapt_port']
                print('[CCM->NCM] Recv mx_up_setup_cnf, WiFi anchor')

                client_lte_adapt_port_bytes = client_lte_adapt_port.to_bytes(2, 'little')
                client_wifi_adapt_port_bytes = client_wifi_adapt_port.to_bytes(2, 'little')

                client_probe_port = message['probe_param']['probe_port']
                client_probe_port_bytes = client_probe_port.to_bytes(2, 'little')

                print('client_probe_port:', client_probe_port, 'client_wifi_adapt_port:',
                      client_wifi_adapt_port, 'client_lte_adapt_port', client_lte_adapt_port)

                up_setup_cnf_msg = User_Plan_Setup_Cnf + \
                                   client_info_arrays[array_index][client_ip_index].to_bytes(4, 'little') + \
                                   client_probe_port_bytes + \
                                   client_wifi_adapt_port_bytes + \
                                   client_lte_adapt_port_bytes

                sendto_server(up_setup_cnf_msg)
                print('[NCM->server] Send User Plan Setup Cnf')

            if type_match(message, 'mx_measurement_report'):
                print('--------------')
                print('[CCM->NCM] Recv Measurement Report')
                print(message['measurement_reports'][0]['delivery_node_id'])
                print(message['measurement_reports'][0]['measurements'][0]['measurement_value'])
                print(message['measurement_reports'][1]['measurements'][0]['measurement_value'])
                print('--------------')

            if type_match(message, 'mx_session_resume_req'):
                if array_index == -1:
                    break
                await g_ws.send(json.dumps(MX_Session_Resume_Rsp))
                client_suspend_stop_req = Client_Suspend_Stop_Req + client_info_arrays[array_index][
                    client_ip_index].to_bytes(4, 'little')
                sendto_server(client_suspend_stop_req)
                client_resume_req = Client_Resume_Req + client_info_arrays[array_index][client_ip_index].to_bytes(4,
                                                                                                                  'little')
                sendto_server(client_resume_req)
                print('[CCM->NCM] Recv MX_Session_Resume_Req')


    except Exception as e:
        print('error:{0}'.format(e))
        print("stop listening g_ws")
    finally:
        # route_del(ccm_end_point_ip, ncm_end_point_ip)
        # sendto_server(add_index(Close_Client_Req_Msg, Client_Index))
        # print('[NCM->Server] Close client:', Client_Index)
        g_ws = None


async def udp_listening():
    while True:
        try:
            while True:
                # print('udp ws', ws)
                # if ws == None:
                #    await asyncio.sleep(0.00001)
                #    continue

                '''Listening to the GMA server'''
                ##global msg_recv
                ##await asyncio.sleep(0.0001)

                msg_recv = recvfrom_server()
                array_index = 0
                client_index = 0
                session_id = 0
                ##
                if msg_recv == [0, 0, 0, 0, 0, 0, 0]:
                    await asyncio.sleep(0.0001)
                    continue

                if msg_recv[3] == 25:  # start virtual websockets listening
                    # start_virtual_server = websockets.serve(virtual_server_listening, Vnic_Ip, Vnic_Port, ssl=ctx)
                    preconfig_ip = config['WEBSOCK']['ip']
                    preconfig_port = int(config['WEBSOCK']['ncm_port'])
                    preconfig_interface = config['WEBSOCK']['interface']
                    if preconfig_ip == "0.0.0.0":
                        preconfig_ip = ni.ifaddresses(preconfig_interface)[ni.AF_INET][0]['addr']
                    Vnic_Ip = config['SERVER_PARAMETERS']['SERVER_VNIC_GW']
                    Vnic_Port = int(config['WEBSOCK']['virtual_port'])
                    global start_ws_listening
                    global start_virtual_server
                    start_ws_listening = await websockets.serve(ws_listening, preconfig_ip, preconfig_port, ssl=ctx)
                    start_virtual_server = await websockets.serve(virtual_server_listening, Vnic_Ip, Vnic_Port, ssl=ctx)
                    # asyncio.run_coroutine_threadsafe(start_virtual_server,main_loop)
                    #main_loop.call_soon_threadsafe(asyncio.ensure_future, start_virtual_server)
                    #my_virtual_server = await start_virtual_server
                    continue
                if msg_recv[3] == 30:  # tsc message ack
                    print('receive tsc message ack')
                    continue
                if msg_recv[3] == 32:  # ccu message ack
                    print('receive ccu message ack')
                    continue
                if msg_recv[3] == 34:  # scu message ack
                    print('receive scu message ack')
                    continue
                if msg_recv[3] == 36:  # restart message ack
                    print('receive restart message ack')
                    continue
                if msg_recv[3] == 38:  # TXC message ack
                    print('receive txc message ack')
                    continue
                if msg_recv[3] == 40:  # TFC message ack
                    print('receive tfc message ack')
                    continue
                if msg_recv[3] == 43:
                    print('receive winapp restart message')
                    start_ws_listening.close()
                    start_virtual_server.close()
                    load_config()
                    send_build_tun_req()
                    
                    global max_client_num
                    global client_info_arrays
                    global sn_num_arrays
                    global ws_array_index_dict
                    ws_array_index_dict.clear()
                    client_info_arrays.clear()
                    sn_num_arrays.clear()
                    rows, cols = (max_client_num, 5)
                    client_info_arrays = [[0 for i in range(cols)] for j in range(rows)]
                    sn_num_arrays = [0 for i in range(rows)]
                    print('send restart req(tun setup req) from winapp')
                    continue
                # print('len = ', len(msg_recv))
                if msg_recv[3] == 20:  # type: Create_Client_Ack
                    # if len(msg_recv) == 50:
                    rsp_sn = msg_recv[9] << 24 | msg_recv[8] << 16 | msg_recv[7] << 8 | msg_recv[6]
                    # print('rsp_sn',rsp_sn)
                    if rsp_sn < max_client_num and sn_num_arrays[rsp_sn] != 0:
                        client_index = msg_recv[13] << 24 | msg_recv[12] << 16 | msg_recv[11] << 8 | msg_recv[10]
                        session_id = msg_recv[17] << 24 | msg_recv[16] << 16 | msg_recv[15] << 8 | msg_recv[14]
                        aes_key_bytes = msg_recv[-32:];

                        array_index = client_index - 2
                        if client_index < 1 and session_id == 0:
                            MX_Capability_Rsp_Msg['num_anchor_connections'] = 0
                            await sn_num_arrays[rsp_sn].send(json.dumps(MX_Capability_Rsp_Msg))
                            continue

                        Vnic_Ip = config['SERVER_PARAMETERS']['SERVER_VNIC_GW']
                        vnic_ip_list = Vnic_Ip.split('.')
                        vnic_ip_first_bytes_str = vnic_ip_list[0] + '.' + vnic_ip_list[1]
                        client_info_arrays[array_index][client_ip_index] = client_index
                        client_info_arrays[array_index][ip_address_index] = vnic_ip_first_bytes_str + "." + str(
                            client_index // 256) + "." + str(client_index % 256)
                        client_info_arrays[array_index][websockets_connection_index] = sn_num_arrays[rsp_sn]
                        client_info_arrays[array_index][session_id_index] = session_id
                        client_info_arrays[array_index][aes_key_index] = b64encode(aes_key_bytes).decode('utf-8')

                        ws_array_index_dict[
                            client_info_arrays[array_index][websockets_connection_index]] = client_index - 2
                        sn_num_arrays[rsp_sn] = 0
                        print('client index:', client_info_arrays[array_index][client_ip_index])
                        print('ip address:', client_info_arrays[array_index][ip_address_index])
                        print('websocket', client_info_arrays[array_index][websockets_connection_index])
                        print('session id', client_info_arrays[array_index][session_id_index])
                        print('aes_key', client_info_arrays[array_index][aes_key_index])
                #
                # elif len(msg_recv) == 10:
                #	client_index = msg_recv[6] << 24 | msg_recv[7] << 16 | msg_recv[8] << 8 | msg_recv[9]
                #	array_index = client_index - 2
                #	print(array_index)
                #	print(client_index)
                else:
                    print("[udp listening] wrong message")
                    continue

                ws = client_info_arrays[array_index][websockets_connection_index]
                # print(ws)
                if msg_recv[3] == 20:  # type: Create_Client_Ack

                    MX_Capability_Rsp_Msg['unique_session_id']['session_id'] = client_info_arrays[array_index][
                        session_id_index]
                    MX_Capability_Rsp_Msg['aes_key'] = client_info_arrays[array_index][aes_key_index]
                    await ws.send(json.dumps(MX_Capability_Rsp_Msg))

                # await ws.send(json.dumps(MX_LTE_Reconfig_Rsp_Msg))
                # print('[server->NCM] Recv Create Client Rsp')

                # MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['ip'] = client_info_arrays[array_index][ip_address_index]
                # await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                # print('[NCM->CCM] send VNIC UP setup config request')

                if msg_recv[3] == 4:  # type: WiFi_Link_Up/Down_ACK
                    # print('udp ws', ws)
                    await ws.send(json.dumps(MX_Wifi_Reconfig_Rsp_Msg))
                    if msg_recv[2] == 1:
                        print('[server->NCM] Recv WiFi Link Up Rsp')
                        await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                        print('[NCM->CCM] send WiFi UP setup config request')
                    else:
                        print('[server->NCM] Recv WiFi Link Down Rsp')

                if msg_recv[3] == 24:  # type: LTE_Link_Up/Down_ACK
                    # print('udp ws', ws)
                    await ws.send(json.dumps(MX_LTE_Reconfig_Rsp_Msg))
                    if msg_recv[2] == 1:
                        print('[server->NCM] Recv LTE Link Up Rsp')
                        await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                        print('[NCM->CCM] send LTE UP setup config request')
                    else:
                        print('[server->NCM] Recv LTE Link Down Rsp')


        except Exception as e:
            import traceback
            print(traceback.format_exc())
            print('error:{0}'.format(e))
            print("client disconnected")
            # asyncio.gather(...,return_exceptions=True)

            # finally:
            print('exit udp listing')
        # await ws.close()


async def virtual_server_listening(ws2, path):
    # global ws
    # ws = ws2
    remote_ip, remote_port = ws2.remote_address

    remote_ip_list = remote_ip.split('.')
    array_index = int(remote_ip_list[2]) * 256 + int(remote_ip_list[3]) - 2

    if array_index < 0:
        print('no this client ip address')
        return

    try:
        print('discover virtual websocket connection:', ws2)
        while 1:
            '''Listening to virtual websockets'''
            json_message = await ws2.recv()
            # print(json_message)
            message = json.loads(json_message)

            if type_match(message, 'mx_session_resume_req'):
                print('virtual [CCM->NCM] mx_session_resume_req')
                client_resume_req = Client_Resume_Req + client_info_arrays[array_index][client_ip_index].to_bytes(4,
                                                                                                                  'little')
                sendto_server(client_resume_req)
                await ws2.send(json.dumps(MX_Session_Resume_Rsp))
                print('[NCM->CCM] Send MX_Session_Resume_Rsp')
                await ws2.send(json.dumps(MX_Qos_Flow_Conf))
                print('[NCM->CCM] Send MX_Qos_Flow_Conf')
                await ws2.send(json.dumps(MX_Gma_Client_Conf))
                print('[NCM->CCM] Send MX_Gma_Client_Conf')

            if type_match(message, 'mx_session_suspend_req'):
                print('virtual [CCM->NCM] mx_session_suspend_req')
                client_suspend_begin_req = Client_Suspend_Begin_Req + client_info_arrays[array_index][
                    client_ip_index].to_bytes(4, 'little')
                await ws2.send(json.dumps(MX_Session_Suspend_Rsp))
                sendto_server(client_suspend_begin_req)

            if type_match(message, 'mx_session_termination_req'):
                print('virtual [CCM->NCM] mx_session_termination_req')
                await ws2.send(json.dumps(MX_Session_Termination_Rsp))

            if type_match(message, 'mx_reconf_req'):
                if message['sequence_num'] == MX_LTE_Reconfig_Rsp_Msg['sequence_num']:
                    MX_LTE_Reconfig_Req_Msg = message
                    server_lte_header_opt_bytes = b'\x00'

                    if message['connection_status'] == 'connected':

                        client_lte_ip = message['ip_address']
                        client_lte_ip_bytes = socket.inet_aton(client_lte_ip)

                        server_lte_tunnel_ip = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['tunnel_ip_addr']
                        server_lte_tunnel_port = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['tunnel_end_port']
                        server_lte_header_opt = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][0] \
                            ['adaptation_method_params'] \
                            ['mx_header_optimization']

                        server_lte_tunnel_ip_bytes = socket.inet_aton(server_lte_tunnel_ip)
                        server_lte_tunnel_port_bytes = server_lte_tunnel_port.to_bytes(2, 'little')
                        if config['SERVER_PARAMETERS']['LTE_TUNNEL_IP_ENABLED'] == 1:						
                            server_lte_header_opt_bytes = b'\x01'
                        else:
                            server_lte_header_opt_bytes = b'\x00'

                        lte_link_up_msg = LTE_Link_Up_Msg + \
                                          client_info_arrays[array_index][client_ip_index].to_bytes(4, 'little') + \
                                          client_lte_ip_bytes + \
                                          server_lte_tunnel_ip_bytes + \
                                          server_lte_tunnel_port_bytes + \
                                          server_lte_header_opt_bytes

                        print('[CCM->NCM] Recv mx_reconf_req(LTE)')
                        sendto_server(lte_link_up_msg)
                        print('[NCM->Server] Send LTE Link Up Req Msg')
                    else:
                        lte_link_down_msg = LTE_Link_Down_Msg + client_info_arrays[array_index][
                            client_ip_index].to_bytes(4, 'little')
                        sendto_server(lte_link_down_msg)
                        print('[NCM->Server] Send LTE Link Down Req Msg')

                else:
                    MX_Wifi_Reconfig_Req_Msg = message
                    server_wifi_header_opt_bytes = b'\x00'

                    if message['connection_status'] == 'connected':
                        client_wifi_ip = message['ip_address']

                        client_wifi_ip_bytes = socket.inet_aton(client_wifi_ip)

                        server_wifi_tunnel_ip = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['tunnel_ip_addr']
                        server_wifi_tunnel_port = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['tunnel_end_port']
                        server_wifi_header_opt = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
                            ['delivery_connections'][1] \
                            ['adaptation_method_params'] \
                            ['mx_header_optimization']

                        server_wifi_tunnel_ip_bytes = socket.inet_aton(server_wifi_tunnel_ip)
                        server_wifi_tunnel_port_bytes = server_wifi_tunnel_port.to_bytes(2, 'little')
                        if server_wifi_header_opt == True:
                            server_wifi_header_opt_bytes = b'\x01'
                        else:
                            server_wifi_header_opt_bytes = b'\x00'

                        wifi_link_up_msg = WiFi_Link_Up_Msg + \
                                           client_info_arrays[array_index][client_ip_index].to_bytes(4, 'little') + \
                                           client_wifi_ip_bytes + \
                                           server_wifi_tunnel_ip_bytes + \
                                           server_wifi_tunnel_port_bytes + \
                                           server_wifi_header_opt_bytes
                        print('[CCM->NCM] Recv mx_reconf_req(wifi)')
                        sendto_server(wifi_link_up_msg)
                        print('[NCM->Server] Send WiFi Link Up Req Msg')
                    else:
                        wifi_link_down_msg = WiFi_Link_Down_Msg + client_info_arrays[array_index][
                            client_ip_index].to_bytes(4, 'little')
                        sendto_server(wifi_link_down_msg)
                        print('[NCM->Server] Send WiFi Link Down Req Msg')

            if type_match(message, 'mx_measurement_report'):
                print('--------------')
                print('[CCM->NCM] Recv Measurement Report')
                print(message['measurement_reports'][0]['delivery_node_id'])
                print(message['measurement_reports'][0]['measurements'][0]['measurement_value'])
                print(message['measurement_reports'][1]['measurements'][0]['measurement_value'])
                print('--------------')

    except Exception as e:
        print('error:{0}'.format(e))
        print("virtual disconnected")
    finally:
        # sendto_server(add_index(Close_Client_Req_Msg, Client_Index))
        # print('[NCM->Server] Close client:', Client_Index)
        ws2 = None
        # await ws2.close()


if __name__ == "__main__":
    global main_loop
    global config
    global max_client_num
    global client_info_arrays
    global sn_num_arrays
    
    jsonMsg_init('msg_ncm.json')
    config = configparser.ConfigParser()
    
    config.read('/home/ncm_ws/conf.ini')
    max_client_num = int(config['SERVER_PARAMETERS']['MAX_CLIENT_NUM'])
    rows, cols = (max_client_num, 5)
    client_info_arrays = [[0 for i in range(cols)] for j in range(rows)]
    sn_num_arrays = [0 for i in range(rows)]
   
    ncm_ip = config['NCM']['ip']
    ncm_port = int(config['NCM']['port'])
    server_ip = config['SERVER']['ip']
    server_port = int(config['SERVER']['port'])
    udp_init(server_ip, server_port, ncm_ip, ncm_port)

    keyboard_listening_thread = read_from_keyboard()
    keyboard_listening_thread.daemon = True
    keyboard_listening_thread.start()
    '''
    global ncm_end_point_ip
    ncm_end_point_ip = MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['ip_address']
    ncm_end_point_port = MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['port']
    fiveg_anchor_udp_tunnel_port = 0

    ws_port_bytes = ncm_end_point_port.to_bytes(2, 'little')
    ws_ip_bytes = socket.inet_aton(ncm_end_point_ip)
    fiveg_anchor_udp_tunnel_port_bytes = fiveg_anchor_udp_tunnel_port.to_bytes(2, 'little')
    pre_anchor = Set_LTE_Anchor_Msg
    pre_anchor_list = list(pre_anchor)
    pre_anchor_list[2] = 1
    pre_anchor = bytes(pre_anchor_list)
    pre_anchor_msg = pre_anchor + ws_port_bytes + fiveg_anchor_udp_tunnel_port_bytes + ws_ip_bytes
    sendto_server(pre_anchor_msg)
    print('[NCM->server]send pre anchor msg to server')

    set_ip('tun1', ncm_end_point_ip)
    '''
    # route_add('192.168.2.11', '6.6.6.6')#test
    # os.system('ip rule add from 6.6.6.6/32 table 666')
    # os.system('ip route add 0.0.0.0/0 via 6.6.6.6 dev tun1 table 666')

    try:
        print("server running")
        send_key_req()
        send_build_tun_req()
        # start_discover = websockets.serve(discover, preconfig_ip, preconfig_port, ssl=ctx)
        # start_ws_listening = websockets.serve(ws_listening, Sys_Ip, Sys_Port, ssl=ctx)
        #start_ws_listening = await websockets.serve(ws_listening, preconfig_ip, preconfig_port, ssl=ctx)# JZ 04/08/2020
        # global input_listener
        # input_listener = input_listening()
        # start_virtual_server = websockets.serve(virtual_server_listening, Vnic_Ip, Vnic_Port, ssl=ctx)

        tasks = [
            #asyncio.ensure_future(start_ws_listening),
            asyncio.ensure_future(udp_listening()),
            # asyncio.async(input_listener),
            # asyncio.async(start_discover),
            # asyncio.async(start_virtual_server),
            # asyncio.async(periodic_meas()), #2017.10.9
        ]
        main_loop = asyncio.get_event_loop()
        asyncio.get_event_loop().run_until_complete(asyncio.wait(tasks))
        asyncio.get_event_loop().run_forever()

    except Exception as e:
        udp_release()
        print('error:{0}'.format(e))
        print("server stopped")
