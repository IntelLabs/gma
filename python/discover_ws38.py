#Copyright(C) 2022 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
#File : discover_ws38.py
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
import netifaces as ni

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3

#ctx.set_ciphers("AES256-SHA")
ctx.set_ciphers("AES256-GCM-SHA384")
#ctx.load_verify_locations("server.crt")
#ctx.check_hostname = False
certfile = "server.crt"
keyfile = "server.key"
ctx.load_cert_chain(certfile, keyfile)#, password=None)
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
        
    #global MX_Discover_Msg
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
    global Sys_Ip
    global Sys_Port
    global Vnic_Port
    global Vnic_Ip
    global IP_Index_Dict
    global SessionID_Index_Dict
    global Index_Websockets
    
    global g_meas_on
    global ws
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

    Sys_Ip = MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['ip_address']
    Sys_Port = MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['port']

    Vnic_Ip = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['gateway']
    Vnic_Port = MX_UP_Setup_Config_Req_Msg['anchor_connections'][0]['vnic_info']['vnic_port']
    IP_Index_Dict = dict()
    SessionID_Index_Dict = dict()
    Index_Websockets = dict()


'''create an unique index for a new client'''
def create_index():
    for i in range(8,256):
        for j in range(5,256):
            tmp = "10.8." + str(i) + "." + str(j)
            if tmp in IP_Index_Dict:
                continue
            else:
                if (i == 0) and (j == 1): #server virtual index 
                    continue;
                else:
                    return [i,j]
    return None

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
        #global sock_send
        global sock_recv

        global local_in
        global local_out

        local_out = (out_ip, out_port)
        local_in = (in_ip, in_port)

        #sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # make socket reuseble
        #sock_recv.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Allow incoming broadcasts
        sock_recv.setblocking(0)
        sock_recv.bind(local_in)

    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] udp_init')

def udp_release():
    try:
        #sock_send.close()
        sock_recv.close()
    except Exception as e:
        print('error:{0}'.format(e))
        print('[error] udp_release')

def sendto_server(msg):
    try:
        #sock_send.sendto(msg, local_out)
        sock_recv.sendto(msg, local_out)
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
                #global ccm_end_point_ip
                #ccm_end_point_ip, ccm_end_point_port = ws1.remote_address
                config = configparser.ConfigParser()
                config.read('/home/ncm_ws/conf.ini')
                ip_address = config['WEBSOCK']['ip']
                port = int(config['WEBSOCK']['ncm_port'])
                interface = config['WEBSOCK']['interface']
                if ip_address == "0.0.0.0":
                    ip_address = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['ip_address'] = ip_address
                MX_System_Update_Msg['ncm_connections'][0]['ncm_end_point']['port'] = port
                await ws1.send(json.dumps(MX_System_Update_Msg))
                break
    except Exception as e:
        print('error:{0}'.format(e))
        print("client disconnected")
    finally:
        print('close discover ws')
        await ws1.close()

def recvfrom_server(): 
    try:
        r, w, e = select.select([sock_recv,], [], [], 0.0001)
        if sock_recv in r:
            msg, addr = sock_recv.recvfrom(1024)
            print(msg)
            print(msg[3])
            return msg
            
        return [0, 0, 0, 0, 0, 0, 0] 
    except Exception as e:
        print('error:{0}'.format(e))
        print('talk with GMA client stopped')
        return 0

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

async def udp_listening():
    try:
        while True:
            #print('udp ws', ws)
            #if ws == None:
            #    await asyncio.sleep(0.00001)
            #    continue
            
            '''Listening to the GMA server'''
            ##global msg_recv 
            ##await asyncio.sleep(0.0001)

            msg_recv = recvfrom_server()
            ##
            if msg_recv == [0,0,0,0,0,0,0]:
                await asyncio.sleep(0.0001)
                continue

            if msg_recv[3] == 25: #start virtual websockets listening 
                start_virtual_server = await websockets.serve(virtual_server_listening, Vnic_Ip, Vnic_Port, ssl=ctx)
                asyncio.run_coroutine_threadsafe(start_virtual_server,main_loop)
                continue

            if len(msg_recv) > 5:
                vnic_index  = msg_recv[5] << 8 | msg_recv[4]
                print(vnic_index)
            else:
                print("message length wrong")
                continue
            if vnic_index in Index_Websockets:
                ws = Index_Websockets[vnic_index]
            else:
                print("no this websockets")
                continue

            #print(ws)
            if msg_recv[3] == 20: #type: Create_Client_Ack
                await ws.send(json.dumps(MX_LTE_Reconfig_Rsp_Msg))
                print('[server->NCM] Recv Create Client Rsp')

                await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                print('[NCM->CCM] send VNIC UP setup config request')

            if msg_recv[3] == 4: #type: WiFi_Link_Up/Down_ACK
                #print('udp ws', ws)
                await ws.send(json.dumps(MX_Wifi_Reconfig_Rsp_Msg))
                if msg_recv[2] == 1:
                    print('[server->NCM] Recv WiFi Link Up Rsp')
                    await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                    print('[NCM->CCM] send WiFi UP setup config request')
                else:
                    print('[server->NCM] Recv WiFi Link Down Rsp')

            if msg_recv[3] == 24: #type: LTE_Link_Up/Down_ACK
                #print('udp ws', ws)
                await ws.send(json.dumps(MX_LTE_Reconfig_Rsp_Msg))
                if msg_recv[2] == 1:
                    print('[server->NCM] Recv LTE Link Up Rsp')
                    await ws.send(json.dumps(MX_UP_Setup_Config_Req_Msg))
                    print('[NCM->CCM] send LTE UP setup config request')
                else:
                    print('[server->NCM] Recv LTE Link Down Rsp')


    except Exception as e:
        print('error:{0}'.format(e))
        print("client disconnected") 
        #asyncio.gather(...,return_exceptions=True)

    #finally:
        print('exit udp listing')
        #await ws.close()

async def virtual_server_listening(ws2,path):
    #global ws
    #ws = ws2
    remote_ip,remote_port = ws2.remote_address
    if remote_ip in IP_Index_Dict:
        Client_Index = IP_Index_Dict[remote_ip]
        Index_Websockets[Client_Index] = ws2
        Client_Index = [(Client_Index & 0x0000FF00)>>8,Client_Index & 0x000000FF]
        print('virtual server begin')
    else:
        print('no this client index')

    try:
        print('discover virtual websocket connection:', ws2)
        while 1:
            '''Listening to virtual websockets'''
            json_message = await ws2.recv()
            #print(json_message)
            message = json.loads(json_message)
	    
            if type_match(message, 'test_report'):
                print('virtual [CCM->NCM] Test msg')
                await ws2.send(json.dumps(MX_Test_Ack))

            if type_match(message, 'mx_session_resume_req'):
                print('virtual [CCM->NCM] mx_session_resume_req')
                sendto_server(add_index(Client_Resume_Req, Client_Index))
                await ws2.send(json.dumps(MX_Session_Resume_Rsp))
                print('[NCM->CCM] Send MX_Session_Resume_Rsp')
                await ws2.send(json.dumps(MX_Qos_Flow_Conf))
                print('[NCM->CCM] Send MX_Qos_Flow_Conf')
                await ws2.send(json.dumps(MX_Gma_Client_Conf))
                print('[NCM->CCM] Send MX_Gma_Client_Conf')

            if type_match(message, 'mx_session_suspend_req'):
                print('virtual [CCM->NCM] mx_session_suspend_req')
                await ws2.send(json.dumps(MX_Session_Suspend_Rsp))
                sendto_server(add_index(Client_Suspend_Begin_Req, Client_Index))

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
                        if server_lte_header_opt == True:
                            server_lte_header_opt_bytes = b'\x01'
                        else:
                            server_lte_header_opt_bytes = b'\x00'

                        lte_link_up_msg = LTE_Link_Up_Msg + \
                                        client_lte_ip_bytes + \
                                        server_lte_tunnel_ip_bytes + \
                                        server_lte_tunnel_port_bytes + \
                                        server_lte_header_opt_bytes 
                    
                        print('[CCM->NCM] Recv mx_reconf_req(LTE)')
                        sendto_server(add_index(lte_link_up_msg, Client_Index))
                        print('[NCM->Server] Send LTE Link Up Req Msg')
                    else:
                        sendto_server(add_index(LTE_Link_Down_Msg, Client_Index))
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
                        server_wifi_tunnel_port =  MX_UP_Setup_Config_Req_Msg['anchor_connections'][0] \
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
                        sendto_server(add_index(wifi_link_up_msg, Client_Index))
                        print('[NCM->Server] Send WiFi Link Up Req Msg')
                    else:
                        sendto_server(add_index(WiFi_Link_Down_Msg, Client_Index))
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
        #sendto_server(add_index(Close_Client_Req_Msg, Client_Index))
        #print('[NCM->Server] Close client:', Client_Index)
        ws2 = None
        #await ws2.close()

if __name__ == "__main__":
    global main_loop;
    jsonMsg_init('msg_ncm.json')
    config = configparser.ConfigParser()
    config.read('/home/ncm_ws/conf.ini')
    #ncm_ip = config['NCM']['ip']
    #ncm_port = int(config['NCM']['port'])
    #meas_periodic = int(config['NCM']['meas_periodic'])

    #server_ip = config['SERVER']['ip']
    #server_port=int(config['SERVER']['port'])

    preconfig_ip = config['WEBSOCK']['ip']
    preconfig_port = int(config['WEBSOCK']['dis_port'])
    preconfig_interface = config['WEBSOCK']['interface']
    if preconfig_ip == "0.0.0.0":
        preconfig_ip = ni.ifaddresses(preconfig_interface)[ni.AF_INET][0]['addr']

    #udp_init(server_ip,server_port,ncm_ip,ncm_port) 
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
    #route_add('192.168.2.11', '6.6.6.6')#test
    #os.system('ip rule add from 6.6.6.6/32 table 666')
    #os.system('ip route add 0.0.0.0/0 via 6.6.6.6 dev tun1 table 666')
    

    try:
        print("discover running")
        #start_discover = websockets.serve(discover, "0.0.0.0", preconfig_port, ssl=ctx)
        start_discover = websockets.serve(discover, preconfig_ip, preconfig_port, ssl=ctx)
        #start_ws_listening = websockets.serve(ws_listening, Sys_Ip, Sys_Port, ssl=ctx)
        #start_ws_listening = websockets.serve(ws_listening, preconfig_ip, Sys_Port, ssl=ctx)  #JZ 04/08/2020
        #start_virtual_server = websockets.serve(virtual_server_listening, Vnic_Ip, Vnic_Port, ssl=ctx)

        tasks = [
                    #asyncio.async(start_ws_listening),
                    #asyncio.async(udp_listening()),
                    asyncio.ensure_future(start_discover),
                    #asyncio.async(start_virtual_server),
                    #asyncio.async(periodic_meas()), #2017.10.9
                ]
        main_loop = asyncio.get_event_loop()
        asyncio.get_event_loop().run_until_complete(asyncio.wait(tasks))
        asyncio.get_event_loop().run_forever()
        
    except Exception as e:
        udp_release()
        print('error:{0}'.format(e))
        print("server stopped")    
