#Copyright(C) 2022 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
#File : northbound_interface.py

import zmq
import sys
import threading
import time
from random import randint, random
import json
import pandas as pd

class MeasurementReport:
    """Measurement Report Structure.
    """
    def __init__(self, ok_flag, terminate_flag, df_list):
        """Initil the measurement report.

        Args:
            ok_flag (Bool): indicate whehter the measurement is valid.
            terminate_flag (_type_): indicate whether the environement is stopped (disconnected).
            df_list (list[pandas.dataframe]): a list of dataframe that stores the network ststs
        """
        self.ok_flag = ok_flag
        self.terminate_flag = terminate_flag
        self.df_list = df_list

class NorthboundInterface():
    """networkgym northbound interface client.
    
    Northbound interface connects the network gym client to the network gym server. It commucates the network stats and policy.
    """
    def __init__(self, id, config_json):
        """Initial function

        Args:
            id (int): client ID
            config_json (json): configuration file
        """
        self.identity = u'%s-%s-%d' % (config_json["session_name"],config_json["rl_agent_config"]["agent"], id)
        self.config_json=config_json
        self.socket = None
        self.end_ts = None # sync the timestamp between obs and action

    #connect to network gym server using ZMQ socket
    def connect(self):
        """Connect to the network gym server.
        """
        context = zmq.Context()
        self.socket = context.socket(zmq.DEALER)
        self.socket.plain_username = bytes(self.config_json["session_name"], 'utf-8')
        self.socket.plain_password = bytes(self.config_json["session_id"], 'utf-8')
        self.socket.identity = self.identity.encode('ascii')
        self.socket.connect('tcp://localhost:'+str(self.config_json["algorithm_client_port"]))
        print('%s started' % (self.identity))
        print(self.identity + " Sending GMASim Start Request…")
        if self.config_json["session_name"] == "test":
            print("If no reposne after sending the start requst, the port forwarding may be broken...")
        else:
            print("If no response from the server, it could be the session_name and session_id is wrong or the port forwardng is broken. "
             +"You may change the 'session_name' and 'session_id' to 'test' to test port fowarding")
            
        gma_start_request = self.config_json["gmasim_config"]
        self.socket.send(json.dumps(gma_start_request, indent=2).encode('utf-8'))#send start simulation request

    #send action to network gym server
    def send (self, action_list):
        """Send the Policy to the server and environment.

        Args:
            action_list (json): netowkr policy
        """

        if self.config_json['gmasim_config']['GMA']['respond_action_after_measurement']:
            action_json = self.config_json["gmasim_action_template"] #load the action format from template
            action_json["end_ts"]=self.end_ts
            action_json["downlink"]=self.config_json['gmasim_config']["downlink"]
            action_json["action_list"] = action_list

            json_str = json.dumps(action_json, indent=2)
            #print(identity +" Send: "+ json_str)
            self.socket.send(json_str.encode('utf-8')) #send action

    #receive a msg from network gym server
    def recv (self):
        """Receive a message from the network gym server.

        Returns:
            MeasurementReport: the measurement of network stats from the environment
        """

        reply = self.socket.recv()
        relay_json = json.loads(reply)

        #print(relay_json)        

        if relay_json["type"] == "no-available-worker":
            # no available network gym worker, retry the request later
            print(self.identity+" Receive: "+reply.decode())
            print(self.identity+" "+"retry later...")
            quit()

        elif relay_json["type"] == "gmasim-end":
            # simulation end from the network gym server
            terminate_flag = True
            ok_flag = False
            df_list = []

            print(self.identity +" Receive: "+ reply.decode())
            print(self.identity+" "+"Simulation Completed.")
            # quit()
            return MeasurementReport(ok_flag, terminate_flag, df_list)
            # return [],[],[],[],[]
        elif  relay_json["type"] == "gmasim-measurement":
            return self.process_measurement(relay_json)

        elif relay_json["type"] == "gmasim-error":
            # error happened. Check the error msg.
            print(self.identity +" Receive: "+ reply.decode())
            print(self.identity +" "+ "Simulation Stopped with ***[Error]***!")
            quit()
        else:
            # Unkown msg type, please check.This should not happen. 
            print(self.identity +" Receive: "+ reply.decode())
            print(self.identity +" "+ "***[ERROR]*** unkown msg type!")
            quit()
     
    #process measurement from network gym server
    def process_measurement (self, reply_json):
        """Fliter the raw network measurements (json) and translate them to pandas.dataframe format.

        Args:
            reply_json (json): the message from the server

        Returns:
            MeasurementReport: MeasurementReport
        """
        df_list = []
        ok_flag = True
        terminate_flag = False
        df = pd.json_normalize(reply_json['metric_list']) 
        # print(df)

        if self.config_json['gmasim_config']['downlink']:
            df = df[df['direction'] == 'DL'].reset_index(drop=True)
        else:
            df = df[df['direction'] == 'UL'].reset_index(drop=True)
        
        df_phy = df[df['group'] == 'PHY'].reset_index(drop=True)
        df_phy_lte = df_phy[df_phy['cid'] == 'LTE'].reset_index(drop=True)

        df_phy_lte_max_rate = []
        df_phy_wifi_max_rate = []
        
        '''
        start_ts  end_ts  cid direction group      name  user  value  unit
        0    1900.0  2000.0  LTE        DL   PHY  max_rate     0   75.0  mbps
        1    1900.0  2000.0  LTE        DL   PHY  max_rate     1   75.0  mbps
        2    1900.0  2000.0  LTE        DL   PHY  max_rate     2   75.0  mbps
        3    1900.0  2000.0  LTE        DL   PHY  max_rate     3   75.0  mbps
        start_ts  end_ts    cid direction group      name  user  value  unit
        0    1900.0  2000.0  Wi-Fi        DL   PHY  max_rate     0   65.0  mbps
        1    1900.0  2000.0  Wi-Fi        DL   PHY  max_rate     1   65.0  mbps
        2    1900.0  2000.0  Wi-Fi        DL   PHY  max_rate     2   65.0  mbps
        3    1900.0  2000.0  Wi-Fi        DL   PHY  max_rate     3   65.0  mbps
        start_ts  end_ts  cid direction group     name  user   value  unit
        0    1900.0  2000.0  All        DL   GMA  tx_rate     0  34.151  mbps
        1    1900.0  2000.0  All        DL   GMA  tx_rate     1  34.151  mbps
        2    1900.0  2000.0  All        DL   GMA  tx_rate     2  34.383  mbps
        3    1900.0  2000.0  All        DL   GMA  tx_rate     3  34.383  mbps
           start_ts  end_ts    cid direction group name  user  value unit
        0    1900.0  2000.0  Wi-Fi        DL   GMA  owd     0    0.0   ms
        1    1900.0  2000.0    LTE        DL   GMA  owd     0  190.0   ms
        2    1900.0  2000.0  Wi-Fi        DL   GMA  owd     1    0.0   ms
        3    1900.0  2000.0    LTE        DL   GMA  owd     1  300.0   ms
        4    1900.0  2000.0  Wi-Fi        DL   GMA  owd     2   18.0   ms
        5    1900.0  2000.0    LTE        DL   GMA  owd     2   21.0   ms
        6    1900.0  2000.0  Wi-Fi        DL   GMA  owd     3   10.0   ms
        7    1900.0  2000.0    LTE        DL   GMA  owd     3  188.0   ms
        '''


        if not df_phy_lte.empty:
            # process PHY LTE measurement

            df_phy_lte_start_ts = df_phy_lte[df_phy_lte['name'] == 'start_ts'].reset_index(drop=True)
            df_phy_lte_end_ts = df_phy_lte[df_phy_lte['name'] == 'end_ts'].reset_index(drop=True)

            #check PHY LTE timestamps of all users are the same
            if 1==len(set(df_phy_lte_start_ts['value'])) and 1==len(set(df_phy_lte_end_ts['value'])):
                start_ts = df_phy_lte_start_ts['value'][0]
                end_ts = df_phy_lte_end_ts['value'][0]
                self.end_ts = end_ts
                df_phy_lte_max_rate = df_phy_lte[df_phy_lte['name'] == 'max_rate'].reset_index(drop=True)
                df_phy_lte_max_rate.insert(0,'end_ts', end_ts)
                df_phy_lte_max_rate.insert(0,'start_ts', start_ts)
                df_phy_lte_max_rate['unit'] = 'mbps'
                #print(df_phy_lte_max_rate)

                df_phy_lte_slice_id = df_phy_lte[df_phy_lte['name'] == 'slice_id'].reset_index(drop=True)
                df_phy_lte_slice_id.insert(0,'end_ts', end_ts)
                df_phy_lte_slice_id.insert(0,'start_ts', start_ts)
                #print(df_phy_lte_slice_id)

                df_phy_lte_rb_usage = df_phy_lte[df_phy_lte['name'] == 'rb_usage'].reset_index(drop=True)
                df_phy_lte_rb_usage.insert(0,'end_ts', end_ts)
                df_phy_lte_rb_usage.insert(0,'start_ts', start_ts)
                df_phy_lte_rb_usage['unit'] = '%'
                # print(df_phy_lte_rb_usage)

            else:
                print(self.identity+" "+"ERROR, PHY LTE timestamp is not the same")

        df_phy_wifi = df_phy[df_phy['cid'] == 'Wi-Fi'].reset_index(drop=True)
        if not df_phy_wifi.empty:
            # process PHY Wi-Fi measurement
            df_phy_wifi_start_ts = df_phy_wifi[df_phy_wifi['name'] == 'start_ts'].reset_index(drop=True)
            df_phy_wifi_end_ts = df_phy_wifi[df_phy_wifi['name'] == 'end_ts'].reset_index(drop=True)

            #check PHY Wi-Fi timestamps of all users are the same
            if 1==len(set(df_phy_wifi_start_ts['value'])) and 1==len(set(df_phy_wifi_end_ts['value'])):
                start_ts = df_phy_wifi_start_ts['value'][0]
                end_ts = df_phy_wifi_end_ts['value'][0]
                self.end_ts = end_ts
                df_phy_wifi_max_rate = df_phy_wifi[df_phy_wifi['name'] == 'max_rate'].reset_index(drop=True)
                df_phy_wifi_max_rate.insert(0,'end_ts', end_ts)
                df_phy_wifi_max_rate.insert(0,'start_ts', start_ts)
                df_phy_wifi_max_rate['unit'] = 'mbps'
                #print(df_phy_wifi_max_rate)

            else:
                print(self.identity+" "+"ERROR, PHY LTE timestamp is not the same")

        df_gma = df[df['group'] == 'GMA'].reset_index(drop=True)
        if not df_gma.empty:
            # process GMA measurement
            df_gma_start_ts = df_gma[df_gma['name'] == 'start_ts'].reset_index(drop=True)
            df_gma_end_ts = df_gma[df_gma['name'] == 'end_ts'].reset_index(drop=True)

            #check GMA timestamps of all users are the same
            if 1==len(set(df_gma_start_ts['value'])) and 1==len(set(df_gma_end_ts['value'])):
                start_ts = df_gma_start_ts['value'][0]
                end_ts = df_gma_end_ts['value'][0]

                self.end_ts = end_ts
                df_load = df_gma[df_gma['name'] == 'tx_rate'].reset_index(drop=True)
                df_load.insert(0,'end_ts', end_ts)
                df_load.insert(0,'start_ts', start_ts)
                df_load['unit'] = 'mbps'
                #print(df_load)

                df_rate = df_gma[df_gma['name'] == 'rate'].reset_index(drop=True)
                #df_rate = df_rate[df_rate['cid'] == 'All'].reset_index(drop=True)

                df_rate.insert(0,'end_ts', end_ts)
                df_rate.insert(0,'start_ts', start_ts)
                df_rate['unit'] = 'mbps'
                #print(df_rate)

                df_qos_rate = df_gma[df_gma['name'] == 'qos_rate'].reset_index(drop=True)

                df_qos_rate.insert(0,'end_ts', end_ts)
                df_qos_rate.insert(0,'start_ts', start_ts)
                df_qos_rate['unit'] = 'mbps'
                #print(df_qos_rate)

                df_owd = df_gma[df_gma['name'] == 'owd'].reset_index(drop=True)
                #df_owd = df_owd[df_owd['cid'] == 'All'].reset_index(drop=True)
                df_owd.insert(0,'end_ts', end_ts)
                df_owd.insert(0,'start_ts', start_ts)
                df_owd['unit'] = 'ms'
                #print(df_owd)

                df_split_ratio = df_gma[df_gma['name'] == 'split_ratio'].reset_index(drop=True)
                df_split_ratio.insert(0,'end_ts', end_ts)
                df_split_ratio.insert(0,'start_ts', start_ts)
                #print(df_split_ratio)

                df_ap_id = df_gma[df_gma['name'] == 'ap_id'].reset_index(drop=True)
                df_ap_id.insert(0,'end_ts', end_ts)
                df_ap_id.insert(0,'start_ts', start_ts)
                #print(df_ap_id)

                df_delay_violation = df_gma[df_gma['name'] == 'delay_violation'].reset_index(drop=True)
                df_delay_violation.insert(0,'end_ts', end_ts)
                df_delay_violation.insert(0,'start_ts', start_ts)
                df_delay_violation['unit'] = '%'

                #print(df_delay_violation)

                df_ok = df[df['name'] == 'measurement_ok'].reset_index(drop=True)
                df_ok.insert(0,'end_ts', end_ts)
                df_ok.insert(0,'start_ts', start_ts)
                
                if(df_ok['value'].min() < 1):
                    #print("[WARNING], some users may not have a valid measurement, for qos_steering case, the qos_test is not finished before a measurement return...")
                    #print(df_ok)
                    ok_flag = False
            else:
                print(self.identity+" "+"ERROR, GMA timestamp is not the same")
        
        #return True, df_phy_lte_max_rate, df_phy_wifi_max_rate, df_load, df_rate, df_qos_rate, df_owd, df_split_ratio

        df_list.append(df_phy_lte_max_rate)
        df_list.append(df_phy_wifi_max_rate)
        df_list.append(df_load)
        df_list.append(df_rate)
        df_list.append(df_qos_rate)
        df_list.append(df_owd)
        df_list.append(df_split_ratio)
        df_list.append(df_ap_id)
        df_list.append(df_phy_lte_slice_id)
        df_list.append(df_phy_lte_rb_usage)
        df_list.append(df_delay_violation)

        return MeasurementReport(ok_flag, terminate_flag, df_list)