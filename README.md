# PROJECT NOT UNDER ACTIVE MANAGEMENT #  
This project will no longer be maintained by Intel.  
Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  
Intel no longer accepts patches to this project.  
 If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
  
# Generic Multi-Access Network Virtualization

Generic Multi-Access (GMA) Network Virtualization is a client/server-based software framework to virtualize multiple access networks, e.g. Wi-Fi, LTE/5G, etc., and manage data traffic at the edge for meeting diverse requirements (coverage, mobility, throughput, latency, and reliability) of emerging applications, e.g., AR/VR, industrial apps, cloud-gaming, etc. It supports various multi-path traffic managmenet operations, including switching, splitting, and duplicating. Please visit our blog (https://www.intel.com/content/www/us/en/research/blogs/multi-access-traffic-management-edge.html) and the IETF draft (https://datatracker.ietf.org/doc/draft-zhu-intarea-gma-control/) for more details. 

## OS

ubuntu 22.04 64bit

## HW and Network Configuration (for a simple two-node setup)

Setup two Linux machines to operate as GMA client and GMA server, reespectively

Install two ethernet adapters on both machines and have them connected (one is used as "Wi-Fi" and the other is used as "LTE")

Create two default routes (with different subnets) on GMA client using the two Ethernet connections, and configure the GMA server as their gateway, respectively

Install a 3rd ethernet adapter on GMA server, and configure it as the default route for Internet access

Optionally, setup a 3rd Linux machine to operate as GMA controller, or use the same machine for both GMA server and GMA controller


## Step 1: download "gmaserver" and "gmactrl" source files on GMA server

Download the following three folders from this repo to the GMA server: 

	./ctrl  (for "gmactrl")
	./python (for "gmaserver")
   	./server (for "gmaserver")

## Step 2: download "gmaclient" source files on GMA client 

Download both folders ("GMAlib" and "client") from this repo 

## Step 3: install required libraries and tools on GMA client

sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

sudo apt-get install net-tools

sudo apt-get install g++

## Step 4: install required libraries and tools on GMA server

sudo apt-get install iptables

sudo apt-get install iproute2 

sudo apt-get install net-tools

sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

sudo apt-get install python3

sudo apt-get install python3-pip

sudo pip install websockets

sudo pip install pycryptodomex

sudo pip install netifaces

sudo apt-get install g++

## Step 5: build "gmaserver" on GMA server
cd ./server

make -B

## Step 6: build "gmactrl" on GMA server
cd ./ctrl

make -B

## Step 7: install configuration files on GMA server

sudo makdir /home/ncm_ws

cp ./server/conf.ini /home/ncm_ws

cp ./server/server_config.txt /home/ncm_ws

## Step 8: configure network interface & downlink flow on GMA server

Modify the parameters in conf.ini (under /home/ncm_ws): "interface", "WLAN_INTERFACE_CONFIG", "LTE_INTERFACE_CONFIG", "FORWARD_INTERFACE_CONFIG" according to your local environment: 

	interface=eth0
	WLAN_INTERFACE_CONFIG = eth1
	LTE_INTERFACE_CONFIG = eth0
	FORWARD_INTERFACE_CONFIG = eth2
	MEASURE_REPORT_NIC = eth3

(eth0: ingress network interface for cellular, eth1: ingress network interface for wifi, eth2: egress network interface Internet access, eth3: network interface for remote management)

Modify the parameters in confi.ini: "RT_FLOW_DSCP", "HR_FLOW_DSCP" according to your local environment: 

	RT_FLOW_DSCP = 2
	HR_FLOW_DSCP = 1

Downlink packets with DSCP = 2 are classified as the "Real-Time" flow using the steering mode, and those with DSCP = 1 are classified as the "High-Reliability" flow using the duplication mode, and all other packets are classified as the "Non Real-Time (Best Effort)" flow using the splitting mode. For example, the following commands set and unset DSCP to "1" for all downlink UDP flows to 10.8.0.9 respectively: 

	sudo iptables -t mangle -A OUTPUT -d 10.8.0.9 -p udp -j TOS --set-tos 1
	sudo iptables -t mangle -D OUTPUT -d 10.8.0.9 -p udp -j TOS --set-tos 1

Set ENABLE_DL_QOS_CONFIG to "1" to enable downlink traffic shapping (optional)

Use the tfc command in step 15 to configure uplink flows. Notice that uplink "Non Real-Time" flow uses the steering mode because the splitting mode is only supported for downlink in this release.  

![GMA Testbed](https://github.com/IntelLabs/gma/blob/master/GMA-testbed.png)

## Step 9: create a new SSL certificate on GMA server

openssl genrsa -out server.key 3072

openssl req -new -key server.key -out server.csr (input user info)

openssl x509 -req -in server.csr -out server.crt -signkey server.key -days 3650

cp ./server.key ./python

cp ./server.csr ./python

cp ./server.crt ./python

## Step 10: update SSL certification on GMA client

Run the following command to generate client.crt from server.crt
<pre>
sed '/./{s/^/        "&/;s/$/&\\n"/}' server.crt > client.crt
</pre>

Copy the contents of client.crt to ./client/root_certificates.hpp to replace std::string const cert content.

## Step 11: build "gmaclient" on GMA client

cd ./GMAlib/lib

make -B

cd ../../client

make -B

## Step 12: run "gmaserver" on GMA server

Open the first terminal on the server and run the following command:  
	
 	cd ./server
	
 	sudo ./gmaserver

Open the 2nd terminal on the server and run the following command:  

	cd ./python

	sudo python3 ncm_ws38.py

Open the 3rd terminal on the server and run the following command:  

 	cd ./python
	
 	sudo python3 discover_ws38.py

## Step 13: update network configuration on GMA client

modify the following parameters in config.txt (under ./client):  

	SERVER_NCM_IP=a.b.c.d

	WLAN_INTERFACE_CONFIG=wlan0

	LTE_INTERFACE_CONFIG=wwan0

	SERVER_DNS=gmaserver.apps.local

(wlan0: network interface for wifi, wwan0: network interface for cellular, gmaserver.apps.local: local DNS name for GMA service running at Edge, a.b.c.d is the IP address (e.g. 192.168.1.a at Step 8) at the GMA server via LTE)

sudo mkdir /home/gmaclient

sudo cp ./config.txt /home/gmaclient/

## Step 14: start "gmaclient" on GMA client

cd ./client

run the followng command to add the default route via Wi-Fi or LTE if it is not present

    sudo ip route add default via 192.168.1.a dev wwan0 metric 7001

    sudo ip route add default via 192.168.0.b dev wlan0 metric 7000

sudo ./gmaclient

## Step 15: start "gmactrl" on GMA server


cd ./ctrl

Modify the parameters in Params_config.txt according to your local environment: 

     SERVER_IP_CONIFG=192.168.3.c

sudo ./gmactl 

run the following command to control traffic splitting for a GMA client: 

Traffic Steering Command: tsc [clientIndex] [RTtsc] [NRTtsc] [NRTk1] [NRTk2] [NRTl]
               
               clientIndex: the last two bytes of the client IP address
               RTtsc: traffic steering command for RT (Real-Time) flow
                 0: default (DL & UL over Wi-Fi for RT flow)
                 1: DL-over-LTE for RT flow
                 2: UL-over-LTE for RT flow
                 3: UL & DL-over-LTE for RT flow
                 4: no update for RT flow
               NRTtsc: traffic steering command for NRT (Non Real-Time or Best-Effort) flow
                 0: disable dynamic DL splitting for NRT flow
                 1: enable dynamic DL splitting for NRT flow 
                 16: no update for NRT flow
               NRTk1: the Wi-Fi burst size (pkts), e.g. 16
               NRTK2: the LTE burst size, e.g. 16 
               NRTl: the splitting cycle (pkts), e.g. 32

run the following command to control uplink traffic classification for a GMA client: 

Traffic Flow Configuration: tfc [clientIndex] [flowId] [protoType] [portStart] [portend]  
               
               clientIndex: the last two bytes of the client IP address
               flowId:
                 1: high-reliability (duplication) flow 
                 2: real-time flow
                 3: non real-time flow (default)
               protoType:
                 0: disable UL QoS flow classification (default)
                 1: tcp
                 2: udp
                 3: icmp
               portStart: the lower bound of (UDP or TCP) destination port (not used if "icmp")
               portEnd: the upper bound of (UDP or TCP) destination port (not used if "icmp")

run the following command to control (downlink) traffic shaping for a GMA client: 

Traffic Rate Configuration: txc [clientIndex] [Link] [R] [NRT_R] [Q]

               clientIndex: the last two bytes of the client IP address
               Link:
                 0: WiFi 
                 1: LTE
               R: the maximum (per-client & per-link) tx rate (Mbps)
               NRT_R: the assured maximum tx rate for NRT traffic (NRT_R < R)
               Q: the Tx queue length (pkts)

## Testcases & Examples

Please check out testcases & examples from this link: 

               https://www.intel.com/content/www/us/en/developer/articles/reference-implementation/multi-access-with-private-5g.html
