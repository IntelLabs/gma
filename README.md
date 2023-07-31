# Generic Multi-Access Network Virtualization

Generic Multi-Access (GMA) Network Virtualization is a client/server-based software framework to virtualize multiple access networks, e.g. Wi-Fi, LTE/5G, etc., and manage data traffic at the edge for meeting diverse requirements (coverage, mobility, throughput, latency, and reliability) of emerging applications, e.g., AR/VR, industrial apps, cloud-gaming, etc. It supports various multi-path traffic managmenet operations, including switching, splitting, and duplicating. Please visit our blog (https://www.intel.com/content/www/us/en/research/blogs/multi-access-traffic-management-edge.html) and the IETF draft (https://www.ietf.org/id/draft-zhu-intarea-gma-control-03.txt) for more details. GMA server software is available from https://www.intel.com/content/www/us/en/developer/articles/reference-implementation/multi-access-with-private-5g.html . 

## OS

ubuntu20.04 

## How to download GMA server source files 

Download the installer from https://software.intel.com/iot/edgesoftwarehub/download/home/multi-access-with-private-5g . You would need to create an account if you don't have one. 

Unzip the downloaded file (multi-access-with-private-5g.zip) to a Linux machine with Internet access. 

Go into the folder, and run the following commands:

    sudo chmod +x edgesoftware

    sudo ./edgesoftware download

The GMA server source code are stored in the following folder: ./MultiAccess_with_Private_5G_Reference_Implementation_1.0.0/MultiAccess_with_Private_5G/GMA/gmaserver/serverapp/  


## Required libraries (client)
sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

## Required libraries and SW tools (server)
sudo apt-get install iptables

sudo apt-get install iproute2 

sudo apt-get install net-tools

sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

sudo apt-get install python3

sudo apt-get install python3-pip

sudo pip install websockets

sudo pip install pycryptodomex

## How to build "gmacient"
cd ./GMAlib/lib

make -B

cd ../../client

make -B

## How to build "gmaserver"
cd ./server

make -B

## How to build "gmactrl"
cd ./ctrl

make -B

## How to install "gmaserver"

sudo makdir /home/ncm_ws

cp ./server/conf.ini /home/ncm_ws

cp ./server/server_config.txt /home/ncm_ws

## How to update ./conf.ini for "gmaserver"

modify the parameters in conf.ini: "interface", "WLAN_INTERFACE_CONFIG", "LTE_INTERFACE_CONFIG", "FORWARD_INTERFACE_CONFIG" as follows 

	interface=eth0
	WLAN_INTERFACE_CONFIG = eth1
	LTE_INTERFACE_CONFIG = eth0
	FORWARD_INTERFACE_CONFIG = eth2
	MEASURE_REPORT_NIC = eth3

(eth0: ingress network interface for cellular, eth1: ingress network interface for wifi, eth2: egress network interface Internet access, eth3: network interface for remote management)

## How to run the GMA server 

cd ./server

sudo ./gmaserver

cd ./python

sudo python3 ncm_ws38.py

sudo python3 discover_ws38.py

## How to install "gmaclient"

sudo apt-get update 

sudo apt-get install net-tools

sudo makdir /home/gmaclient

sudo chmod 777 ./gmaclient

cp ./gmaclient /home/gmaclient/

cp ./config.txt /home/gmaclient/

cp ./server.crt /home/gmaclient/

## How to update ./config.txt for "gmaclient"

modify the following parameters in config.txt:  

	SERVER_NCM_IP=a.b.c.d

	WLAN_INTERFACE_CONFIG=wlan0

	LTE_INTERFACE_CONFIG=wwan0

	SERVER_DNS=gmaserver.apps.local

(wlan0: network interface for wifi, wwan0: network interface for cellular, gmaserver.apps.local: local DNS name for GMA service running at Edge, a.b.c.d is the (GMA service) IP address at the edge node via LTE)

## How to start "gmaclient" 

cd /home/gmaclient

sudo ./gmaclient
