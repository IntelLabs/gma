# Generic Multi-Access Network Virtualization

Generic Multi-Access (GMA) Network Virtualization is a client/server-based software framework to virtualize multiple access networks, e.g. Wi-Fi, LTE/5G, etc., and manage data traffic at the edge for meeting diverse requirements (coverage, mobility, throughput, latency, and reliability) of emerging applications, e.g., AR/VR, industrial apps, cloud-gaming, etc. It supports various multi-path traffic managmenet operations, including switching, splitting, and duplicating. Please visit our blog (https://www.intel.com/content/www/us/en/research/blogs/multi-access-traffic-management-edge.html) and the IETF draft (https://www.ietf.org/id/draft-zhu-intarea-gma-control-04.txt) for more details. 

## Required OS

ubuntu20.04 

## Required libraries
sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

## How to build "gmacient" ?

cd ./GMAlib/lib

make -B

cd ../../client

make -B

## How to install "gmaclient" ?

sudo apt-get update 

sudo apt-get install net-tools

sudo makdir /home/gmaclient

sudo chmod 777 ./gmaclient

cd ./client

cp ./gmaclient /home/gmaclient/

cp ./config.txt /home/gmaclient/

## How to update ./config.txt ?

modify the following parameters in config.txt:  

	SERVER_NCM_IP=a.b.c.d

	WLAN_INTERFACE_CONFIG=wlan0

	LTE_INTERFACE_CONFIG=wwan0

	SERVER_DNS=gmaserver.apps.local

(wlan0: network interface for wifi, wwan0: network interface for cellular, gmaserver.apps.local: local DNS name for GMA service running at Edge, a.b.c.d is the (GMA service) IP address at the edge node via LTE)

## How to start "gmaclient" ?

cd /home/gmaclient

sudo ./gmaclient
