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

The GMA server source files are stored in the following folder: ./MultiAccess_with_Private_5G_Reference_Implementation_1.0.0/MultiAccess_with_Private_5G/GMA/gmaserver/serverapp/, and there are three folders: 

   ./ctrl  (for "gmactrl")

   ./python (for "gmaserver")
   
   ./server (for "gmaserver")


## Required libraries and tools (client)

sudo apt-get update 

sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

sudo apt-get install net-tools

## Required libraries and tools (server)

sudo apt-get install iptables

sudo apt-get install iproute2 

sudo apt-get install net-tools

sudo apt-get install libboost-all-dev

sudo apt-get install libssl-dev

sudo apt-get install python3

sudo apt-get install python3-pip

sudo pip install websockets

sudo pip install pycryptodomex

## How to build "gmaclient"

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

![GMA Testbed](https://github.com/IntelLabs/gma/blob/master/GMA-testbed.png)

## How to create a new SSL certificate for "gmaserver"

openssl genrsa -out server.key 3072

openssl req -new -key server.key -out server.csr (input user info)

openssl x509 -req -in server.csr -out server.crt -signkey server.key -days 3650

cp ./server.key ./python

cp ./server.csr ./python

cp ./server.crt ./python

## How to update SSL certification for "gmaclient"

Run the following command to generate client.crt from server.crt
<pre>
sed '/./{s/^/        "&/;s/$/&\\n"/}' server.crt > client.crt
</pre>

Copy the contents of client.crt to ./client/root_certificates.hpp to replace std::string const cert content.

Compile the GMA client again

## How to run "gmaserver" 

Open the first terminal on the server and run the following command:  
	
 	cd ./server
	
 	sudo ./gmaserver

Open the 2nd terminal on the server and run the following command:  

	cd ./python

	sudo python3 ncm_ws38.py

Open the 3rd terminal on the server and run the following command:  

 	cd ./python
	
 	sudo python3 discover_ws38.py

## How to update ./config.txt for "gmaclient"

modify the following parameters in config.txt:  

	SERVER_NCM_IP=a.b.c.d

	WLAN_INTERFACE_CONFIG=wlan0

	LTE_INTERFACE_CONFIG=wwan0

	SERVER_DNS=gmaserver.apps.local

(wlan0: network interface for wifi, wwan0: network interface for cellular, gmaserver.apps.local: local DNS name for GMA service running at Edge, a.b.c.d is the (GMA service) IP address at the edge node via LTE)

## How to start "gmaclient" 

cd ./client

sudo ./gmaclient
