## GMA virtual network configuration in conf.ini 

[SERVER_PARAMETERS]

SERVER_VNIC_IP: the first IP address assigned to a GMA client for the virtual "tun" interface

SERVER_VNIC_GW: the IP address of the virtual network interface at the GMA server

SERVER_VNIC_MSK: the subnet mask of the virtual network interface

SERVER_VNIC_DNS: the DNS server IP address of the virtual network interface 

## GMA server port definition in conf.ini 

[NCM]

port: internal UDP socket for ncm_ws38.py (./gma/python) to communicate with gmaserver (./gma/server)

[SERVER]

port: internal UDP socket for gmaserver to communicate with ncm_ws38.py

[WEBSOCK]

**dis_port**: public* TCP socket for discover_ws38.py (./gma/python) to communicate with a GMA client through the "lte" interface

**ncm_port**: public TCP socket for ncm_ws38.py to communicate with a GMA client through the "lte" interface 

virtual_port: internal TCP socket for ncm_ws38.py to communicate with a GMA client through the virtual ("tun") interface 

[SERVER_PARAMETERS]

**WIFI_INTERFACE_IP_PPORT**: public UDP socket for gmaserver to communicate with a GMA client through the "wifi" interface 

**LTE_INTERFACE_IP_PORT**: public UDP socket for gmaserver to communicate with a GMA client through the "lte" interface

UDP_PORT: internal UDP socket for gmaserver to communicate with a GMA client through the virtual ("tun") interface 

**TCP_PORT**: public TCP socket for gmaserver to send "keep-alive" messages to GMA client through the "wifi" or "lte" interface

MEASURE_REPORT_PORT = internal UDP socket for gmaserver to communicate with gmactrl (./gma/ctrl) 


# Note

*: **All public ports must be accessible from GMA client through the corresponding interface (wifi or lte)**   
