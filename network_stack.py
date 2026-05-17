from l2socket import Socket
from ip import IP
from ethernet import Ethernet, MAC
from ipv4addr import IPv4Address
from routing_table import RoutingTable

import uuid

def init(iface: str, ip_info: tuple[str, str, str]) -> None:
	'''
	Library initialization function
	iface - Interface name
	ip_info - tuple containing IP information: (host address, subnet mask, default gateway)

	Function sets the default socket interface
	Sets IP host_addr, subnet_mask, default_gateway

	Calls RoutingTable.init (initializes routing table)
	Sets Ethernet host_addr
	'''
	Socket.iface = iface

	IP.host_addr = IPv4Address(ip_info[0])
	IP.subnet_mask = IPv4Address(ip_info[1])
	IP.default_gateway = IPv4Address(ip_info[2])

	IP.routing_table = RoutingTable.init(IP.host_addr, IP.subnet_mask, IP.default_gateway)

	Ethernet.host_addr = MAC(uuid.getnode())
