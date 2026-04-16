from enum import Enum
from typing import Union, Self

from ipv4addr import IPv4Address
from ethernet import MAC, Ethernet
from arp import ARP
from l2socket import Socket


class RoutingAction(Enum):
	# Packet is sent back to this network card
	LOOPBACK = 0
	# Packet is sent to a device in the LAN
	DIRECT = 1
	# Packet is sent to a gateway
	GATEWAY = 2
	# Packet is broadcasted
	BROADCAST = 3


# Singleton class
class RoutingEntry:
	def __init__(self, address: IPv4Address, mask: IPv4Address, 
			      interface: IPv4Address, action: RoutingAction, 
				  gateway: Union[IPv4Address, None]=None
				 ):
		
		if action == RoutingAction.GATEWAY and gateway is None:
			raise ValueError("GATEWAY action requires non-None gateway parameter")

		self.address = address
		self.mask = mask
		self.interface = interface
		self.action = action
		self.gateway = gateway


class RoutingTable:
	_instance = None

	def __new__(cls) -> Self:
		if cls._instance is None:
			cls._instance = object.__new__(cls)
			cls._instance._table = {}
		return cls._instance
	
	def route(self, socket: Socket, address: IPv4Address) -> tuple[MAC, IPv4Address]:
		'''
		Gets an IP address to route.
		Returns MAC address of next hop
		'''
		for mask_value in sorted(self._table.keys(), reverse=True):
			entries = self._table[mask_value]
			for entry in entries:
				if (address & entry.mask) == entry.address:
					if entry.action == RoutingAction.LOOPBACK:
						return (Ethernet.host_addr, entry.interface)
					elif entry.action == RoutingAction.DIRECT:
						return (ARP.query(socket, address, entry.interface), entry.interface)
					elif entry.action == RoutingAction.GATEWAY:
						return (ARP.query(socket, entry.gateway, entry.interface), entry.interface)
					elif entry.action == RoutingAction.BROADCAST:
						return (Ethernet.broadcast, entry.interface)

	def add_entry(self, entry: RoutingEntry) -> None:
		'''
		Adds entry to the routing table.
		entry - RoutingEntry
		'''
		mask_value = int.from_bytes(entry.mask.addr)
		if mask_value in self._table:
			self._table[mask_value].append(entry)
			return
		
		self._table[mask_value] = [entry]

	def remove_entry(self, entry: RoutingEntry) -> None:
		'''
		Removes entry to the routing table.
		entry - RoutingEntry
		'''
		mask_value = int.from_bytes(entry.mask.addr)
		if mask_value in self._table:
			if entry in self._table[mask_value]:
				self._table[mask_value].remove(entry)
				return
		
		raise ValueError("'entry' not in routing table")

	@classmethod
	def init(cls, host_addr: IPv4Address, subnet_mask: IPv4Address, default_gateway: IPv4Address) -> Self:
		'''
		Initializes the routing table with default entries
		'''
		routing_table = cls()

		full_ip = IPv4Address("255.255.255.255")
		empty_ip = IPv4Address("0.0.0.0")

		routing_table.add_entry(RoutingEntry(
								IPv4Address("127.0.0.1"),
								full_ip,
								IPv4Address("127.0.0.1"),
								RoutingAction.LOOPBACK
							   ))
		routing_table.add_entry(RoutingEntry(
								host_addr,
								full_ip,
								host_addr,
								RoutingAction.LOOPBACK
							   ))
		routing_table.add_entry(RoutingEntry(
								full_ip,
								full_ip,
								host_addr,
								RoutingAction.BROADCAST
							   ))
		routing_table.add_entry(RoutingEntry(
								host_addr & subnet_mask,
								subnet_mask,
								host_addr,
								RoutingAction.DIRECT
							   ))
		routing_table.add_entry(RoutingEntry(
								empty_ip,
								empty_ip,
								host_addr,
								RoutingAction.GATEWAY,
								gateway=default_gateway
							   ))
		
		return routing_table