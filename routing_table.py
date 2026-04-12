from ipv4addr import IPv4Address
from ethernet import MAC
from arp import ARP
from enum import Enum
from typing import Union


class RoutingAction(Enum):
	# Packet is sent back to this network card
	LOOPBACK = 0
	# Packet is sent to a device in the LAN
	DIRECT = 1
	# Packet is sent to a gateway
	GATEWAY = 2


class RoutingEntry:
	def __init__(self, address: IPv4Address, mask: IPv4Address, 
			      interface: IPv4Address, action: RoutingAction, 
				  gateway: Union[IPv4Address, None]=None
				 ):
		
		if action == RoutingAction.GATEWAY and gateway == None:
			raise ValueError("GATEWAY action requires non-None gateway parameter")

		self.address = address
		self.mask = mask
		self.interface = interface
		self.action = action
		self.gateway = gateway


class RoutingTable:
	def __init__(self):
		self._table = {}
	
	def __call__(self, address: IPv4Address) -> MAC:
		'''
		Gets an IP address to route.
		Returns MAC address of next hop
		'''
		for mask_value in sorted(self._table.keys(), reverse=True):
			entries = self._table[mask_value]
			for entry in entries:
				if (address & entry.mask) == entry.address:

					if entry.action == RoutingAction.LOOPBACK:
						return MAC.host_address
					elif entry.action == RoutingAction.DIRECT:
						return ARP(address).send()
					elif entry.action == RoutingAction.GATEWAY:
						return ARP(entry.gateway).send()


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