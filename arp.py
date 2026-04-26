from typing import Self
import struct
import time
from enum import Enum

from ethernet import Ethernet, MAC, EtherType
from ipv4addr import IPv4Address
from l2socket import Socket

class ARPOpcode(Enum):
	REQUEST = 1
	RESPONSE = 2


class ARP:
	cache = {}

	def __init__(self, target_ip: IPv4Address, sender_ip: IPv4Address, opcode: ARPOpcode=ARPOpcode.REQUEST, 
			  	 sender_physical: MAC=None, target_physical: MAC=Ethernet.broadcast):
		'''
		Constructs ARP packet, saves into payload class member.

		target_ip - string or IPv4Address representing address looked for
		sender_ip - string or IPv4Address representing address of searching host
		opcode - operation of ARP packet
		sender_physical - Layer 2 address of sending side
		target_physical - Destination Layer 2 address
		'''

		# Hardware & protocol types (2 bytes each). Ethernet = 1
		self._hardware_type = 1
		self._protocol_type = EtherType.IPv4

		# Hardware & protocol length - length of respective address in bytes (1 byte)
		self._hardware_length = 6
		self._protocol_length = 4

		#Operation - Request = 1, Reply = 2 (2 bytes)
		self._opcode = opcode

		# Sender physical & protocol addresses
		self.sender_physical = sender_physical
		if self.sender_physical == None:
			self.sender_physical = Ethernet.host_addr

		self.sender_virtual = sender_ip

		# Target physical & protocol address
		self.target_physical = target_physical
		self.target_virtual = target_ip

	def send(self, socket: Socket) -> None:
		'''
		Sends ARP message
		'''
		
		# Crafting payload & sending Ethernet frame
		payload = struct.pack("!HHBBH6s4s6s4s", 
							  self._hardware_type, self._protocol_type.value, 
							  self._hardware_length, self._protocol_length,
							  self._opcode.value, 
							  self.sender_physical.addr, self.sender_virtual.addr, 
							  self.target_physical.addr, self.target_virtual.addr
							 )
		
		message = Ethernet(self.target_physical, payload, type=EtherType.ARP)
		message.send(socket)

	def __repr__(self) -> str:
		return ("ARP("
				f"opcode={self._opcode.name},"
				f"sender_physical={self.sender_physical},"
				f"sender_virtual={self.sender_virtual},"
				f"target_physical={self.target_physical},"
				f"target_virtual={self.target_virtual}"
				")"
			   )

	@classmethod
	def parse(cls, raw_packet: bytes) -> Self:
		'''
		Takes in raw_packet, return ARP object
		'''
		ret = object.__new__(cls)
					
		# Parsing ARP response, saving only relevant fields
		(
		 ret._hardware_type, ret._protocol_type, 
		 ret._hardware_length, ret._protocol_length,
		 ret._opcode, 
		 ret.sender_physical, ret.sender_virtual, 
		 ret.target_physical, ret.target_virtual
		) = struct.unpack("!HHBBH6s4s6s4s", raw_packet[:28])

		ret._protocol_type = EtherType(ret._protocol_type)
		ret._opcode = ARPOpcode(ret._opcode)

		ret.sender_physical = MAC(ret.sender_physical)
		ret.sender_virtual = IPv4Address(ret.sender_virtual)
		ret.target_physical = MAC(ret.target_physical)
		ret.target_virtual = IPv4Address(ret.target_virtual)

		return ret

	@classmethod
	def recv(cls, socket: Socket, timeout: int=1, filter: Self | None=None) -> Self:
		'''
		Receives an ARP packet. Doesn't check cache. For cache + recv use query classmethod
		timeout - timeout for response before exception thrown (in seconds)
		filter  - optional variable. If isn't None, function returns an ARP request that is a response to 'filter'
		'''
		if filter is not None:
			# Making sure filter is valid
			if not isinstance(filter, cls):
				raise ValueError("'filter' must either be None ARP with opcode of Request")
			if filter._opcode != ARPOpcode.REQUEST:
				raise ValueError("'filter' must have opcode Request")
			
		start_time = time.time()
		while True:
			if (time.time() - start_time) > timeout:
				raise TimeoutError("No ARP packet received")
			
			resp = Ethernet.recv(socket)
		
			if resp is not None:
				if resp.type == EtherType.ARP:
					ret = ARP.parse(resp.data[:28])

					ARP.cache[ret.sender_virtual.addr] = ret.sender_physical

					# If there's no filter, return first ARP packet received
					if filter is None:
						return ret
				
					# If packet isn't a response
					if ret._opcode != ARPOpcode.RESPONSE:
						continue
					
					# If the filter's target matches received packet's sending address, then returns the response
					if filter.target_virtual == ret.sender_virtual:
						return ret
			
	@classmethod
	def query(cls, socket: Socket, target: IPv4Address, source: IPv4Address) -> MAC:
		'''
		Conducts a full ARP query
		Checks cache, if in cache, returns MAC
		If not, sends a request, waits for a reply
		'''
		if target.addr in cls.cache:
			return cls.cache[target.addr]
		
		request = cls(target, source)
		request.send(socket)

		return cls.recv(socket, filter=request).sender_physical