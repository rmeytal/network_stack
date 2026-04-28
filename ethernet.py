import struct
from enum import Enum
from typing import Self, Callable

from l2socket import Socket


class MAC:
	def __init__(self, addr: bytes | int | str):
		'''
		addr - either an integer or a string representing the MAC address
		'''
		self.addr = addr
		if isinstance(addr, int):
			self.addr = addr.to_bytes(6, byteorder="big")
		elif isinstance(addr, str):
			self.addr = int(addr.replace(":", "").replace("-", ""), base=16).to_bytes(6, byteorder="big")
		elif not isinstance(addr, bytes):
			raise ValueError("'addr' must be bytes, int or string")

	def __str__(self) -> str:
		return ":".join(f"{b:02x}" for b in self.addr)

	def __repr__(self) -> str:
		return f"MAC({self})"

class EtherType(Enum):
	'''
	Enum of all possible EtherTypes
	'''
	# Default value indicating that type field has been replaced by length
	LENGTH = 0

	UNKNOWN = -1

	IPv4 = 0x0800
	ARP = 0x0806
	IPv6 = 0x86DD
	VLAN_TAGGED = 0x8100
	QinQ = 0x88A8
	MPLS = 0x8847
	PPPoE_DISCOVERY = 0x8863
	PPPoE_SESSION = 0x8864
	GOOSE = 0x88B8
	RARP = 0x8035
	PROVIDER_BRIDGE_PROTOCOLS = 0x893A

	def _missing_(*args):
		return EtherType.UNKNOWN


class Ethernet:
	broadcast = MAC("ff:ff:ff:ff:ff:ff")
	host_addr = None

	def __init__(self, destination: MAC, data: bytes, 
			  	 type: EtherType | None=EtherType.IPv4, source: MAC=None):
		'''
		destination - MAC object
		data - bytes
		type - Integer, must be an enum
		source - MAC object
		length - in certain standards, length replaces Ethertype and indicates data length (<1500)
		'''
		self.destination = destination
		self.source = source
		if self.source == None:
			self.source = Ethernet.host_addr
		self.type = type 
		self.data = data

	def send(self, socket: Socket) -> None:
		'''
		Sends the object as an ethernet frame
		'''
		header = struct.pack(f"!6s6sH", 
								self.destination.addr, 
								self.source.addr, 
								self.type.value
							)
		
		socket.send(header + self.data)
	
	def __repr__(self) -> str:
		return ("Ethernet("
		  		f"destination={self.destination}, "
			    f"source={self.source}, "
				f"type={self.type.name}, "
				f"data={self.data})"
			   )

	@classmethod
	def parse(cls, raw_frame: bytes) -> Self:
		'''
		Takes in a raw frame
		Returns Ethernet object
		'''
		header = struct.unpack("!6s6sH", raw_frame[:14])
		data = raw_frame[14:]
		
		return Ethernet(MAC(header[0]), 
						data, 
						source=MAC(header[1]), 
						type=EtherType(header[2])
					   )
							

	@classmethod
	def recv(cls, socket: Socket, filter: Callable[[Self], bool]=(lambda _: True)) -> Self | None:
		'''
		Non-blocking function. Receives an ethernet frame and returns it parsed into
		an 'Ethernet' instance.

		socket - Socket object to recv from
		filter - optional filter function. Must return boolean.
		'''
		raw_frame = socket.recv()
		if raw_frame is not None:
			frame = Ethernet.parse(raw_frame)
			if filter(frame):
				return frame
			
		return None