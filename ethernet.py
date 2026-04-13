from scapy.all import conf
import struct
import uuid
from enum import Enum
from typing import Union, Self


class MAC:
	def __init__(self, addr: Union[bytes, int, str]):
		'''
		addr - either an integer or a string representing the MAC address
		'''
		self.addr = addr
		if isinstance(addr, int):
			self.addr = addr.to_bytes(6, byteorder="big")
		elif isinstance(addr, str):
			self.addr = int(addr.replace(":", "").replace("-", ""), base=16).to_bytes(6, byteorder="big")

	def __repr__(self) -> str:
		hex_chars = list(hex(int.from_bytes(self.addr, byteorder="big"))[2:].zfill(12))
		return "MAC(" + ":".join([hex_chars[x] + hex_chars[x + 1] for x in range(0, len(hex_chars), 2)]) + ")"
	
# Variables cannot be initialized in the class since they are instances of the class :(
MAC.broadcast = MAC("ff:ff:ff:ff:ff:ff")
MAC.host_address = MAC(uuid.getnode())


class EtherType(Enum):
	'''
	Enum of all possible EtherTypes
	'''
	# Default value indicating that type field has been replaced by length
	LENGTH = 0

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


class Ethernet:
	# IFACE must be changed if being used on a different computer
	socket = conf.L2socket(iface="Realtek Gaming GbE Family Controller", promisc=True)

	def __init__(self, destination: MAC, data: bytes, 
			  	 type: Union[EtherType, None]=EtherType.IPv4, source: MAC=MAC.host_address):
		'''
		destination - MAC object
		data - bytes
		type - Integer, must be an enum
		source - MAC object
		length - in certain standards, length replaces Ethertype and indicates data length (<1500)
		'''
		self.destination = destination 
		self.source = source
		self.type = type 
		self.data = data

	def send(self) -> None:
		'''
		Sends the object as an ethernet frame
		'''
		header = struct.pack(f"!6s6sH", 
								self.destination.addr, 
								self.source.addr, 
								self.type.value
							)
		
		Ethernet.socket.send(header + self.data)
	
	def __repr__(self) -> str:
		return ("Ethernet("
		  		f"destination={self.destination}, "
			    f"source={self.source}, "
				f"type={self.type.name}, "
				f"data={self.data})"
			   )

	@classmethod
	def recv(cls) -> Union[Self, None]:
		'''
		Non-blocking function. Receives an ethernet frame and returns it parsed into
		an 'Ethernet' instance.
		'''
		raw = Ethernet.socket.recv_raw()
		raw_frame = raw[1]
		if raw_frame is None:
			return None
		
		header = struct.unpack("!6s6sH", raw_frame[:14])
		data = raw_frame[14:]

		if header[2] <= 1500:
			return Ethernet(MAC(header[0]), 
							data, 
							source=MAC(header[1]), 
							type=EtherType.LENGTH
						)
		
		return Ethernet(MAC(header[0]), 
							data, 
							source=MAC(header[1]), 
							type=EtherType(header[2])
						)


def main() -> None:
	'''
	Sending a frame to host computer's network card
	'''
	frame = Ethernet(MAC.host_address, b'Hello world!')
	frame.send()
	print(Ethernet.recv())


if __name__ == "__main__":
	main()