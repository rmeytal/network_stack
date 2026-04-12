import struct
from enum import Enum
from typing import Self

from ipv4addr import IPv4Address
from ethernet import Ethernet, EtherType
from routing_table import RoutingTable, RoutingEntry, RoutingAction


class ChecksumError(Exception):
	pass


class IPProtocolType(Enum):
	UNKNOWN = -1
	ICMP = 1
	TCP = 6
	UDP = 17

	@classmethod
	def _missing_(cls, _) -> Self:
		return cls.UNKNOWN


class IP:
	# Hard coded network info. Must be verified before usage.
	host_addr = IPv4Address("192.168.68.107")
	subnet_mask = IPv4Address("255.255.255.0")
	default_gateway = IPv4Address("192.168.68.1")

	# Creating routing table
	routing_table = RoutingTable()
	routing_table.add_entry(RoutingEntry(
							IPv4Address("127.0.0.1"),
							IPv4Address("255.255.255.255"),
							IPv4Address("127.0.0.1"),
							RoutingAction.LOOPBACK
						   ))
	routing_table.add_entry(RoutingEntry(
							host_addr,
							IPv4Address("255.255.255.255"),
							host_addr,
							RoutingAction.LOOPBACK
						   ))
	routing_table.add_entry(RoutingEntry(
							host_addr & subnet_mask,
							subnet_mask,
							host_addr,
							RoutingAction.DIRECT
						   ))
	routing_table.add_entry(RoutingEntry(
							IPv4Address("0.0.0.0"),
							IPv4Address("0.0.0.0"),
							host_addr,
							RoutingAction.GATEWAY,
							gateway=default_gateway
						   ))

	def __init__(self, destination: IPv4Address, 
				 data: bytes, source: IPv4Address=host_addr, 
				 ttl: int=128, protocol: IPProtocolType=IPProtocolType.TCP
				):
		'''
		destination - Target IP address
		data - Self explanatory
		source - Sending IP address
		ttl - Time to live (default 128)
		protocol - Type of Level 4 protocol being sents
		'''
		# Hard coded version (IPv4)
		self._version = 0b0100

		# Internet Header Length. Counted in 4 bytes (meaning 20 bytes = length of 5)
		self._ihl = 5
		# Type of Service (ToS). Also known as DSCP & ECN. Sets priority of the packet. Normal values
		self._tos = 0b00000000 

		# Length of packet in bytes
		self._total_length = (self._ihl * 4) + len(data)
		# Identifies fragmented packets. Set to 0 since fragmentation isn't supported
		self._identification = 0

		# Fragmentation specifications. Currently doesn't support fragmentation (More Fragments = 0)
		self._flags = 0b000 
		self._fragment_offset = 0
		
		# Time-to-live and Level 4 protocol type
		self._ttl = ttl
		self._protocol = IPProtocolType(protocol)

		# Set to 0 until payload is crafted. Checksum is calculated with this field set to 0
		self._header_checksum = 0 

		# Source and destination addresses
		self._source = source
		self._destination = destination

		# Optional field with variable length. Isn't included in header, here just for clarification
		# self._options = 0

		self._data = data
	
	def send(self) -> None:
		'''
		Sends the IP packet. Calculates checksum.
		Note: The IP packet is sent from the 'source' IP address, not the interface 
		specified in the routing table.
		'''
		version_ihl_byte = (self._version << 4) + self._ihl

		fragment_word = (self._flags << 13) + self._fragment_offset
		raw_header = struct.pack("!BBHHHBBH4s4s",
						   		 version_ihl_byte, self._tos,
								 self._total_length, 
								 self._identification, 
								 fragment_word, 
								 self._ttl, self._protocol.value, 
								 self._header_checksum, 
								 self._source.addr, 
								 self._destination.addr
								)
		
		self._header_checksum = IP._calculate_checksum(raw_header)

		# Changing checksum to final value
		raw_header = list(raw_header)
		raw_header[10] = self._header_checksum >> 8
		raw_header[11] = self._header_checksum & 0xff
		raw_header = bytes(raw_header)
		
		# Checking if source and destination are in the same VLAN
		destination_mac = IP.routing_table(self._destination)

		frame = Ethernet(destination_mac, raw_header + self._data)
		frame.send()

	def __repr__(self) -> str:
		return ("IP("
		        f"destination={self._destination}, "
				f"source={self._source}, " 
			    f"protocol={self._protocol.name}, "
				f"ttl={self._ttl}, "
				f"checksum={hex(self._header_checksum)}, "
				f"data={self._data})"
			   )

	@classmethod
	def recv(cls) -> Self:
		'''
		Receives an IP packet, returns IP object with first IP packet recevied.
		Blocking function
		Doesn't support IP's with headers longer than 20 bytes
		'''
		while True:
			frame = Ethernet.recv()
			if frame is not None:
				if frame.type == EtherType.IPv4:
					raw_header = frame.data[:20]
					parsed_header = struct.unpack("!BBHHHBBH4s4s", frame.data[:20])
					ret = object.__new__(cls)

					ret._version = parsed_header[0] >> 4
					ret._ihl = parsed_header[0] & 0b1111
					ret._tos = parsed_header[1]

					ret._total_length = parsed_header[2]
					ret._identification = parsed_header[3]

					ret._flags = parsed_header[4] >> 13
					ret._fragment_offset = parsed_header[4] & 0b1111111111111

					ret._ttl = parsed_header[5]
					ret._protocol = IPProtocolType(parsed_header[6])

					ret._header_checksum = parsed_header[7]

					# Zeroing checksum field
					raw_header = list(raw_header)
					raw_header[10] = 0
					raw_header[11] = 0
					raw_header = bytes(raw_header)

					# ChecksumError is essentially pointless, created for future use if needed
					try:
						if ret._header_checksum != IP._calculate_checksum(raw_header):
							raise ChecksumError("Invalid Checksum")
					except ChecksumError:
						continue

					ret._source = IPv4Address(parsed_header[8])
					ret._destination = IPv4Address(parsed_header[9])

					# Indexing until total_length to avoid including filler bytes
					ret._data = frame.data[20:ret._total_length]

					return ret
	
	@staticmethod
	def _calculate_checksum(raw: bytes) -> int:
		'''
		Takes in the raw bytes
		Returns the checksum value
		'''
		sum = 0

		# Adding all 16-bit values to sum
		for i in range(0, len(raw) - (len(raw) % 2), 2):
			sum += (raw[i] << 8) + raw[i + 1]

		# Adding odd bit if exists
		if len(raw) % 2:
			# Bottom bit is 0, hence the bitwise shift
			sum += (raw[-1] << 8)

		# Carrying top 16 bits down
		while sum >> 16:
			sum = (sum & 0xffff) + (sum >> 16)

		# Flips the bits
		return sum ^ 0xffff


def main() -> None:
	packet = IP(IPv4Address("192.168.68.1"), data=b"Hello World")
	packet.send()

if __name__ == "__main__":
	main()