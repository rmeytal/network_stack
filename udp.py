from typing import Union, Self
import random
import struct

from ipv4addr import IPv4Address
from ip import IP, IPProtocolType, ChecksumError
from icmp import ICMP, ICMPType


class UDP:
	def __init__(self, destination: tuple[IPv4Address, int], 
			  	 data: bytes, 
				 source: tuple[IPv4Address, int]=(IP.host_addr, random.randint(1024, 0xffff))
				):
		'''
		destination - tuple representing destination socket
		data - bytes to be sent
		source - tuple representing source socket
		'''
		self._destination_port = destination[1]
		self._source_port = source[1]
		self._data = data
		# Adding 8 since length is the total length of UDP packet
		self._length = len(self._data) + 8
		self._checksum = 0

		# Since UDP header is crafted in 'send', IP data is currently empty
		self._ip_packet = IP(destination[0], b"", source=source[0], protocol=IPProtocolType.UDP)

	def calculate_checksum(self, payload: bytes) -> int:
		'''
		Calculates and returns (doesn't set)
		Takes in the UDP header + data with the checksum field zeroed out
		payload - UDP header + data (checksum = 0xffff)
		'''

		pseudo_header = struct.pack("!4s4sBBH", 
							  		self._ip_packet._source.addr, self._ip_packet._destination.addr, 
									0, self._ip_packet._protocol.value, self._length)

		return IP._calculate_checksum(pseudo_header + payload)

	def send(self) -> None:
		'''
		Sends the packet to the destination
		Since checksum is optional, it currently isn't calculated and set to 0
		'''
		raw_header = struct.pack("!HHHH", self._source_port, self._destination_port, self._length, self._checksum)

		payload = raw_header + self._data

		# Setting checksum
		self._checksum = self.calculate_checksum(payload)
		payload = list(payload)
		payload[6] = self._checksum >> 8
		payload[7] = self._checksum & 0xff
		payload = bytes(payload)

		# IP total_length field is changed in setter
		self._ip_packet.data = payload
		self._ip_packet.send()

	def __repr__(self) -> str:
		return ("UDP("
				f"destination=({self._ip_packet._destination}, {self._destination_port}), "
				f"source=({self._ip_packet._source}, {self._source_port}),"
				f"data={self._data},"
				f"checksum={hex(self._checksum)}"
				")")
	
	@property
	def data(self) -> bytes:
		return self._dat
	
	@data.setter
	def data(self, new) -> None:
		'''
		data setter
		Modifies length accordingly
		'''
		if not isinstance(new, bytes):
			return ValueError("'data' must be bytes")
		
		self._data = new
		# Adding default UDP header length
		self._length = len(self._data) + 8

	@classmethod
	def parse_packet(cls, packet: IP) -> Self:
		'''
		Takes in a raw UDP packet
		Returns as a UDP instance
		'''
		if packet._protocol != IPProtocolType.UDP:
			raise ValueError("'packet' protocol must be UDP")
		
		ret = object.__new__(cls)
		
		# Parsing header fields
		(ret._source_port, 
   		 ret._destination_port, 
		 ret._length, 
		 ret._checksum
		) = struct.unpack("!HHHH", packet._data[:8])

		ret._data = packet._data[8:ret._length]
		ret._ip_packet = packet

		# Verifying checksum
		raw_payload = list(packet._data)
		raw_payload[6] = 0
		raw_payload[7] = 0
		raw_payload = bytes(raw_payload)

		calculated_checksum = ret.calculate_checksum(raw_payload)
		if calculated_checksum != ret._checksum:
			raise ChecksumError("Incorrect checksum")

		return ret

	@classmethod
	def recv(cls, source_filter: Union[tuple[IPv4Address, int], None]=None) -> Union[Self, ICMP]:
		'''
		Receives a UDP packet or corresponding response if source specified
		Blocks until receives a packet

		source_filter - Optional variable. Will only return a relevant packet from the specified source.
		ICMP packets will only be returned if the source is filtered and an ICMP packet is received from the source.
		'''
		while True:
			packet = IP.recv()

			if (
				packet._protocol == IPProtocolType.UDP or 
			   	(packet._protocol == IPProtocolType.ICMP and source_filter != None)
			   ):
				# Implements source filter
				if source_filter != None:
					# Checks if IP address matches
					if packet._source == source_filter[0]:
						# If UDP, checks if port matches and returns UDP
						if packet._protocol == IPProtocolType.UDP:
							try:
								ret = UDP.parse_packet(packet)
							except ChecksumError:
								continue

							if ret._source_port == source_filter[1]:
								return ret
						# If ICMP, checks if message type is relevant and returns ICMP
						else:
							# NOTE: the following line can trigger a Checksum error, intentionaly not handled
							try:
								ret = ICMP.parse_message(packet)
							except ChecksumError:
								continue

							if ret._type == ICMPType.DESTINATION_UNREACHABLE or ret._type == ICMPType.TIME_EXCEEDED:
								return ret
							
				# If not filtered then protocol is definitely UDP; crafts and returns packet
				else:
					try:
						return UDP.parse_packet(packet)
					except ChecksumError:
						continue


def main() -> None:
	# Sending a UDP packet to the router
	udp = UDP((IPv4Address("192.168.68.1"), 9000), b"Hello destination unreachable")
	udp.send()
	print(udp)

	# Receiving a response (presumably ICMP destination unreachable)
	print(UDP.recv(source_filter=(IPv4Address("192.168.68.1"), 9000)))
	# Receiving another arbitrary UDP packet
	print(UDP.recv())


if __name__ == "__main__":
	main()