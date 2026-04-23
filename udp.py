from typing import Union, Self
import random
import struct
import time

from ipv4addr import IPv4Address
from ip import IP, IPProtocolType, ChecksumError
from icmp import ICMP, ICMPType
from l2socket import Socket


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

	def send(self, socket: Socket) -> None:
		'''
		Sends the packet to the destination
		Since checksum is optional, it currently isn't calculated and set to 0
		'''
		raw_header = struct.pack("!HHHH", self._source_port, self._destination_port, self._length, self._checksum)

		payload = raw_header + self._data

		# Setting checksum (identical to IP formula, includes pseudoheader)
		self._checksum = IP._calculate_checksum(self._ip_packet.get_pseudo_header(self._length) + payload)
		payload = UDP._change_checksum(payload, self._checksum)

		# IP total_length field is changed in setter
		self._ip_packet.data = payload
		self._ip_packet.send(socket)

	def __repr__(self) -> str:
		return ("UDP("
				f"destination=({self._ip_packet._destination}, {self._destination_port}), "
				f"source=({self._ip_packet._source}, {self._source_port}),"
				f"data={self._data},"
				f"checksum={hex(self._checksum)}"
				")")
	
	@property
	def data(self) -> bytes:
		return self._data
	
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

	@staticmethod
	def _change_checksum(raw_payload: bytes, new_value: int) -> bytes:
		'''
		Changes the checksum field in raw_payload to new_value
		'''
		raw_payload = list(raw_payload)
		raw_payload[6] = new_value >> 8
		raw_payload[7] = new_value & 0xff
		raw_payload = bytes(raw_payload)

		return raw_payload

	@classmethod
	def parse(cls, packet: IP) -> Self:
		'''
		Takes in a raw UDP packet
		Returns as a UDP instance
		'''	
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
		raw_payload = UDP._change_checksum(packet._data, 0)

		# Verifying checksum (identical to IP formula, includes pseudoheader)
		calculated_checksum = IP._calculate_checksum(ret._ip_packet.get_pseudo_header(ret._length) + raw_payload)
		if calculated_checksum != ret._checksum:
			raise ChecksumError("Incorrect checksum")

		return ret

	@classmethod
	def recv(cls, socket: Socket,
		  	 source_filter: Union[tuple[IPv4Address, int], None]=None, timeout: int=1
			) -> Union[Self, ICMP]:
		'''
		Receives a UDP packet or corresponding response if source specified
		Blocks until receives a packet

		source_filter - Optional variable. Will only return a relevant packet from the specified source.
		ICMP packets will only be returned if the source is filtered and an ICMP packet is received from the source.
		timeout - exception raised if no UDP packet received before timeout runs out
		'''

		start_time = time.time()
		while True:
			if (time.time() - start_time) > timeout:
				raise TimeoutError("No UDP packet received")
			
			packet = IP.recv(socket)

			if (packet._protocol == IPProtocolType.UDP or 
			    (packet._protocol == IPProtocolType.ICMP and source_filter != None)
			   ):
				# Implements source filter
				if source_filter != None:
					# Checks if IP address matches
					if packet._source == source_filter[0]:
						# If UDP, checks if port matches and returns UDP
						if packet._protocol == IPProtocolType.UDP:
							try:
								ret = UDP.parse(packet)
							except ChecksumError:
								continue

							if ret._source_port == source_filter[1]:
								return ret
						# If ICMP, checks if message type is relevant and returns ICMP
						else:
							try:
								ret = ICMP.parse(packet)
							except ChecksumError:
								continue

							if ret._type == ICMPType.DESTINATION_UNREACHABLE or ret._type == ICMPType.TIME_EXCEEDED:
								# Verifying port of packet being responded to matches source_filter
								# No need to check checksum, since it will definitely be valid (ICMP already checked)
								response_to = UDP.parse(IP.parse(ret._data))
								if response_to._destination_port == source_filter[1]:
									return ret
							
				# If not filtered then protocol is definitely UDP; crafts and returns packet
				else:
					try:
						return UDP.parse(packet)
					except ChecksumError:
						continue
