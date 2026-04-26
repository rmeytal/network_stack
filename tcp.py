from typing import Self, Callable
from enum import Enum
import struct
import random
import time

from l2socket import Socket
from ip import IP, IPProtocolType, ChecksumError
from ipv4addr import IPv4Address
from icmp import ICMP, ICMPType


class TCPFlags(Enum):
	FIN = 0b000001
	SYN = 0b000010
	RST = 0b000100
	PSH = 0b001000
	ACK = 0b010000
	URG = 0b100000


class TCP:
	def __init__(self, destination: tuple[IPv4Address, int], 
				 seq: int, ack: int, flags: int, window: int, 
				 data: bytes,
				 urgent_pointer: int=0, source: tuple[IPv4Address | None, int]=(None, random.randint(1024, 0xffff))
				):
		self._source_port = source[1]
		self._destination_port = destination[1]

		# Setting seq and ack numbers
		self._seq = seq
		self._ack = ack

		# Field is 2 bytes long: 4 header length bits, 6 reserved bits, rest flags, must be modified later
		if isinstance(flags, TCPFlags):
			self._flags = flags.value
		else:
			self._flags = flags
		self._window = window

		# Checksum is 0 for calculation
		self._checksum = 0
		self._urgent_pointer = urgent_pointer

		# Since header currently doesn't support options, length is always 5 (20 bytes)
		self._header_len = 5
		self._data = data

		self._ip_packet = IP(destination[0], b"", source=source[0], protocol=IPProtocolType.TCP)

	def send(self, socket: Socket) -> None:
		'''
		Sends self through socket
		'''
		# Header currently doesn't support options
		raw_header = struct.pack("!HHIIBBHHH", self._source_port, 
						   		 self._destination_port, self._seq, 
								 self._ack, self._header_len << 4, self._flags,
								 self._window, 0, self._urgent_pointer)

		payload = raw_header + self._data

		# Setting checksum
		self._checksum = IP._calculate_checksum(
							self._ip_packet.get_pseudo_header(self._header_len * 4 + len(self._data)) + payload
						 )
		payload = TCP._change_checksum(payload, self._checksum)

		self._ip_packet.data = payload
		self._ip_packet.send(socket)

	def __repr__(self) -> str:
		return ("TCP("
		  		f"destination=({self._ip_packet._destination}, {self._destination_port}), "
				f"source=({self._ip_packet._source}, {self._source_port}), "
				f"sequence_number={self._seq}, "
				f"acknowledgement_number={self._ack}, "
				f"flags={self._flags}, "
				f"window={self._window}, "
				f"checksum={hex(self._checksum)}, "
				f"urgent={self._urgent_pointer}, "
				f"data={self._data}"
				")")
	
	@staticmethod
	def _change_checksum(raw_payload: bytes, new_value: int) -> bytes:
		raw_payload = list(raw_payload)
		raw_payload[16] = new_value >> 8
		raw_payload[17] = new_value & 0xff
		
		return bytes(raw_payload)
	
	@classmethod
	def parse(cls, packet: IP) -> Self:
		'''
		Takes in a raw TCP packet
		Returns as a TCP instance
		'''	
		if packet._protocol != IPProtocolType.TCP:
			raise ValueError("'packet' protocol must be TCP")
		
		ret = object.__new__(cls)
		
		# Header currently doesn't support options
		(ret._source_port, ret._destination_port, 
   		 ret._seq, ret._ack, ret._header_len, ret._flags,
		 ret._window, ret._checksum, ret._urgent_pointer
		) = struct.unpack("!HHIIBBHHH", packet._data[:20])

		ret._header_len = ret._header_len >> 4

		ret._data = packet._data[20:]
		
		ret._ip_packet = packet

		# Verifying checksum
		raw_payload = TCP._change_checksum(packet._data, 0)

		# Verifying checksum (identical to IP formula, includes pseudoheader)
		calculated_checksum = IP._calculate_checksum(
								ret._ip_packet.get_pseudo_header(ret._header_len * 4 + len(ret._data)) + raw_payload
							  )
		if calculated_checksum != ret._checksum:
			raise ChecksumError("Incorrect checksum")

		return ret

	@classmethod
	def recv(cls, socket: Socket, timeout: int=1,
		  	 filter: Callable[[Self, ICMP], bool]=(lambda _: True), include_icmp: bool=False
			) -> Self | ICMP:
		'''
		Receives a TCP packet or corresponding response if source specified
		Blocks until receives a packet

		timeout - exception raised if no TCP packet received before timeout runs out
		filter - Function that takes in packets and returns a boolean if the packet passes the filter
		include_icmp - True if the filter should take in all ICMP packets too, otherwise false
		'''

		start_time = time.time()
		while True:
			if (time.time() - start_time) > timeout:
				raise TimeoutError("No TCP packet received")
				
			packet = IP.recv(socket, timeout=timeout)

			if packet._protocol == IPProtocolType.TCP:
				try:
					ret = TCP.parse(packet)
				except ChecksumError:
					continue

				# Applying filter
				if filter(ret):
					return ret
			elif packet._protocol == IPProtocolType.ICMP and include_icmp:
				try:
					ret = ICMP.parse(packet)
				except ChecksumError:
					continue

				# Applying filter
				if filter(ret):
					return ret