import struct
from enum import Enum
from typing import Self, Union
import time

from ipv4addr import IPv4Address
from ethernet import Ethernet, EtherType, MAC
from l2socket import Socket


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
	broadcast = IPv4Address("255.255.255.255")

	# Set in Stack.init
	host_addr = None
	subnet_mask = None
	default_gateway = None
	routing_table = None

	def __init__(self, destination: IPv4Address, 
				 data: bytes, source: Union[IPv4Address, None]=None, 
				 ttl: int=128, protocol: IPProtocolType=IPProtocolType.TCP,
				 destination_mac: Union[MAC, None]=None
				):
		'''
		destination - Target IP address
		data - Self explanatory
		source - Sending IP address (if None, routing table interface is used)
		ttl - Time to live (default 128)
		protocol - Type of Level 4 protocol being sents
		destination_mac - Supply the destination mac without ARPing for it or checking arp cache
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
		if self._source is None:
			self._source = IP.host_addr
		self._destination = destination

		# Optional field with variable length. Isn't included in header, here just for clarification
		# self._options = 0

		self._destination_mac = destination_mac

		self._data = data
	
	def send(self, socket: Socket) -> None:
		'''
		Sends the IP packet. Calculates checksum.
		Note: The IP packet is sent from the 'source' IP address, not the interface 
		specified in the routing table.
		'''
		# Getting MAC of next hop & interface
		if self._destination_mac is None:
			self._destination_mac, interface = IP.routing_table.route(socket, self._destination)

		if self._source is None:
			self._source = interface

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
		raw_header = IP._change_checksum(raw_header, self._header_checksum)

		frame = Ethernet(self._destination_mac, raw_header + self._data)
		frame.send(socket)

	def __repr__(self) -> str:
		return ("IP("
		        f"destination={self._destination}, "
				f"source={self._source}, " 
			    f"protocol={self._protocol.name}, "
				f"ttl={self._ttl}, "
				f"checksum={hex(self._header_checksum)}, "
				f"data={self._data})"
			   )

	@property
	def data(self) -> bytes:
		return self._data
	
	@data.setter
	def data(self, new: bytes) -> None:
		'''
		If data field is changed, total length must change accordingly
		'''
		if not isinstance(new, bytes):
			raise ValueError("'data' must be bytes")
		
		self._data = new
		self._total_length = (self._ihl * 4) + len(self._data)

	@staticmethod
	def _change_checksum(raw_header: bytes, new_checksum: int) -> bytes:
		'''
		Takes in an IP header and changes its checksum field
		'''
		raw_header = list(raw_header)
		raw_header[10] = new_checksum >> 8
		raw_header[11] = new_checksum & 0xff
		raw_header = bytes(raw_header)
		
		return raw_header


	@classmethod
	def parse(cls, raw_packet: bytes) -> Self:
		'''
		Takes a raw IP packet
		Returns packet parsed into IP object
		'''
		raw_header = raw_packet[:20]
		parsed_header = struct.unpack("!BBHHHBBH4s4s", raw_packet[:20])
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
		raw_header = IP._change_checksum(raw_header, 0)

		if ret._header_checksum != IP._calculate_checksum(raw_header):
			raise ChecksumError("Invalid Checksum")

		ret._source = IPv4Address(parsed_header[8])
		ret._destination = IPv4Address(parsed_header[9])

		ret._destination_mac = None

		# Indexing until total_length to avoid including filler bytes
		ret._data = raw_packet[20:ret._total_length]

		return ret

	@classmethod
	def recv(cls, socket: Socket, timeout: int=1) -> Self:
		'''
		Receives an IP packet, returns IP object with first IP packet recevied.
		Blocking function
		Doesn't support IP's with headers longer than 20 bytes

		timeout - if timeout exceeded with no packet received, exception thrown
		'''

		start_time = time.time()
		while True:
			frame = Ethernet.recv(socket)
			if frame is not None:
				if frame.type == EtherType.IPv4:
					try:
						return IP.parse(frame.data)
					except ChecksumError:
						continue
			
			if (time.time() - start_time) > timeout:
				raise TimeoutError("No IP packet received")
	
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
