import struct
import random
from typing import Union, Self

from ip import IP, IPProtocolType, ChecksumError
from ipv4addr import IPv4Address
from enum import Enum


class ICMPType(Enum):
	UNKNOWN = -1

	ECHO_REPLY = 0
	DESTINATION_UNREACHABLE = 3
	ECHO_REQUEST = 8
	TIME_EXCEEDED = 11

	@classmethod
	def _missing_(cls, _):
		return cls.UNKNOWN


class ICMP:
	def __init__(self, destination: IPv4Address, data:bytes, 
			  	 type: ICMPType=ICMPType.ECHO_REQUEST, code: int=0, 
				 type_fields: dict={}
				):
		'''
		ICMPv4
		Doesn't support extended headers
		'''
		self._destination = destination
		self._data = data
		self._type = type
		self._code = code
		self._checksum = 0
		self._type_fields = type_fields

		if self._type == ICMPType.ECHO_REQUEST or self._type == ICMPType.ECHO_REPLY:
			# Generates fields for the user if not provided
			if "Identifier" not in self._type_fields:
				self._type_fields["Identifier"] = random.randint(0, 0xffff)
			if "Sequence Number" not in self._type_fields:
				self._type_fields["Sequence Number"] = 0

	def send(self) -> None:
		'''
		Calculates the checksum and sends the message
		'''
		payload = struct.pack(f"!BBH", self._type.value, self._code, self._checksum)

		# Adding the type-specific fields
		if self._type == ICMPType.ECHO_REQUEST or self._type == ICMPType.ECHO_REPLY:
			payload += struct.pack("!HH", self._type_fields["Identifier"], self._type_fields["Sequence Number"])

		payload += self._data

		self._checksum = IP._calculate_checksum(payload)
		
		# Filling in checksum field
		payload = list(payload)
		payload[2] = self._checksum >> 8
		payload[3] = self._checksum & 0xff
		payload = bytes(payload)

		packet = IP(self._destination, payload, protocol=IPProtocolType.ICMP)
		packet.send()

	def __repr__(self) -> str:
		ret = ("ICMP(" 
				f"destination={self._destination}, "
				f"type={self._type.name}, "
				f"code={bin(self._code)}, "
				f"checksum={hex(self._checksum)}, ")
		
		if len(self._type_fields):
			ret += f"{self._type_fields}, "

		ret += f"data={self._data})"
		return ret
	
	@classmethod
	def parse_message(cls, packet: IP) -> Self:
		'''
		Receives an ICMP packet in 'packet'
		Returns as an ICMP object
		'''
		if packet._protocol != IPProtocolType.ICMP:
			raise ValueError("'packet' protocol must be ICMP")
		
		ret = object.__new__(cls)
		(type, code, checksum) = struct.unpack("!BBH", packet._data[:4])

		# Filling in fields
		ret._destination = packet._destination
		ret._type = ICMPType(type)
		ret._code = code
		ret._checksum = checksum
		ret._data = packet._data[4:]
		ret._type_fields = {}

		# Calculating checksum
		raw_payload = list(packet._data)
		raw_payload[2] = 0
		raw_payload[3] = 0

		calculated_checksum = IP._calculate_checksum(bytes(raw_payload))

		if calculated_checksum != ret._checksum:
			raise ChecksumError("Invalid ICMP checksum")

		# Unpacking type-specific fields
		if ret._type == ICMPType.ECHO_REQUEST or ret._type == ICMPType.ECHO_REPLY:
			(identifier, sequence_number) = struct.unpack("!HH", packet._data[4:8])
			ret._type_fields = {"Identifier": identifier, "Sequence Number": sequence_number}
			ret._data = packet._data[8:]

		return ret

	@classmethod
	def recv(cls, type_filter: Union[ICMPType, None]=None, identifier_filter: Union[int, None]=None, ) -> Self:
		'''
		Blocks until an ICMP message is received
		Message can be filtered by ICMP type and identifier

		type_filter - Optional. Filters incoming packets by type
		identifier_filter - Optional. Filters incoming packets with identifier field by identifier
		'''

		while True:
			packet = IP.recv()

			# Filtering non-ICMP packets
			if packet._protocol == IPProtocolType.ICMP:
				try:
					ret = ICMP.parse_message(packet)
				except ChecksumError:
					continue

				# Applying filters, returning accordingly
				if type_filter == None:
					return ret
				elif type_filter == ret._type:
					if ((ret._type == ICMPType.ECHO_REQUEST or ret._type == ICMPType.ECHO_REPLY) and 
					     identifier_filter != None):
						if identifier_filter == ret._type_fields["Identifier"]:
							return ret
					else:
						return ret


def main():
	'''
	main
	'''
	# dim.uchile.cl = 146.83.7.25
	message = ICMP(IPv4Address("146.83.7.25"), b"Hello Chile")
	print(message)

	message.send()

	response = ICMP.recv(type_filter=ICMPType.ECHO_REPLY)
	print(response)


if __name__ == "__main__":
	main()