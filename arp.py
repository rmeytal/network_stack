from ethernet import Ethernet, MAC, EtherType
from ipv4addr import IPv4Address
from typing import Union
import struct
import time


class ARP:
	cache = {}

	def __init__(self, target_ip: Union[IPv4Address, str], type_enum=EtherType.IPv4):
		'''
		Constructs ARP packet, saves into payload class member.

		target_ip - string or IPv4Address representing address looked for
		type_enum - protocol of target addr, currently only IPv4 supported
		'''
		self._target_ip = target_ip
		if isinstance(self._target_ip, str):
			self._target_ip = IPv4Address(self._target_ip)

		# Hardware & protocol types (2 bytes each). Ethernet = 1
		self._hardware_type = 1
		self._protocol_type = type_enum.value

		# Hardware & protocol length - length of respective address in bytes (1 byte)
		self._hardware_length = 6
		self._protocol_length = 4

		#Operation - Request = 1, Reply = 2 (2 bytes)
		self._opcode = 1

		# Sender physical & protocol addresses
		self._sender_physical = MAC.host_address.addr
		# TODO: Replace the following line with current computer's IP
		self._sender_protocol = IPv4Address("0.0.0.0").addr

		# Target physical & protocol address
		self._target_physical = MAC.broadcast.addr
		self._target_protocol = self._target_ip.addr


	def send(self, timeout: int=1) -> MAC:
		'''
		Sends ARP request, returns MAC address received in reply
		timeout - timeout for response before exception thrown (in seconds)
		'''
		if self._target_ip.addr in ARP.cache:
			return ARP.cache[self._target_ip.addr]
		
		# Crafting payload & sending Ethernet frame
		payload = struct.pack("!HHBBH6s4s6s4s", 
							  self._hardware_type, self._protocol_type, 
							  self._hardware_length, self._protocol_length,
							  self._opcode, 
							  self._sender_physical, self._sender_protocol, 
							  self._target_physical, self._target_protocol
							 )
		
		request = Ethernet(MAC.broadcast, payload, type=EtherType.ARP)
		request.send()

		start_time = time.time()
		while True:
			resp = Ethernet.recv()
			if resp is not None:
				if resp.type == EtherType.ARP:
					# Parsing ARP response, saving only relevant fields
					_, opcode, physical_addr, protocol_addr, _ = struct.unpack("!6sH6s4s10s", resp.data[:28])

					# Checking if response is a Reply operation (2)
					if opcode == 2:
						# Checking if reply answers our request
						if protocol_addr == self._target_ip.addr:
							ARP.cache[self._target_ip.addr] = MAC(physical_addr)
							return ARP.cache[self._target_ip.addr]
			
			if time.time() - start_time > timeout:
				raise TimeoutError("No ARP response received.")


def main():
	'''
	main
	Sends ARP request to my router, prints MAC address of router
	'''
	request = ARP("192.168.68.1")
	print(request.send())


if __name__ == "__main__":
	main()