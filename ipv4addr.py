from typing import Union, Self


class IPv4Address:
	def __init__(self, addr: Union[bytes, str]):
		'''
		Doesn't check validity of string
		'''
		self.addr = addr
		if isinstance(addr, str):
			self.addr = b"".join(int(byte).to_bytes(1, byteorder="big") for byte in self.addr.split("."))
		elif isinstance(addr, int):
			self.addr = self.addr.to_bytes(4, byteorder="big")

	def __str__(self) -> str:
		return ".".join(str(byte) for byte in self.addr)
	
	def __repr__(self) -> str:
		return f"IPAddress({self})"
	
	def __and__(self, other: Self) -> Self:
		operation = int.from_bytes(self.addr, byteorder="big") & int.from_bytes(other.addr, byteorder="big")
		return IPv4Address(operation)
	
	def __eq__(self, other: Self) -> bool:
		if not isinstance(other, IPv4Address):
			return False
		return self.addr == other.addr