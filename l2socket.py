from scapy.all import conf


# Wrapper around scapy.all.conf.L2socket
# Exists in order to make changes to library simple in the future
class Socket:
	iface = None

	def __init__(self, iface: str | None=None, promisc: bool=False):
		if iface is None:
			iface = Socket.iface
		self._socket = conf.L2socket(iface=iface, promisc=promisc)

	def send(self, payload: bytes) -> None:
		'''
		Sends raw frame
		'''
		self._socket.send(payload)

	def recv(self) -> bytes:
		'''
		Receives raw frame
		'''
		return self._socket.recv_raw()[1]
	
	def close(self) -> None:
		'''
		Closes socket
		'''
		self._socket.close()
