import network_stack
from l2socket import Socket
from ethernet import Ethernet
from arp import ARP
from ipv4addr import IPv4Address
from ip import IP
from icmp import ICMP, ICMPType
from udp import UDP


# network_stack.init is the initialization function that must be called before using this library
network_stack.init("Realtek Gaming GbE Family Controller", ("192.168.68.100", "255.255.255.0", "192.168.68.1"))
sock = Socket(promisc=True)


def test_ethernet() -> None:
	'''
	Sending a frame to host computer's network card
	'''
	print(Ethernet.host_addr)
	frame = Ethernet(Ethernet.host_addr, b'Hello world!')
	frame.send(sock)
	print(Ethernet.recv(sock))

def test_arp() -> None:
	'''
	Sends ARP request to my router, prints MAC address of router
	'''
	target = IPv4Address("192.168.68.1")
	print(f"MAC of {target} is {ARP.query(sock, target, IPv4Address("192.168.1.100"))}")

def test_ip() -> None:
	'''
	Sends Hello world to self
	'''
	packet = IP(IPv4Address("127.0.0.1"), data=b"Hello World")
	packet.send(sock)

	print(IP.recv(sock))
	print(IP.recv(sock))

def test_icmp() -> None:
	'''
	Sends an ICMP ping to dim.uchile.cl
	'''
	# dim.uchile.cl = 146.83.7.25
	message = ICMP(IPv4Address("146.83.7.25"), b"Hello Chile")
	print(message)

	message.send(sock)

	response = ICMP.recv(sock, type_filter=ICMPType.ECHO_REPLY)
	print(response)

def test_udp() -> None:
	# Sending a UDP packet to the router
	udp = UDP((IPv4Address("192.168.68.1"), 9000), b"Hello destination unreachable")

	udp.send(sock)
	print(udp)

	# Receiving a response (presumably ICMP destination unreachable)
	print(UDP.recv(sock, source_filter=(IPv4Address("192.168.68.1"), 9000)))
	# Receiving another arbitrary UDP packet
	print(UDP.recv(sock))



print("ETHERNET")
test_ethernet()

print("ARP")
test_arp()

print("IP")
test_ip()

print("ICMP")
test_icmp()

print("UDP")
test_udp()

sock.close()