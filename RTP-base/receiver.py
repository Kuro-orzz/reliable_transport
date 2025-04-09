import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

ip = "0.0.0.0"
port = 12345
sz = 128

# send ACK packet
def send_ACK_packet(sock, address):
	pkt_header = PacketHeader(type=3, seq_num=1, length=0)
	sock.sendto(bytes(pkt_header), address)

def receiver(receiver_ip, receiver_port, window_size):
	"""TODO: Listen on socket and print received message to sys.stdout."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((receiver_ip, receiver_port))
	while True:
		# Receive packet; address includes both IP and port
		pkt, address = s.recvfrom(1472)

		# Extract header and payload
		pkt_header = PacketHeader(pkt[:16])
		msg = pkt[16 : 16 + pkt_header.length]

		if pkt_header.type == 0:
			send_ACK_packet(s, address)
			continue
		elif pkt_header.type == 1:
			send_ACK_packet(s, address)
			break

		# Verity checksum
		pkt_checksum = pkt_header.checksum
		pkt_header.checksum = 0
		computed_checksum = compute_checksum(pkt_header / msg)
		if pkt_checksum != computed_checksum:
			# print("checksums not match")
			continue
		else:
			send_ACK_packet(s, address)
			print(msg.decode(), end="")
	s.close()

def main():
	parser = argparse.ArgumentParser()
	if len(sys.argv) == 4:
		parser.add_argument(
			"receiver_ip", help="The IP address of the host that receiver is running on"
		)
		parser.add_argument(
			"receiver_port", type=int, help="The port number on which receiver is listening"
		)
		parser.add_argument(
			"window_size", type=int, help="Maximum number of outstanding packets"
		)
		args = parser.parse_args()

		receiver(args.receiver_ip, args.receiver_port, args.window_size)
	else:
		receiver(ip, port, sz)

if __name__ == "__main__":
	main()
