import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

ip = "0.0.0.0"
port = 12345
sz = 128

START = 0
END = 1
DATA = 2
ACK = 3

# send ACK packet
def send_ACK_packet(sock, address, seqNum):
	pkt_header = PacketHeader(type=3, seq_num=seqNum, length=0)
	sock.sendto(bytes(pkt_header), address)

def receiver(receiver_ip, receiver_port, window_size):
	"""TODO: Listen on socket and print received message to sys.stdout."""
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.bind((receiver_ip, receiver_port))

	expected_seqNum = 0
	buffer = dict()

	while True:
		# Receive packet; address includes both IP and port
		pkt, address = s.recvfrom(1472)

		# Extract header and payload
		pkt_header = PacketHeader(pkt[:16])
		msg = pkt[16 : 16 + pkt_header.length]
		recv_checksum = pkt_header.checksum

		# checksum to detect if bit error or not
		pkt_header.checksum = 0
		new_checksum = compute_checksum(pkt_header / msg)
		if recv_checksum != new_checksum:
			continue

		# check if it out of range of sliding window
		if expected_seqNum + window_size <= pkt_header.seq_num:
			continue

		# if packet not equal expected packet, send ACK
		if pkt_header.seq_num != expected_seqNum:
			buffer[pkt_header.seq_num] = msg
			send_ACK_packet(s, address, expected_seqNum)
			continue

		# Handle START, END packet
		if pkt_header.type == START:
			expected_seqNum += 1
			send_ACK_packet(s, address, expected_seqNum)
			continue
		if pkt_header.type == END:
			expected_seqNum += 1
			send_ACK_packet(s, address, expected_seqNum)
			break

		# recv valid and inorder packet, send back ACK
		expected_seqNum += 1
		sys.stdout.buffer.write(msg)
		sys.stdout.buffer.flush()
		while(expected_seqNum in buffer):
			chunk = buffer.pop(expected_seqNum)
			sys.stdout.buffer.write(chunk)
			sys.stdout.buffer.flush()
			expected_seqNum += 1

		send_ACK_packet(s, address, expected_seqNum)

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
