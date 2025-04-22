import argparse
import socket
import sys

from time import sleep
from utils import PacketHeader, compute_checksum

ip = "0.0.0.0"
port = 12345
sz = 128

START = 0
END = 1
DATA = 2
ACK = 3
MAX_RESEND = 100
MAX_PAYLOAD = 1456

# Wait for response
def wait_for_ack(sock, seqNum):
    try:
        while True:
            data, _ = sock.recvfrom(1472)
            ack = PacketHeader(data[:16])
            if ack.type == 3 and ack.seq_num == seqNum + 1:
                return True
    except socket.timeout:
        return False

# Send start packet and wait for ACK, if not receive, resend packet
# Timeout for START and DATA is 0.1s, END is 0.5s
def send_packet(sock, recv_ip, recv_port, pkt_type, seqNum) -> bool:
    pkt_header = PacketHeader(type=pkt_type, seq_num=seqNum, length=0)
    count = 0
    while count < MAX_RESEND:
        sock.sendto(bytes(pkt_header), (recv_ip, recv_port))
        if wait_for_ack(sock, seqNum) == True:
            return True
        count += 1
    if pkt_type == 0:
        print("Fail to send START packet")
    if pkt_type == 1:
        print("Fail to send END packet")
    return False

def send_data_packet(sock, msg, recv_ip, recv_port, seqNum) -> bool:
    pkt_header = PacketHeader(type=2, seq_num=seqNum, length=len(msg))
    pkt_header.checksum = compute_checksum(pkt_header / msg)
    pkt = pkt_header / msg
    count = 0
    while count < MAX_RESEND:
        sock.sendto(bytes(pkt), (recv_ip, recv_port))
        if wait_for_ack(sock, seqNum) == True:
            return True
        count += 1
    print("Fail to send DATA packet")
    return False

def split_message(message, chunk_size):
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
    return chunks

def sender(receiver_ip, receiver_port, window_size):
    """TODO: Open socket and send message from sys.stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.1)
    msg = sys.stdin.buffer.read()

    seqNum = 0

    # handle START packet
    if send_packet(s, receiver_ip, receiver_port, START, seqNum):
        seqNum += 1
    else:
        s.close()
        return

    # Split message
    listMsg = split_message(msg, MAX_PAYLOAD)

    # send and handle DATA packet
    for message in listMsg:
        if send_data_packet(s, message, receiver_ip, receiver_port, seqNum):
            seqNum += 1
        else:
            s.close()
            return

    # handle END packet
    s.settimeout(0.5)
    if send_packet(s, receiver_ip, receiver_port, END, seqNum):
        seqNum += 1

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

        sender(args.receiver_ip, args.receiver_port, args.window_size)
    else:
        sender(ip, port, sz)


if __name__ == "__main__":
    main()