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

# Wait for response
def wait_for_ack(sock):
    try:
        data, _ = sock.recvfrom(1472)
        ack = PacketHeader(data[:16])
        if ack.type == 3:
            return True
    except socket.timeout:
        return False

# Send start packet and wait 500ms for ACK, if not receive, resend start packet
# START = 0, END = 1, DATA = 2, ACK = 3
def send_packet(sock, recv_ip, recv_port, pkt_type, seqNum):
    pkt_header = PacketHeader(type=pkt_type, seq_num=seqNum, length=0)
    count = 0
    while count < MAX_RESEND:
        sock.sendto(bytes(pkt_header), (recv_ip, recv_port))
        if wait_for_ack(sock) == True:
            if pkt_type == 0: print("START ACKed", seqNum)
            elif pkt_type == 1: print("END ACKed", seqNum)
            return
        print("Resend")
        count += 1

def send_data_packet(sock, msg, recv_ip, recv_port, seqNum):
    pkt_header = PacketHeader(type=2, seq_num=seqNum, length=len(msg))
    pkt_header.checksum = compute_checksum(pkt_header / msg)
    pkt = pkt_header / msg
    count = 0
    while count < MAX_RESEND:
        sock.sendto(bytes(pkt), (recv_ip, recv_port))
        if wait_for_ack(sock) == True:
            print("DATA ACKed", seqNum)
            return
        print("Resend data packet")
        count += 1

def split_message(message, chunk_size):
    chunks = [message[i:i + chunk_size] for i in range(0, len(message), chunk_size)]
    return chunks

def sender(receiver_ip, receiver_port, window_size):
    """TODO: Open socket and send message from sys.stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    msg = input()

    seqNum = 0

    send_packet(s, receiver_ip, receiver_port, START, seqNum)
    seqNum += 1

    listMsg = split_message(msg, 1456)
    for message in listMsg:
        send_data_packet(s, message, receiver_ip, receiver_port, seqNum)
        seqNum += 1

    send_packet(s, receiver_ip, receiver_port, END, seqNum)

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
