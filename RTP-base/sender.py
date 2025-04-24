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
MAX_PAYLOAD = 1456

# Wait for response
def wait_for_ack(sock, seqNum) -> int:
    nextSeq = seqNum
    try:
        while True:
            data, _ = sock.recvfrom(1472)
            ack = PacketHeader(data[:16])
            if ack.type == 3 and ack.seq_num > nextSeq:
                nextSeq = ack.seq_num
    except socket.timeout:
        return nextSeq

# Send start packet and wait for ACK, if not receive, resend packet
# Timeout for START and DATA is 0.1s, END is 0.5s
def send_packet(sock, recv_ip, recv_port, pkt_type, seqNum) -> bool:
    pkt_header = PacketHeader(type=pkt_type, seq_num=seqNum, length=0)
    sock.sendto(bytes(pkt_header), (recv_ip, recv_port))
    if wait_for_ack(sock, seqNum) == seqNum + 1:
        return True
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
    start_ack = False
    while not start_ack:
        if send_packet(s, receiver_ip, receiver_port, START, seqNum):
            seqNum += 1
            start_ack = True

    # Split message and make packet
    listMsg = split_message(msg, MAX_PAYLOAD)
    msgPacket = [0]
    for i in range(len(listMsg)):
        pkt_header = PacketHeader(type=2, seq_num=i+1, length=len(listMsg[i]))
        pkt_header.checksum = compute_checksum(pkt_header / listMsg[i])
        pkt = pkt_header / listMsg[i]
        msgPacket.append(pkt)

    # Send DATA packet
    while seqNum <= len(listMsg):
        limit = min(seqNum+window_size+1, len(listMsg)+1)
        for i in range(seqNum, limit):
            s.sendto(bytes(msgPacket[i]), (receiver_ip, receiver_port))
        seqNum = max(seqNum, wait_for_ack(s, seqNum))

    # handle END packet
    s.settimeout(0.1)
    end_ack = False
    while not end_ack:
        if send_packet(s, receiver_ip, receiver_port, END, seqNum):
            end_ack = True

    s.close()
    with open("test.txt", "a") as f:
        f.write("end\n")
        f.flush()

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