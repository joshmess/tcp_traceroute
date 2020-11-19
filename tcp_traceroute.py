import sys, os
import argparse
import time
import socket
import struct
from scapy.layers.inet import *

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 4: tcp_traceroute.py
# Usage: sudo python3 tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] [-t TARGET]

TIMEOUT = 2.0
SOCKET_TIMEOUT = 0
DST_REACHED = 1
ICMP_ECHO_REQUEST = 8


def checksum(pkt):

    # perform byte manipulation on packet to get checksum
    pkt = bytearray(pkt)
    checksum = 0
    countTo = (len(pkt) // 2) * 2

    for count in range(0, countTo, 2):

        val = pkt[count+1] * 256 + pkt[count]
        checksum = checksum + val
        checksum = checksum & 0xffffffff

    if countTo < len(pkt):
        checksum = checksum + pkt[-1]
        checksum = checksum & 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    result = ~checksum
    result = result & 0xffff
    result = result >> 8 | (result << 8 & 0xff00)

    return result


# receives the echo from the target, returns delay and more info
def rcv_ping(raw_socket):

    start = time.time()

    while (start + TIMEOUT - time.time()) > 0:

        try:
            rcvd_pkt, (addr, port) = raw_socket.recvfrom(1024)
        except socket.timeout:
            break

        rcvd_time = time.time()
        icmp_hdr = rcvd_pkt[20:28]

        icmp_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmp_hdr)

        if icmp_type == 11 and code == 0:
            return (rcvd_time - start), addr, None
        elif icmp_type == 0 and code == 0:
            return (rcvd_time - start), addr, DST_REACHED

    return None, None, SOCKET_TIMEOUT


# sends a packet to the target
def send_ping(raw_socket, dst_addr, dst_port, id, ttl):
    # the packets we will be sending are IMCP echo request packets

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, 1)
    pkt = header + data

    #pkt = IP(dst=dst_addr,ttl=ttl)/TCP(dport=dst_port, flags="S")/ICMP(seq=1)

    raw_socket.sendto(pkt, (dst_addr, dst_port))


# controls flow for performing one ping
def perform_ping(dst_addr, dst_port, ttl):

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    raw_socket.settimeout(TIMEOUT)

    # store current process ID
    id = os.getpid() & 0xFFFF

    send_ping(raw_socket, dst_addr, dst_port, id,ttl)
    delay = rcv_ping(raw_socket)

    raw_socket.close()

    return delay


# prints results of a ping
def print_part(delay, address, prev_addr):

    if not delay:
        print('*', end=' ', flush=True)
        return

    delay *= 1000

    if not prev_addr == address:
        try:
            host, _, _ = socket.gethostbyaddr(address)
        except:
            host = address

        print('{} ({})  {:.3f} ms'.format(host, address, delay),
              end=' ', flush=True)
    else:
        print(' {:.3f} ms'.format(delay),
              end=' ', flush=True)


# controls main flow of program
def traceroute(max_hops,dst_port,dst_host,dst_addr):

    # iterate over all ttls
    for ttl in range(1, max_hops+1):

        print('{:2} '.format(ttl), end=' ', flush=True)
        prev_addr = None

        # compute latency 3 times
        for i in range(3):

            delay, address, info = perform_ping(dst_addr,dst_port, ttl)
            print_part(delay, address, prev_addr)
            prev_addr = address

        if info == DST_REACHED:
            break

        print()


def main():

    # Set up argument parsing automation
    prog = 'python3 tcp_traceroute.py'
    descr = 'TCP Traceroute Program Implemented in Python'
    parser = argparse.ArgumentParser(prog=prog, description=descr)
    parser.add_argument('-m', '--MAX_HOPS', type=int, default=30, required=False,help='Max hops to probe')
    parser.add_argument('-p', '--DST_PORT', type=int, default=80, help='TCP Destination Port')
    parser.add_argument('-t', '--TARGET', type=str,required=True, help='Target domain or IP')

    # Parse given arguments
    args = parser.parse_args()
    max_hops = args.MAX_HOPS
    dst_port = args.DST_PORT
    target = args.TARGET

    dest = socket.gethostbyname(target)

    print("traceroute to %s (%s), %d hops max" % (target, dest, max_hops))

    traceroute(max_hops, dst_port, target, dest)


if __name__ == '__main__':
    main()