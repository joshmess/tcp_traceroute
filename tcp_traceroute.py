import sys, os
import argparse
import time
import socket
import struct
import scapy.all
from scapy.layers.inet import *

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 4: tcp_traceroute.py
# Usage: sudo python3 tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] [-t TARGET]

TIMEOUT = 2.0
SOCKET_TIMEOUT = 0
DST_REACHED = 1
ICMP_ECHO_REQUEST = 8

def checksum(str_):
    str_ = bytearray(str_)
    csum = 0
    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count+1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


# receives the echo from the target, returns delay and more info
def rcv_ping(raw_socket):

    start = time.time()

    while (start + TIMEOUT - time.time()) > 0:
        try:
            recPacket, (addr, x) = raw_socket.recvfrom(1024)
        except socket.timeout:
            break  # timed out
        timeReceived = time.time()

        # Fetch the ICMPHeader fromt the IP
        icmpHeader = recPacket[20:28]

        icmpType, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        if icmpType == 11 and code == 0:
            return (timeReceived - start), addr, None
        elif icmpType == 0 and code == 0:
            return (timeReceived - start), addr, DST_REACHED

    return None, None, SOCKET_TIMEOUT


# sends a packet to the target
def send_ping(raw_socket, dst_addr, dst_port, id):

    # Make a dummy header with a 0 checksum
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # htons: Convert 16-bit integers from host to network  byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, 1)
    packet = header + data

    # AF_INET address must be tuple, not str
    raw_socket.sendto(packet, (dst_addr, 1))

# controls flow for performing one ping
def perform_ping(dst_addr, dst_port, ttl):

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    raw_socket.settimeout(TIMEOUT)

    # store current process ID
    id = os.getpid() & 0xFFFF

    send_ping(raw_socket, dst_addr, dst_port, id)
    delay = rcv_ping(raw_socket, id, dst_addr)

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