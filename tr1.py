import sys, os
import argparse
import time
import socket
import struct
from scapy.layers.inet import *
import threading

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 4: tcp_traceroute.py
# Usage: sudo python3 tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] [-t TARGET]

TIMEOUT = 0.5
DST_REACHED = 1
DST_UNREACHABLE = 2
ICMP_ECHO_REQUEST = 8
SOCKET_TIMEOUT = 0


class RecvSocket:

    def __init__(self, type):
        self.type = type
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, type)
        self.sock.settimeout(TIMEOUT)
        self.pkt = b''
        self.info = None
        self.delay = None
        self.address = None
        self.start_time = None
        self.rcv_time = None
        self.timeout = False

    def run(self):

        self.start_time = time.time()

        while (self.start_time + TIMEOUT - time.time()) > 0:

            try:
                self.pkt, self.address = self.sock.recvfrom(1024)
            except socket.timeout:
                self.timeout = True
                break

            self.rcv_time = time.time()

            if self.type == 1:
                ip = IP(self.pkt)
                imcp_code = ip[ICMP].code
                icmp_type = ip[ICMP].type

                # ICMP type 11 code 0 --> TIME EXCEEDED
                if icmp_type == 11 and imcp_code == 0:
                    self.delay = self.rcv_time - self.start_time
                    self.info = None
                # ICMP type 0 code 0 --> ECHO REPLY (DST Reached)
                elif icmp_type == 0 and imcp_code == 0:
                    self.delay = self.rcv_time - self.start_time
                    self.info = DST_REACHED
                # ICMP type 3 --> DST UNREACHABLE
                elif icmp_type == 3:
                    self.delay = None
                    self.info = DST_UNREACHABLE
            else:
                self.delay = self.rcv_time - self.start_time

        if self.timeout:
            self.delay = None
            self.address = None
            self.info = SOCKET_TIMEOUT

    def get_addr(self):
        if self.address:
            return self.address
        else:
            return None

    def get_delay(self):
        return self.delay

    def get_info(self):
        return self.info


# controls flow for performing one ping
def send_probe(dst_addr, dst_port, ttl):
    # sending socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    # receiving sockets
    recv_icmp = RecvSocket(socket.IPPROTO_ICMP)
    recv_tcp = RecvSocket(socket.IPPROTO_TCP)
    threads = [threading.Thread(target=recv_icmp.run), threading.Thread(target=recv_tcp.run)]

    syn_pkt = IP(dst=dst_addr, ttl=ttl) / TCP(dport=dst_port, sport=54321, flags='S')
    s.sendto(bytes(syn_pkt), (dst_addr, dst_port))

    for t in threads:
        t.start()
        t.join()

    if recv_tcp.get_addr():
        return recv_tcp.get_delay(), recv_tcp.get_addr(), recv_tcp.get_info()
    elif recv_icmp.get_addr():
        return recv_icmp.get_delay(), recv_icmp.get_addr(), recv_icmp.get_info()
    else:
        return None, None, SOCKET_TIMEOUT


# prints results of a ping
def print_part(delay, address, prev_addr):
    if not delay:
        print('*', end=' ', flush=True)
        return

    # to ms
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
def traceroute(max_hops, dst_port, dst_host, dst_addr):
    # iterate over all ttls
    for ttl in range(1, max_hops + 1):

        print('{:2} '.format(ttl), end=' ', flush=True)
        prev_addr = None

        # compute latency 3 times
        for i in range(3):
            delay, address, info = send_probe(dst_addr, dst_port, ttl)
            print_part(delay, address, prev_addr)
            prev_addr = address

        print()

        if info == DST_REACHED:
            break


def main():
    # Set up argument parsing automation
    prog = 'python3 tcp_traceroute.py'
    descr = 'TCP Traceroute Program Implemented in Python'
    parser = argparse.ArgumentParser(prog=prog, description=descr)
    parser.add_argument('-m', '--MAX_HOPS', type=int, default=30, required=False, help='Max hops to probe')
    parser.add_argument('-p', '--DST_PORT', type=int, default=80, help='TCP Destination Port')
    parser.add_argument('-t', '--TARGET', type=str, required=True, help='Target domain or IP')

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