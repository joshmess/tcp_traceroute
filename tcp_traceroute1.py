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

TIMEOUT = 0.25
SOCKET_TIMEOUT = 0
DST_REACHED = 1
DST_UNREACHABLE = 2
ICMP_ECHO_REQUEST = 8


class RecvSocket:

    def __init__(self, type, timeout):
        self.r = socket.socket(socket.AF_INET, socket.SOCK_RAW, type)
        self.r.settimeout(timeout)
        self.packet = b''

    def run(self):
        try:
            self.t1 = time.time()
            self.packet, self.address = self.r.recvfrom(1024)
            self.t2 = time.time()
        except socket.timeout as err:
            self.address = None
        except KeyboardInterrupt:
            exit()
        finally:
            self.r.close()

    def getResponseAddress(self):
        if self.address:
            return self.address[0]
        else:
            return None

    def getTimeCost(self):
        return self.t2 - self.t1


# controls main flow of program
def traceroute(max_hops, dst_port, dst_host, dst_addr):

    type = socket.IPPROTO_ICMP
    ttl = 1

    for ttl in range(1,max_hops+1):

        print('{:2} '.format(ttl), end=' ', flush=True)
        prev_addr = None

        # compute latency 3 times
        for i in range(3):

            # SOCKET to send TCP SYN
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # Sockets to simultaneously listen for TCP and ICMP
            recv_icmp_socket = RecvSocket(socket.IPPROTO_ICMP, TIMEOUT)
            recv_tcp_socket = RecvSocket(socket.IPPROTO_TCP, TIMEOUT)
            threads = [threading.Thread(target=recv_icmp_socket.run), threading.Thread(target=recv_tcp_socket.run)]

            syn_pkt = IP(dst=dst_addr, ttl=ttl) / TCP(dport=dst_port, sport=54321, flags='S')
            s.sendto(bytes(syn_pkt), (dst_addr, dst_port))

            # listen for responses (tcp & icmp)
            for t in threads:
                t.start()
                t.join()

            delta_t = 0

            if recv_tcp_socket.getResponseAddress():
                address = recv_tcp_socket.getResponseAddress()
                delta_t = recv_tcp_socket.getTimeCost()
            elif recv_icmp_socket.getResponseAddress():
                address = recv_icmp_socket.getResponseAddress()
                delta_t = recv_icmp_socket.getTimeCost()
            else:
                address = None

            if address:
                print("%2d: %4dms, %3d.%3d.%3d.%3d" % (
                ttl, int(delta_t * 1000), socket.inet_aton(address)[0], socket.inet_aton(address)[1],
                socket.inet_aton(address)[2], socket.inet_aton(address)[3]))
            else:
                print("%2d: ____ms, ___.___.___.___" % (ttl))

            ttl += 1


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
