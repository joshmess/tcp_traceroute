# tcp_traceroute
Computer Networks

A command line tool that, given a single target IP address or domain names, measures the latency between each hop on the path from the host to the target. This project makes use of raw sockets, ICMP, and TCP.


### Test:
```
$ python3 tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] -t TARGET
```


### Current State:
- Currently works as an ICMP traceroute, sending ICMP echo request packets over raw sockets.
- Send a TCP SYN packet, not sure if using TCP SYN probe correctly
- Sometimes fails to get hostname and displays IP address twice.

### To Do:
- Finalize TCP SYN part of script
