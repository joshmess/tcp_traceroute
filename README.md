# tcp_traceroute
Computer Networks

A command line tool that, given a single target IP address or domain names, measures the latency between each hop on the path from the host to the target. This project makes use of raw sockets, ICMP, and TCP.


### Test:
```
$ python3 tcp_traceroute.py [-m MAX_HOPS] [-p DST_PORT] -t TARGET
```


### Current State:
- Currently works as an ICMP traceroute, sending ICMP echo request packets over raw sockets.
- Performs similar to traceroute, except where traceroute stops, my script continues to print asteriks up until the MAX_HOPS value.

### To Do:
- Implement TCP SYN packet part of program (send TCP SYN packets over raw socket, need to listen for TCP and ICMP)
