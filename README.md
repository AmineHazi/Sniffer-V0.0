# Sniffer-V0.0

## A little Packet sniffer made in C

### TO BUILD : 
   - Using Make : "make sniffer"
   - Without Make : "gcc build/main.c build/sniffer.c protocols/tcp.c protocols/udp.c protocols/icmp.c && sudo ./a.out"

First version of the packet sniffer in C without analysing the packets.
(protocls supported : TCP, UDP, ICMP)
