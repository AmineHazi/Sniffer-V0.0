######################################### VERY SIMPLE MAKE FILE NEED CHANGES ####################################################

sniffer: build/main.c build/sniffer.c protocols/tcp.c protocols/udp.c protocols/icmp.c
	gcc build/main.c build/sniffer.c protocols/tcp.c protocols/udp.c protocols/icmp.c && sudo ./a.out