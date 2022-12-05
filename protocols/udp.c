#include "../headers/sniffer.h"


void print_udp_packet(unsigned char *Buffer , int Size)
{
	
	unsigned short iphdrlen;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	//Get the lenght of the IP header
	iphdrlen = iph->ihl*4;
	//Get the UDP header part without the Ethernet and IP headers. 
	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	//Get the size of the header part (Ethernet + IP + UDP)
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	
/* 	fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
	
	print_ip_header(Buffer,Size);			
	
	fprintf(logfile , "\nUDP Header\n");
	fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
	fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
	fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
	fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
	
	fprintf(logfile , "\n");
	fprintf(logfile , "IP Header\n");
	PrintData(Buffer , iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer+iphdrlen , sizeof udph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	
	fprintf(logfile , "\n###########################################################"); */

	fprintf(logfile , "\n\n\t\t{\n");
	
	fprintf(logfile , "\t\t\t\"Protocol Name\" : \"UDP\",\n");
	print_ip_header(Buffer,Size);			
	
	fprintf(logfile , "\t\t\t\"Source Port\": \"%d\",\n" , ntohs(udph->source));
	fprintf(logfile , "\t\t\t\"Destination Port\": \"%d\",\n" , ntohs(udph->dest));
	fprintf(logfile , "\t\t\t\"UDP Length\": \"%d\",\n" , ntohs(udph->len));
	fprintf(logfile , "\t\t\t\"UDP Checksum \": \"%d\",\n" , ntohs(udph->check));
	
	fprintf(logfile , "\t\t\t\"IP Header\": ");
	PrintData(Buffer , iphdrlen);
	fprintf(logfile , ",\n");
	fprintf(logfile , "\t\t\t\"UDP Header\": ");
	PrintData(Buffer+iphdrlen , sizeof udph);
	fprintf(logfile , ",\n");
	fprintf(logfile , "\t\t\t\"Data Payload\": ");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , Size - header_size);
	fprintf(logfile , "\n");
	if(cpt == 50) { fprintf(logfile , "\n\t\t}"); 
	} else {
		fprintf(logfile , "\n\t\t},");
	}
}
