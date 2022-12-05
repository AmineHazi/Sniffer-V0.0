#include "../headers/sniffer.h"

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	unsigned short iphdrlen;
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
	//Get the lenght of the IP header
	iphdrlen = iph->ihl * 4;
	//Get the ICMP header part without the Ethernet and IP headers. 
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
	//Get the size of the header part (Ethernet + IP + ICMP)
	int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	
	/* fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");	
	
	print_ip_header(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "ICMP Header\n");
	fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
			
	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
	fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
	fprintf(logfile , "\n");

	fprintf(logfile , "IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfile , "UDP Header\n");
	PrintData(Buffer + iphdrlen , sizeof icmph);
		
	fprintf(logfile , "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	
	fprintf(logfile , "\n###########################################################"); */
	
	fprintf(logfile , "\n\n\t\t{\n");	
	fprintf(logfile , "\t\t\t\"Protocol Name\": \"ICMP\",\n");

	print_ip_header(Buffer , Size);
			
	fprintf(logfile , "\n");
		
	fprintf(logfile , "\t\t\t\"Type\": \"%d\",\n",(unsigned int)(icmph->type));
			
/* 	if((unsigned int)(icmph->type) == 11)
	{
		fprintf(logfile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
	{
		fprintf(logfile , "  (ICMP Echo Reply)\n");
	}
	 */
	fprintf(logfile , "\t\t\t\"Code\": \"%d\",\n",(unsigned int)(icmph->code));
	fprintf(logfile , "\t\t\t\"Checksum\": \"%d\",\n",ntohs(icmph->checksum));
	//fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
	//fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));

	fprintf(logfile , "\t\t\t\"IP Header\": ");
	PrintData(Buffer,iphdrlen);
	fprintf(logfile , ",\n");	

	fprintf(logfile , "\t\t\t\"UDP Header\": ");
	PrintData(Buffer + iphdrlen , sizeof icmph);
	fprintf(logfile , ",\n");

	fprintf(logfile , "\n\t\t\t\"Data Payload\": ");	
	
	//Move the pointer ahead and reduce the size of string
	PrintData(Buffer + header_size , (Size - header_size) );
	fprintf(logfile , "\n");
	if(cpt == 50) { fprintf(logfile , "\n\t}\t"); 
	} else {
		fprintf(logfile , "\n\t\t},");
	}
}
