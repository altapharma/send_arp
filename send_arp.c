#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>    
#include <stdlib.h>
//get my mac addr

//get others mac addr -- request

/* Ethernet header */
  struct sniff_ethernet {
        
  #define ETHER_ADDR_LEN 6
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
        };


/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
  struct arphdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}; 
//attack


int main(int argc, char* argv[])
{
	struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int i;
    int packet_len;

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

    unsigned char mac_address[6];

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    for(i=0;i<6;i++)
    {
    		printf("%02x",mac_address[i]);
    		if(i != 5) printf(":");
    	
    }
    printf("\n");

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , argv[1] , IFNAMSIZ - 1);
	ioctl(sock, SIOCGIFADDR, &ifr);
	struct in_addr my_ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	//printf("IP Address is %s\n",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	printf("IP Address is %s\n",inet_ntoa(my_ip_addr));

	close(sock);

   /////////////////////////////////////////////////////////////////////////////////////
   //make packet 
    struct in_addr senderIP, targetIP;
	u_char* packet;
	struct sniff_ethernet* eth;
	struct sniff_ethernet* recv_eth;
	struct arphdr* arp;
	struct arphdr* recv_arp;
	struct pcap_pkthdr* header;
	u_char recv_mac[6];

	#define SIZE_ETHERNET 14


    inet_pton(AF_INET,argv[2],&senderIP.s_addr);
	inet_pton(AF_INET,argv[3],&targetIP.s_addr);

	eth = (struct sniff_ethernet*)malloc(sizeof(struct sniff_ethernet));
	arp = (struct arphdr*)malloc(sizeof(struct arphdr));
	printf("choi\n");
	memcpy(eth->ether_dhost,"\xff\xff\xff\xff\xff\xff",ETHER_ADDR_LEN);
	memcpy(eth->ether_shost,mac_address,ETHER_ADDR_LEN);
	eth->ether_type = htons(0x0806);
	printf("kim\n");
	arp->htype = htons(0x0001);
	arp->ptype = htons(0x0800);
	arp->hlen = 0x06;
	arp->plen = 0x04;
	arp->oper = htons(0x0001);
	memcpy(arp->sha,mac_address,6);
	printf("1\n");
	memcpy(arp->spa,&my_ip_addr,4);
	printf("2\n");
	memcpy(arp->tha,"\x00\x00\x00\x00\x00\x00",6);
	printf("3\n");
	memcpy(arp->tpa,&senderIP,4);
	printf("4\n");
	packet = (u_char*)malloc(sizeof(struct sniff_ethernet)+sizeof(struct arphdr));

	memcpy(packet,eth,sizeof(struct sniff_ethernet));
	memcpy(packet+sizeof(struct sniff_ethernet),arp,sizeof(struct arphdr));
	packet_len = sizeof(struct sniff_ethernet) + sizeof(struct arphdr);

	printf("packet_len : %d\n",packet_len);

	printf("memset ok\n");
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  printf("handle\n");
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
/*
	printf("\n[+] packet to send\n");
	for(int i=0;i<packet_len;i++){
		if(i != 0 && i%16 == 0)
			printf("\n");
		printf("%02x ",*(packet+i));
	}
	printf("end\n");
*/
  	
	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0)
			break;
			//printf("sbsbsbsbsb\n");
	}
	
	while (1) {
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    /*
     -1 if an error occurred 
     -2 if EOF was reached reading from an offline capture
    */
    recv_eth = (struct sniff_ethernet*)packet;

    printf("Start!\n");
    printf("*************************************************************************\n");

    if(recv_eth->ether_type == 0x0806) //arp
    {
    	recv_arp = (struct arphdr*)(packet + SIZE_ETHERNET);

    	if(recv_arp->oper == htons(0x0002))
    	{
    		char* ptr;
  	
			u_char* ip_buf_tmp = (u_char*)malloc(4);
    		sprintf(ip_buf_tmp, "%x%x%x%x",recv_arp->tpa[3],recv_arp->tpa[2],recv_arp->tpa[1],recv_arp->tpa[0]);
    		if(senderIP.s_addr == strtol(ip_buf_tmp,&ptr,16))
    		{
    			memcpy(recv_mac,recv_eth->ether_shost,6);
    			printf("recv mac :%s\n",recv_mac);
    		}
    	}
    }
	
	}
} 














