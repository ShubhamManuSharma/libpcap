#include "header.h"
#define IPSUM 27675
char errbuf[PCAP_ERRBUF_SIZE];
pcap_dumper_t *pcapfile;
pcap_t *pcap;			// handler to dump into file after modification
pcap_t *phandler;		// pcap read handler

void init_pcap_for_write()
{
	pcapfile = pcap_dump_open(phandler, "dump.pcap");
	if(!pcapfile){
		printf("pcap open Error : %s",errbuf);
		exit(EXIT_FAILURE);
	}
}

void read_pcap(u_char *args,const struct pcap_pkthdr* header,
			    const u_char* packet)
{
	struct ether_header *eth_header;
	struct ip *ip_h;
	struct in_addr addrs;
	struct tcphdr *tcph;
	struct udphdr *udph;

	eth_header = (struct ether_header *) packet;
	eth_header->ether_dhost[0] = 0x00;
	eth_header->ether_dhost[1] = 0x0c;
	eth_header->ether_dhost[2] = 0x29;
	eth_header->ether_dhost[3] = 0x1f;
	eth_header->ether_dhost[4] = 0x0e;
	eth_header->ether_dhost[5] = 0xd4;

	/* modification ip dst addrs */
	ip_h = (struct ip_hdr *)(packet + sizeof(struct ether_header));
	inet_aton(DSTIP,&ip_h->ip_dst);
	ip_h->ip_sum = htons(0);
	ip_h->ip_sum = ipv4_cksum(ip_h);
	
	/* modification in l4 header */
	switch (ip_h->ip_p){
		case 17:
			udph = (struct udphdr *)(packet + sizeof(struct ip) + sizeof(struct ether_header));
		//	printf("cksum udp: %x to -->",udph->uh_sum);
			udph->uh_sum = udptcp_cksum(ip_h, (void *)udph);
			printf(" %x  \n",udph->uh_sum);
			break;
		case 6:
			tcph = (struct tcphdr *)(packet + sizeof(struct ip) + sizeof(struct ether_header));
			tcph->th_sum = udptcp_cksum(ip_h, (void *)tcph);
			printf("cksum tcp: %x  \n",tcph->th_sum);
			break;
	}
	
	pcap_dump((u_char *)pcapfile,header,packet);
}

int main(int argc, char *argv[])
{
	struct pcap_pkthdr *hdlr;
	char *filename;			// from the file pkts can be read
	int count;
	filename = (char *)malloc(sizeof(char)*MAX);	
	if(!filename){
		perror("MAlloc filename Error");
		exit(EXIT_FAILURE);
	}
	strcpy(filename,argv[1]);
	count = atoi(argv[2]);
	phandler = pcap_open_offline(filename,errbuf);
	if(!phandler){
		printf("pcap open Error : %s",errbuf);
		exit(EXIT_FAILURE);
	}
	init_pcap_for_write();
	pcap_loop(phandler,count,(pcap_handler)read_pcap,NULL);
	pcap_close(phandler); 
return 0;
}


/*printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",
               eth_header->ether_dhost[0],eth_header->ether_dhost[1],
	       eth_header->ether_dhost[2],eth_header->ether_dhost[3],
	       eth_header->ether_dhost[4],eth_header->ether_dhost[5]);*/
//printf(" %s\n",inet_ntoa(ip_h->ip_dst));

