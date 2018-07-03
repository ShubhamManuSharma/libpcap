void callback_function(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        int i=0;
        static int count=0;
        struct ethernet_header *ethernet=NULL;
        struct ip_header *ip=NULL;
        struct icmp_header *icmp=NULL;
        struct tcp_header *tcp=NULL;
        struct udp_header *udp=NULL;
        struct arp_header *arp=NULL;
        struct ip6_header *ip6=NULL;
        struct ip6_header var;
        struct udp6_header *udp6=NULL;
        struct tcp6_header *tcp6=NULL;
        struct icmp6_header *icmp6=NULL;
        int size_ip, size_tcp;


        ethernet = (struct ethernet_header *)packet;

        switch(ethernet->ether_type)
        {
                case 0x0008 :
                                ip = (struct ip_header *)(packet + 14);
                                size_ip = IP_HL(ip) * 4;
                                if(size_ip < 20)
                                {
                                        printf("\n");
                                }
                                else
                                {
                                        printf("(%hhx:%hhx:%hhx:%hhx:%hhx:%hhx) > (%hhx:%hhx:%hhx:%hhx:%hhx:%hhx), ",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                                        printf("IPv4 (0x0800), ");
                                        printf("length %hu ",ip->ip_len);
                                        printf("%s > ",inet_ntoa(ip->ip_src));
                                        printf("%s : ",inet_ntoa(ip->ip_dst));

                                        switch(ip->ip_p)
                                        {
                                                case 1:
                                                        printf("ICMP ");
				 			icmp = (struct icmp_header *)(packet + SIZE_ETHERNET + size_ip);
                                                        printf("checksum %d\n",icmp->checksum);
                                                        break;
                                                case 6:
                                                        printf("TCP ");
                                                        tcp = (struct tcp_header *)(packet + SIZE_ETHERNET+ size_ip);
                                                        size_tcp= TH_OFF(tcp)*4;
                                                        if(size_tcp < 20)
                                                        {
                                                                printf("\n");
                                                        }
                                                        else
                                                        {
                                                                printf("win %hu ",tcp->th_win);
                                                                printf("Checksum %hu\n",tcp->th_sum);
                                                        }
                                                        break;
                                                case 17:
                                                        printf("UDP ");
                                                        udp = (struct udp_header *)(packet + SIZE_ETHERNET + size_ip);
                                                        printf("lenght %d\n",udp->udp_length);
                                                        break;
                                                default:
                                                        printf("\n");
                                                        break;
                                        }
                                }

                                break;
                case 0x0608 :
                                arp = (struct arp_header *)(packet + SIZE_ETHERNET);
                                printf("(%hhx:%hhx:%hhx:%hhx:%hhx:%hhx) > (%hhx:%hhx:%hhx:%hhx:%hhx:%hhx), ",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                                printf("ARP (0x0806), ");
                                if(arp->hlen > 0)
                                {
                                        printf("lenght %d ",arp->hlen);
                                        printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx > ",arp->sender_mac[0],arp->sender_mac[1],arp->sender_mac[2],arp->sender_mac[3],arp->sender_mac[4],arp->sender_mac[5]);
                                        printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",arp->target_mac[0],arp->target_mac[1],arp->target_mac[2],arp->target_mac[3],arp->target_mac[4],arp->target_mac[5]);
                                        printf(" %u.%u.%u.%u > ",arp->sender_ip[0],arp->sender_ip[1],arp->sender_ip[2],arp->sender_ip[3]);
                                        printf(" %u.%u.%u.%u,  ",arp->target_ip[0],arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
                                        printf("length %d\n",arp->plen);
                                }
                                else
                                       printf("\n");
                                break;
                case 0xdd86 :
                                ip6 = (struct ip6_header *)(packet + 14);
                                printf("(%hhx:%hhx:%hhx:%hhx:%hhx:%hhx) > (%hhx:%hhx:%hhx:%hhx:%hhx:%hhx), ",ethernet->ether_shost[0],ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
                                printf("IPv6(0x86dd) ");
                                switch(ip6->next_header)
                                {
                                        case 1:
                                                printf("ICMP(1)");
                                                break;
                                        case 6:
                                                printf("TCP(6) ");
                                                break;
                                        case 17:
                                                printf("UDP(17),");
                                                break;
                                        default:
                                                printf("\n");
                                                break;
                                }

                                printf("payload length %d, ",ip6->length);
                                printf("%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx > ",(int)ip6->src.s6_addr[0], (int)ip6->src.s6_addr[1],(int)ip6->src.s6_addr[2], (int)ip6->src.s6_addr[3],(int)ip6->src.s6_addr[4], (int)ip6->src.s6_addr[5],(int)ip6->src.s6_addr[6], (int)ip6->src.s6_addr[7],(int)ip6->src.s6_addr[8], (int)ip6->src.s6_addr[9],(int)ip6->src.s6_addr[10],(int)ip6->src.s6_addr[11],(int)ip6->src.s6_addr[12], (int)ip6->src.s6_addr[13],(int)ip6->src.s6_addr[14], (int)ip6->src.s6_addr[15]);
                                printf("%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx:%hx%hx \n",(int)ip6->dst.s6_addr[0], (int)ip6->dst.s6_addr[1],(int)ip6->dst.s6_addr[2], (int)ip6->dst.s6_addr[3],(int)ip6->dst.s6_addr[4], (int)ip6->dst.s6_addr[5],(int)ip6->dst.s6_addr[6], (int)ip6->dst.s6_addr[7],(int)ip6->dst.s6_addr[8], (int)ip6->dst.s6_addr[9],(int)ip6->dst.s6_addr[10],(int)ip6->dst.s6_addr[11],(int)ip6->dst.s6_addr[12], (int)ip6->dst.s6_addr[13],(int)ip6->dst.s6_addr[14], (int)ip6->dst.s6_addr[15]);
                                break;
                default:
                        printf("\n");
                        break;


        }

}
                        
