#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#define DSTMAC "00:0c:29:1f:0e:d4"
#define DSTIP "172.16.1.185"
#define MAX 15
#define SIZE_ETH_HDR 14
#define PKT_TX_TCP_SEG   (1ULL << 50)


#define bswap16(x) __builtin_bswap16(x)
#define be_to_cpu_16(x) bswap16(x)
#define cpu_to_be_16(x) bswap16(x)

uint16_t
__rte_raw_cksum_reduce(uint32_t );


uint32_t raw_cksum_calc(const void *, size_t, uint32_t);

uint16_t
	raw_cksum(const void *, size_t );

uint16_t
	ipv4_cksum(const struct ip *);

uint16_t udptcp_cksum(const struct ip *, const void *);
