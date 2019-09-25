#include "header.h"
/*uint16_t cpu_to_be_16(unsigned short len)
{
	return (((len >> 8) & 0x00ff) | ((len << 8) & 0xff00));
}

uint16_t be_to_cpu_16(unsigned short len)
{
	return (((len >> 8) & 0x00ff) | ((len << 8) & 0xff00));
}
*/
uint16_t raw_cksum_reduce(uint32_t sum)
{
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	return (uint16_t)sum;
}

uint32_t raw_cksum_calc(const void *buf, size_t len, uint32_t sum)
{
	/* workaround gcc strict-aliasing warning */
	uintptr_t ptr = (uintptr_t)buf;
	typedef uint16_t __attribute__((__may_alias__)) u16_p;
	const u16_p *u16 = (const u16_p *)ptr;

	while (len >= (sizeof(*u16) * 4)) {
		sum += u16[0];
		sum += u16[1];
		sum += u16[2];
		sum += u16[3];
		len -= sizeof(*u16) * 4;
		u16 += 4;
	}
	while (len >= sizeof(*u16)) {
		sum += *u16;
		len -= sizeof(*u16);
		u16 += 1;
	}

	/* if length is in odd bytes */
	if (len == 1)
		sum += *((const uint8_t *)u16);
	return sum;
}

uint16_t ipv4_phdr_cksum(const struct ip *ipv4_hdr, uint64_t ol_flags)
{
	/* psudo header */
	struct ipv4_psd_header {
		uint32_t src_addr; /* IP address of source host. */
		uint32_t dst_addr; /* IP address of destination host. */
		uint8_t  zero;     /* zero. */
		uint8_t  proto;    /* L4 protocol type. */
		uint16_t len;      /* L4 length. */
	} psd_hdr;

	psd_hdr.src_addr = ipv4_hdr->ip_src.s_addr;
	psd_hdr.dst_addr = ipv4_hdr->ip_dst.s_addr;
	psd_hdr.zero = 0;
	psd_hdr.proto = ipv4_hdr->ip_p;
	if (ol_flags & PKT_TX_TCP_SEG) {
		psd_hdr.len = 0;
	} else {
		psd_hdr.len = cpu_to_be_16((uint16_t)(be_to_cpu_16(ipv4_hdr->ip_len)
						- sizeof(struct ip)));
	}
	return raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

uint16_t raw_cksum(const void *buf, size_t len)
{
	uint32_t sum;

	sum = raw_cksum_calc(buf, len, 0);
	return raw_cksum_reduce(sum);
}

uint16_t ipv4_cksum(const struct ip *ipv4_hdr)
{
	uint16_t cksum;
	cksum = raw_cksum(ipv4_hdr, sizeof(struct ip));
	return (cksum == 0xffff) ? cksum : ~cksum;
}

uint16_t udptcp_cksum(const struct ip *ipv4_hdr, const void *l4_hdr)
{
	uint32_t cksum;
	uint16_t l4_len;

	l4_len = be_to_cpu_16(ipv4_hdr->ip_len) - sizeof(struct ip);

	cksum = raw_cksum(l4_hdr, l4_len);
	cksum = ipv4_phdr_cksum(ipv4_hdr, 0);

	cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
	cksum = (~cksum) & 0xffff;
	if (cksum == 0)
		cksum = 0xffff;

	return cksum;
}
 
