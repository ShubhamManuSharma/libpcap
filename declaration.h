int ntohs_fn(u_short);

#define ETHERNET_LEN 6

struct ethernet_header
{
	u_char ether_dhost[ETHERNET_LEN];
	u_char ether_shost[ETHERNET_LEN];
	u_short ether_type;
};


struct ip_header
{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	u_char ip_th;
	u_char ip_p;
	struct in_addr ip_src, ip_dst;
};

#define IP_HL(ip) 	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) 	(((ip)->ip_vhl) >> 4)


struct tcp_header
{
	u_short th_sport;		// source port
	u_short th_dport;		// destination prot
	u_int th_seq;			// sequence number
	u_int th_ack;			// acknowledgement
	u_char th_offx2;		
	u_char th_off;			// data offset
	u_char th_flag;			
	u_short th_sum;			// Checksum
	u_short th_urp;			// urgent pointer
	u_short th_win;			//window

};
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

struct udp_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

struct icmp_header
{
    u_int8_t type;		/* message type */
    u_int8_t code;		/* type sub-code */
    u_int16_t checksum;
    union
    {
    	  struct
    	  {
      		u_int16_t	id;
  		u_int16_t	sequence;
	  } echo;			/* echo datagram */
    	  u_int32_t	gateway;	/* gateway address */
    	  struct
   	  {
      		u_int16_t	__unused;
      		u_int16_t	mtu;
    	  } frag;			/* path mtu discovery */
    } un;
};

struct arp_header 
{
  	uint16_t htype;                 // formate of hardware address
  	uint16_t ptype;			// formate of protocol address	
  	uint8_t hlen;			// length of hardware address
  	uint8_t plen;			// length of protocol address
  	uint16_t opcode;		// ARP opcode (command)
  	uint8_t sender_mac[6];		
  	uint8_t sender_ip[4];
  	uint8_t target_mac[6];
  	uint8_t target_ip[4];
};

//-----------------------------------------------------------------------------------------------------------------------------
// IPv6 Headers
struct ip6_header
{
    unsigned int
        version : 4,
        traffic_class : 8,
        flow_label : 20;
    uint16_t length;			 // define the payload length
    uint8_t  next_header;                // define the next protocol
    uint8_t  hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
};

struct icmp6_header
{
    unsigned char type;
    unsigned char code;
    unsigned short int chk_sum;
    unsigned int body;
};
struct udp6_header 
{
         __u16   source;
         __u16   dest;
         __u16   len;
         __u16   check;
};
