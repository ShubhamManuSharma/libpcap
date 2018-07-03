#include"headers.h"
//#include"IPv6_struct.h"
#include"declaration.h"
#define SIZE_ETHERNET 14


void callback_function(u_char *dumpfile, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	pcap_dump(dumpfile, pkthdr, packet);	
}

int main()
{
	int i=0,getlink, *arr[10];
	int cnt;
	const char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program filt;
	bpf_u_int32 net,mask;
	struct pcap_pkthdr header;					// Pointer that store the info about the packet to be captured
	const u_char *packet;
	u_char *user;
	pcap_dumper_t *dumpfile = NULL;
	const char *filename = "savefile";
	
	dev = pcap_lookupdev(errbuf);                                  // looking for online devices
	printf("dev : %s\n",dev);	
	handle = pcap_open_live(dev, BUFSIZ, -1, 1000, errbuf);         // Opening the available  device 
	if(handle==NULL)
	{
		fprintf(stderr,"No device found : %s\n",errbuf);
		return (2);
	}
	
	dumpfile = pcap_dump_open(handle, filename);
	if(dumpfile == NULL)
	{
		fprintf(stderr,"Error to opening file : \n");
		return -1;
	}
	
	printf("Source MAC      >   Destination        ProtoType\t\n");
	pcap_loop(handle, -1, callback_function, (unsigned char *)dumpfile);			// loop

return 0;
}
