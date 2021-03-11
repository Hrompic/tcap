//Hrompic 2021
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#ifdef DEBUG
#define DEBUG 1

#endif
#define MAXIP 100  //Max ip address saves
#define PATH "/tmp/sdump" //Path to write file
FILE *f;

//Global vars init zeroes
struct in_addr ipaddr[MAXIP];
int npacket[MAXIP];
int j;

static void skeleton_daemon()
{
	pid_t pid;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* On success: The child process becomes session leader */
	if (setsid() < 0)
		exit(EXIT_FAILURE);

	/* Catch, ignore and handle signals */
	//TODO: Implement a working signal handler */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");

	/* Close all open file descriptors */
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
	{
		close (x);
	}

	/* Open the log file */
	openlog ("tcapdaemon", LOG_PID, LOG_DAEMON);
}


void checkIp(struct in_addr ip)
{
	if(!j)//first time
	{
		ipaddr[0] = ip;
		j++;
		return;
	}
	for(int i=0; i<=j; i++)
	{
		if(ip.s_addr==ipaddr[i].s_addr)
		{
			npacket[i]++;
			return;
		}
		else if(i==j &&/*check overflow*/ j!=MAXIP)
		{
			ipaddr[i] = ip;
			npacket[i]++;
			j++;
			return;
		}
	}
}
void help()
{
	printf("Usage: "
"start (packets are being sniffed from now on from default iface(eth0))\n\
stop (packets are not sniffed)\n\
show [ip] count (print number of packets received from ip address)\n\
select iface [iface] (select interface for sniffing eth0, wlan0, ethN, wlanN...)\n\
stat [iface] show all collected statistics for particular interface, if iface omitted - for all interfaces.\n\
--help (show usage information)\n");
}
void dump()
{
	f = fopen(PATH, "w");
	for(int i=0; i<j; i++)
	{
#if DEBUG
		printf("%s - %d\n", inet_ntoa(ipaddr[i]), npacket[i]);
#endif
		fprintf(f, "%s - %d\n", inet_ntoa(ipaddr[i]), npacket[i]);
	}
	fclose(f);
}
void my_packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet)
{

	(void)(args); //Unused

	struct ether_header *eth_header;
	eth_header = (struct ether_header *)packet;
	/* Pointers to start point of various headers */
	const u_char *ip_header;
	/* Header lengths in bytes */
	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length;

	/* Find start of IP header */
	ip_header = packet + ethernet_header_length;
	/* The second-half of the first byte in ip_header
	   contains the IP header length (IHL). */
	ip_header_length = ((*ip_header) & 0x0F);
	/* The IHL is number of 32-bit segments. Multiply
	   by four to get a byte count for pointer arithmetic */
	ip_header_length = ip_header_length * 4;

	struct ip* ip = (struct ip*)ip_header;
	checkIp(ip->ip_src);
//	checkIp(ip->ip_dst);
#if DEBUG
	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);
	printf("Source: %s\n", inet_ntoa(ip->ip_src));
	printf("Destenation: %s\n", inet_ntoa(ip->ip_dst));
#endif
}

int main(int argc, char **argv)
{
#ifdef DAEMON
	skeleton_daemon();
#endif
	f = fopen(PATH, "w");
	char errBuf[PCAP_ERRBUF_SIZE];
	int snapshot_len = 1028;
	int promiscuous = 0;
	int timeout = 1000;
	pcap_if_t* devs;

	struct bpf_program filter;
	bpf_u_int32 subnet_mask, ip;
	char *filter_exp = "ip";
	int err = pcap_findalldevs(&devs, errBuf);
	if(err==-1){printf("Error: %s", errBuf); return 2;}


	char *name = "eth0";// devs->name;
	if(argc>1)
	{
		if(!strcmp(argv[1], "stop")){return 0;}
		else if (!strcmp(argv[1], "start")){}
		else if(argc>3&&!strcmp(argv[1], "select"))
		{
			name = malloc(16);
			snprintf(name, 16, "%s", argv[3]);
			printf("%s\n", name);
		}
		else if(!strcmp(argv[1], "show"))
		{
			if(argc==2){help(); return 2;}
			filter_exp = malloc(32);
			snprintf(filter_exp, 32, "ip and src %s", argv[2]);
			printf("%s\n", filter_exp);
		}

		else if(!strcmp(argv[1], "stat"))
		{
			if(argc==2)
			for(pcap_if_t* dev = devs; strcmp(dev->name,"any"); dev = dev->next)
			{
		//		inet_ntoa(((struct sockaddr_in*)devs->addresses->addr)->sin_addr)
				pcap_lookupnet(dev->name, &ip, &subnet_mask, errBuf);

				char path[64];
				snprintf(path, 64, "/sys/class/net/%s/address", dev->name);
				FILE *fmac = fopen(path,"r");
				char mac[16];
				fscanf(fmac, "%s", mac);
				fclose(fmac);
#if DEBUG
				printf("Device: %s, ip: %s Netmask: %s HW addr:%s\n", dev->name, inet_ntoa(*(struct in_addr*)&ip), inet_ntoa(*(struct in_addr*)&subnet_mask), mac);
#endif
				fprintf(f, "Device: %s, ip: %s Netmask: %s HW addr:%s\n", dev->name, inet_ntoa(*(struct in_addr*)&ip), inet_ntoa(*(struct in_addr*)&subnet_mask), mac);
			}
			else
			{
				int err = pcap_lookupnet(argv[2], &ip, &subnet_mask, errBuf);
					if(err == -1){printf("%s\n", errBuf); return 2;}
				char path[64];
				snprintf(path, 64, "/sys/class/net/%s/address", argv[2]);
				FILE *fmac = fopen(path,"r");
				char mac[16];
				fscanf(fmac, "%s", mac);
				fclose(fmac);
	#if DEBUG
				printf("Device: %s, ip: %s Netmask: %s HW addr:%s\n", argv[2], inet_ntoa(*(struct in_addr*)&ip), inet_ntoa(*(struct in_addr*)&subnet_mask), mac);
	#endif
				fprintf(f, "Device: %s, ip: %s Netmask: %s HW addr:%s\n", argv[2], inet_ntoa(*(struct in_addr*)&ip), inet_ntoa(*(struct in_addr*)&subnet_mask), mac);
				exit(0);
			}
			exit(0);
		}
		else{ help(); return 2;}
	}
	fclose(f);
	err = pcap_lookupnet(name, &ip, &subnet_mask, errBuf);
	if(err == -1)
	{
		printf("%s, using standart interface %s\n", errBuf, devs->name);
		name = devs->name;
		pcap_lookupnet(name, &ip, &subnet_mask, errBuf);
	}
	pcap_t* handl = pcap_open_live(name, snapshot_len, promiscuous, timeout, errBuf);
	err = pcap_compile(handl, &filter, filter_exp, 0, ip);
		if(err==-1){printf("Bad filter - %s\n", pcap_geterr(handl)); exit(2);}
	err = pcap_setfilter(handl, &filter);
		if(err==-1){printf("Error setting filter - %s\n", pcap_geterr(handl)); exit(2);}

	while (1)
	{
		pcap_loop(handl, 50, my_packet_handler, NULL);
		dump();
	}
	free(name);
	fclose(f);
	exit(0);
}
