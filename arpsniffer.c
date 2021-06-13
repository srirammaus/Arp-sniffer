#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h> // To invoke the libpcap library and use its functions.
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h> 
#include <unistd.h>
//#include <libnotify/notify.h>

#define ARP_REQUEST 1	//ARP Request
#define ARP_RESPONSE 2	//ARP Response
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;		//Hardware type
  uint16_t ptype;		//Protocol type
  uint8_t hlen;			//Hardware address lenght (MAC)
  uint8_t plen;			//Protocol address length
  uint16_t opcode;		//Operation code (request or response)
  uint8_t sender_mac[6];	//Sender hardware address	
  uint8_t sender_ip[4];		//Sender IP address
  uint8_t target_mac[6];	//Target MAC address
  uint8_t target_ip[4];		//Target IP address
};


void alert_spoof(char *ip, char *mac){
	printf("\nAlert: Possible ARP Spoofing Detected. IP: %s and MAC: %s\n", ip, mac);
} 

int print_available_interfaces(){
	char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *temp;
	int i = 0;
	
	if(pcap_findalldevs(&interfaces, error) == -1){
		printf("Cannot acquire the devices\n");
		return -1;
	}
	
	printf("The available interfaces are: \n");
	for(temp = interfaces; temp; temp=temp->next){
		printf("#%d: %s\n", ++i, temp->name);
	}
	return 0;
}

void print_version(){
	printf("   /   |  / __ \\/ __ \\                    \n");
	printf("  / /| | / /_/ / /_/ /                    \n");
	printf(" / ___ |/ _, _/ ____/                     \n");
	printf("/_/__|_/_/ |_/_/_________________________ \n");
	printf("  / ___// | / /  _/ ____/ ____/ ____/ __ \\ \n");
	printf("  \\__ \\/  |/ // // /_  / /_  / __/ / /_/ /\n");
	printf(" ___/ / /|  // // __/ / __/ / /___/ _, _/ \n");
	printf("/____/_/_|_/___/_/ __/_/   /_____/_/ |_|  \n");

	printf("\nLAHTP ARP Spoof Detector v0.1\n");
	printf("\nThis tool will sniff for ARP packets in the interface and can possibly detect if there is an ongoing ARP spoofing attack. This tool is still in a beta stage. \n");
}

void print_help(char *bin){

	printf("\nAvailable arguments: \n");
	printf("----------------------------------------------------------\n");
	printf("-h or --help:\t\t\tPrint this help text.\n");
	printf("-l or --lookup:\t\t\tPrint the available interfaces.\n");
	printf("-i or --interface:\t\tProvide the interface to sniff on.\n");
	printf("-v or --version:\t\tPrint the version information.\n");
	printf("----------------------------------------------------------\n");
	printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", bin);
	exit(1);
	
}

char* get_hardware_address(uint8_t mac[6]){
	char *m = (char*)malloc(20*sizeof(char));
		
	sprintf(m, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return m;
}

char* get_ip_address(uint8_t ip[4]){
	char *m = (char*)malloc(20*sizeof(char));
	sprintf(m, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
	return m;
}

int sniff_arp(char *device_name){
	char error[PCAP_ERRBUF_SIZE];
	pcap_t* pack_desc;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr; //net/ethernet.h
	arp_hdr *arpheader = NULL;
	int i;
	u_char *hard_ptr;
	char *t_mac, *t_ip, *s_mac, *s_ip;
	int counter = 0;
	time_t ct, lt;
	long int diff = 0;
	pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
	if(pack_desc == NULL){
		printf("%s\n", error);
		print_available_interfaces();
		return -1;
	} else {
		printf("Listening on %s...\n", device_name);
	}
	while(1){
		packet = pcap_next(pack_desc, &header);
		if(packet == NULL){
			printf("Error: Cannot capture packet\n");
			return -1;
		} else {
			eptr = (struct ether_header*) packet;
			if (ntohs(eptr->ether_type) == ETHERTYPE_ARP){
				ct = time(NULL);
				diff = ct - lt;
				printf("ct: %ld; Diff: %ld; Counter: %d\n",ct, diff, counter);
				if(diff > 20){
					counter = 0;
				}
				arpheader = (arp_hdr*)(packet+14);
				printf("\nReceived an ARP packet with length %d\n", header.len);
				printf("Received at %s", ctime((const time_t*) &header.ts.tv_sec));
				printf("Ethernet Header Length: %d\n", ETHER_HDR_LEN);
				printf("Operation Type: %s\n", (ntohs(arpheader->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");
				s_mac = get_hardware_address(arpheader->sender_mac);
				s_ip = get_ip_address(arpheader->sender_ip);
				t_mac = get_hardware_address(arpheader->target_mac);
				t_ip = get_ip_address(arpheader->target_ip);
				printf("Sender MAC: %s\n", s_mac);
				printf("Sender IP: %s\n", s_ip);
				printf("Target MAC: %s\n", t_mac);
				printf("Target IP: %s\n", t_ip);
				printf("--------------------------------------------------------------");
				counter++;
				lt = time(NULL);
				if(counter > 10){
					alert_spoof(s_ip, s_mac);
				}
					
			}
		}
	}
	return 0;

}

int main(int argc, char *argv[]){

	if(access("/usr/bin/notify-send", F_OK) == -1){
		printf("Missing dependencies: libnotify-bin\n");
		printf("Please run: sudo apt-get install libnotify-bin");
		printf("\n");
		print_version();
		exit(-1);
	}
	
	if(argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0){
		print_version();
		print_help(argv[0]);
	} else if(strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0){
		print_version();
		exit(1);
	} else if(strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0){
		print_available_interfaces();
	} else if(strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0){
		if(argc < 3){
			printf("Error: Please provide an interface to sniff on. Select from the following.\n");
			printf("--------------------------------------------------------------------------\n");
			print_available_interfaces();
			printf("\nUsage: %s -i <interface> [You can look for the available interfaces using -l/--lookup]\n", argv[0]);
		} else {
			sniff_arp(argv[2]);
		}
			
			
	} else {
		printf("Invalid argument.\n");
		print_help(argv[0]);
	}
	return 0;
}









	
