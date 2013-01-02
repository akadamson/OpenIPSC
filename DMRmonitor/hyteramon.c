/*
hyteramon.c - monitor hytera repeater and send to server
C 2012 David Kierzokwski (kd8eyf@digitalham.info)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA. */

#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include<pcap/pcap.h> 			
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<getopt.h>
#include<time.h>

#define NUMSLOTS 2				
#define SLOT1    0x1111		
#define SLOT2    0x2222		
#define DMR      0x1111				
#define PTPP	 0x50325050
#define VCALL    0x1111					
#define DCALL    0x6666				
#define SYNC     0xEEEE				

#define VFRAMESIZE 	0x48					//UDP PAYLOAD SIZE OF REPEATER VOICE/DATA TRAFFIC

#define SLOT_OFFSET 	16
#define SYNC_OFFSET 	18
#define DMR_OFFSET 	20				//VOICE 
#define PTP_OFFSET 	5				//STATUS
#define PTPP_OFFSET 	6
#define PTPP_MS		0x0D
#define SRC_OFFSET1 	38				
#define SRC_OFFSET2 	40
#define SRC_OFFSET3 	42
#define DST_OFFSET1 	32
#define DST_OFFSET2 	34
#define DST_OFFSET3 	36

#define MAX_REPEATERS 	1

typedef struct str_dev_string{
	uint8_t flag1;
        uint8_t flag2;
	//uint16_t udp_port;
	//struct in_addr ip_address;
}str_dev_string;

typedef struct str_ptpp_msg {
	int32_t header;
	uint8_t msgtype;
	char null1[7];
	uint8_t seq;
	uint8_t flag1;
	uint8_t flag2;
  	uint8_t flag3;
	uint8_t flag4;
	char null2[3];	
	uint8_t num_devices;	
	char null3;
	uint8_t service;
	char null5[2];
} str_ptpp_msg;

struct str_slot {
        int status;					 //0 - UNKEYED. 1 - KEYED
        unsigned int source_id;                          //0 - 16777215
        unsigned int destination_id;			 //0 - 16777215
        unsigned short int destination_type;             //1 - Group, 2 - Private, 3 - All ***** NEED TO IMPLEMENT STILL
        unsigned short int call_type;			 //1 - VOICE, 2 - DATA
        struct tm *datetime;				 //YYYY-MM-DD HH:MM:SS UTC format is used
};

typedef struct str_status {
        struct str_slot slot[NUMSLOTS];
} str_status;

typedef struct str_repeater {
        int repeater_id;
	struct in_addr ip_address;
	int udp_src;
	int repeater_role;				//1 = master, 2 = slave, 3 = slave
        struct str_status *status;
        struct str_repeater *left;			//pointer to smaller node left on tree
        struct str_repeater *right;			//pointer to larger node right on tree
} str_repeater;

str_repeater *Insert(str_repeater *leaf, int repeater_id)	//Insert data into the tree
{
        if (leaf == NULL) {
                str_repeater *temp;
                temp = (str_repeater *)malloc(sizeof(str_repeater));
                temp -> repeater_id = repeater_id;
                temp -> left = temp -> right = NULL;
                return temp;
        }

        if (repeater_id > (leaf->repeater_id)) {
                leaf->right = Insert(leaf->right, repeater_id);
        } else if (repeater_id < (leaf->repeater_id)) {
                leaf->left = Insert(leaf->left, repeater_id);
        }

        return leaf;

}

str_repeater *Find(str_repeater *leaf, int repeater_id)		//Find data return null if not found
{
        if (leaf == NULL) {
                return NULL;
        }

        if (repeater_id > leaf->repeater_id) {
                return Find(leaf->right, repeater_id);
        } else if (repeater_id < leaf->repeater_id) {
                return Find(leaf->left, repeater_id);
        } else {
                return leaf;
        }
};

struct str_repeater *repeater = NULL;

void printstaitus(int repeater_id, int slot)
{
        printf("%04d-%02d-%02d %02d:%02d:%02d %i %i %i %i %i %i %i %i\n",
               repeater->status->slot[slot].datetime->tm_year+1900,
               repeater->status->slot[slot].datetime->tm_mon+1,
               repeater->status->slot[slot].datetime->tm_mday,
               repeater->status->slot[slot].datetime->tm_hour,
               repeater->status->slot[slot].datetime->tm_min,
               repeater->status->slot[slot].datetime->tm_sec,
	       repeater->repeater_id,
	       repeater->udp_src,
               repeater->status->slot[slot].status,
               slot+1,
               repeater->status->slot[slot].source_id,
               repeater->status->slot[slot].destination_id,
               repeater->status->slot[slot].call_type,
               repeater->status->slot[slot].destination_type);
	 fflush(stdout);
};

int debug = 0;
char *devname = NULL;
void usage(int8_t e);
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        struct ip *ip;
        struct udphdr *udp;
	struct str_ptpp_msg *ptpp_msg;
	struct str_dev_string *dev_string;

        str_status *tmp_status;
        str_repeater *tmp_repeater;
        
	tmp_repeater = (str_repeater*)malloc(sizeof(str_repeater));
        tmp_status = (str_status*)malloc(sizeof(str_status));
		
        int datalen = pkthdr->len;
        int ipleni =0;
	int isdata = 0;
	int issync = 0;
	int i = 0;
        int process = 0;	
	time_t Time;
       	char* c_time_string;
	 
	packet += sizeof(struct ether_header);		//Walkthrough the ethernet header
        datalen -= sizeof(struct ether_header);		//and decerement the payload size
        
	ip = (struct ip*) packet;			//setup the ip 
        packet += ip->ip_hl * 4;			//move past it
        datalen -= ip->ip_hl * 4;			//and decrement the payload size..
	
        udp = (struct udphdr *) packet;			//The Rest is UDP
        packet += sizeof(struct udphdr);		//move past 	
        datalen -= sizeof(struct udphdr);		//and decerment

	isdata = (*(packet + DMR_OFFSET) << 8 | *(packet + (DMR_OFFSET + 1)));
	issync = (*(packet + SYNC_OFFSET) << 8 | *(packet + (SYNC_OFFSET + 1)));
	
	if ((datalen == 72) && (isdata) && (issync)) {				//Packet is same size as DMR voice/data
	}
	else if ((((*(packet+0)) << 24 | (*(packet+1)) << 16 | (*(packet+2)) << 8  | (*(packet+3))) == PTPP)){
		ptpp_msg = (struct str_ptpp_msg*) packet;	
		packet += sizeof(struct str_ptpp_msg);
		datalen -= sizeof(struct str_ptpp_msg);

		if (ptpp_msg->msgtype == PTPP_MS) {
			while (i < datalen) {
        			printf("%02X", packet[i]);
	                        i++;
	                };
			printf("\n");
			i = 0;
			process = 1;
			//while (i < ptpp_msg->num_devices){
	                  //      dev_string = (struct str_dev_string*) packet;
        	                //packet += sizeof(struct str_dev_string);
                	    //    i++;
                        	//printf("%i: flag1: %x flag2: %x IP:  \n", i,dev_string->flag1, dev_string->flag2);//,  inet_ntoa(dev_string->ip_address),  ntohs(dev_string->udp_port));
		};
	};
		
		
	if ((debug ==1)&& (process ==1) ){
		Time = time(NULL);
		c_time_string = time(&Time);
		//printf("TYP:%x ",ptpp_msg->msgtype);
		//printf("NUM:%i ",ptpp_msg->num_devices);
		//printf("SEQ:%x ",ptpp_msg->seq);
		//printf("SVC:%x ",ptpp_msg->service); 
	        //printf("\n");
	};
	fflush(stdout);
};

int main(int argc, char *argv[])
{
        char packet_filter[] = "udp";
        struct bpf_program fcode;
        u_int netmask;
        pcap_t *descr = NULL;
        int32_t c;
        while ((c = getopt(argc, argv, "opdVhi:")) != EOF) {
                switch (c) {
                case 'p':
                        debug = 2;
                        break;
                case 'd':
                        debug = 1;
                        break;
                case 'V':
                        version();
                        break;
                case 'i':
                        devname = optarg;
                        break;
                case 'h':
                        usage(-1);
                        break;
                }
        }

        if (devname == NULL) {
                usage(-1);
        }

        if (debug == 1) {
                printf("USING CAPTURE DEVICE: %s\n", devname);
        }
        pcap_if_t *alldevsp , *device;
        pcap_t *handle;
	int count =1;
	char errbuf[100] , devs[100][100];
        handle = pcap_open_live(devname , 65536 , 1 , 0, errbuf);

        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s : %s\n" , devname , errbuf);
                exit(1);
        }

        pcap_compile(handle, &fcode, packet_filter, 1, netmask);

        if (pcap_loop(handle, -1, processPacket, (u_char *)&count) == -1) {
                fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr));
                exit(1);
        }
        return 0;
}
void usage(int8_t e)
{
        printf("Usage: DMRmontiorHytera [OPTION]... \n"
               "Listen send DMR data for remote server for processing\n"
               "\n"
               "   -i, --interface     Interface to listen on\n"
               "   -h, --help          This Help\n"
               "   -V, --version       Version Information\n"
               "\n"
               "Report cat bugs to kd8eyf@digitalham.info\n");
        exit(e);
}

int version(void)
{
        printf("hytera 1.00\n");
        exit(1);
}
