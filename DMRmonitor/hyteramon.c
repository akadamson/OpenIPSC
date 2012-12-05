/*
hyteramon.c - monitor hytera repeater and send to server
Copyright (C) 2012 David Kierzokwski (kd8eyf@digitalham.info)

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
#include "/usr/include/pcap/pcap.h" 			// NEED TO FIX THIS SO COMPILIER AUTOMATICALLY FINDS !!
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/udp.h>
#include<netinet/ip.h>
#include<getopt.h>
#include<time.h>

#define NUMSLOTS 2					//DMR IS 2 SLOT 
#define SLOT1 4369					//SLOT 1 IS SHOWN AS ARRAY ELEMENT 0
#define SLOT2 8738					//SKIT 2 US SHOWS AS ARRAY ELEMENT 1
#define VCALL 4369
#define DCALL 26214
#define CALL  2
#define CALLEND 3
#define VFRAMESIZE 72					//UDP PAYLOAD SIZE OF REPEATER VOICE/DATA TRAFFIC

struct UDP_hdr {
        unsigned short int uh_sport;			//Source Port
        unsigned short int uh_dport;			//Destnation Port
        unsigned short int uh_ulen;			//Datagram Length
        unsigned short int uh_sum;			//Datagram Checksum
};

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

int printstatus(int repeater_id, int slot)
{
	str_status *tmp_status;
	tmp_status = (str_status*)malloc(sizeof(str_status));
	printf("RID:%i SLOT:%i",repeater_id, slot);
	tmp_status = Find(repeater, repeater_id);
	if (tmp_status == NULL) { printf ("NULL"); return; };
	printf("%04d-%02d-%02d %02d:%02d:%02d REP_ID:%i07 SLOT:%i SRC_ID:%07i DST_ID:%07i \n",
        	tmp_status->slot[slot].datetime->tm_year+1900,
                tmp_status->slot[slot].datetime->tm_mon+1,
                tmp_status->slot[slot].datetime->tm_mday,
                tmp_status->slot[slot].datetime->tm_hour,
                tmp_status->slot[slot].datetime->tm_min,
                tmp_status->slot[slot].datetime->tm_sec,
                repeater_id,
                slot,
                tmp_status->slot[slot].source_id,
                tmp_status->slot[slot].destination_id);
};

int debug = 0;
char *devname = NULL;
void usage(int8_t e);
void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        struct ip *ip;
        struct UDP_hdr *udp;

	str_status *tmp_status;
	str_repeater *tmp_repeater;
	tmp_repeater = (str_repeater*)malloc(sizeof(str_repeater));
        tmp_status = (str_status*)malloc(sizeof(str_status));

	int PacketType = 0;
        int sync = 0;
        int slot = 0;
        unsigned int capture_len = pkthdr->len;
        unsigned int IP_header_length;
        time_t Time;
	packet += sizeof(struct ether_header);
        capture_len -= sizeof(struct ether_header);
        ip = (struct ip *) packet;
        IP_header_length = ip->ip_hl * 4;
        packet += IP_header_length;
        capture_len -= IP_header_length;
        udp = (struct UDP_hdr *) packet;
        packet += sizeof(struct UDP_hdr);
        capture_len -= sizeof(struct UDP_hdr);
        Time = time(NULL);
        PacketType = *(packet + 8);				//START DECODING STUFF
        sync = *(packet + 22) << 8 | *(packet + 23);
        if (capture_len == VFRAMESIZE) {
                if ((*(packet + 16) << 8 | *(packet + 17)) == SLOT1) {
                        slot = 0;
                } else if ((*(packet + 16) << 8 | *(packet + 17)) == SLOT2) {
                        slot = 1;
                };
                if (sync) {
                        tmp_status->slot[slot].source_id = *(packet + 38) << 16 | *(packet + 40) << 8 | *(packet + 42);

                        switch (sync) {
                        case VCALL:				//VOICE TRAFFIC PAYLOAD
                                tmp_status->slot[slot].call_type = 1;
                                break;
                        case DCALL:				//DATA PAYLOAD
                                tmp_status->slot[slot].call_type = 2;
                                break;
                        };
                };
		tmp_status->slot[slot].destination_id = *(packet + 66) << 16 | *(packet + 65) << 8 | *(packet + 64);	//Radio Destination
                tmp_status->slot[slot].datetime = gmtime(&Time);//Store the Time / Need to check if start / end ?
                tmp_status->slot[slot].destination_type = 1;    //Set to group call by default for now, until found in stream
                tmp_repeater->status = tmp_status;              //store the temp status into the temp repeater for insertion into the btree
                tmp_repeater->repeater_id = ip->ip_src.s_addr;  //set the btree index
                tmp_repeater->left = NULL;                      //set the left and right to null since we are not using em here
                tmp_repeater->right = NULL;

                if ((PacketType == 2) & (sync != 0)) {  	//NEW OR CONTINUED TRANSMISSION
			if (((Find(repeater, ip->ip_src.s_addr)) == 0)){				//Check if this repeater exists
				printf("NEW REPEATER\n");						//IF NOT PRINT A MESSAGE
        			tmp_status->slot[slot].status = 1;
				repeater = Insert(tmp_repeater, ip->ip_src.s_addr);			//AND ALLOCATE 
                                printstatus(ip->ip_src.s_addr, slot);
			};
			if ((((Find(repeater, ip->ip_src.s_addr))))->status->slot[slot].status == 0){	//First Time heard this transmission?
				tmp_status->slot[slot].status = 1;					//If So store temp status as active
				repeater = Insert(tmp_repeater, ip->ip_src.s_addr);			//And apply to actual status
				printstatus(ip->ip_src.s_addr, slot);
				return;
			} else { 
			};
                };

                if (PacketType == 3) {                  	//END OF TRANSMISSION
                        tmp_status->slot[slot].status = 0;
			repeater = Insert(tmp_repeater, ip->ip_src.s_addr);
			printstatus(ip->ip_src.s_addr, slot);
                };
	
	};
};

int main(int argc, char *argv[])
{
        char packet_filter[] = "ip and udp";
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
        char errbuf[100] , devs[100][100];
        int count = 1 , n;
        handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);

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
               "   -d, --debug         Show whats happening in english\n"
               "   -p, --payload       Dump UDP payload data in one line hex (usefull for reverse engineering)\n"
               "\n"
               "Report cat bugs to kd8eyf@digitalham.info\n");
        exit(e);
}

int version(void)
{
        printf("hytera 0.08\n");
        exit(1);
}
