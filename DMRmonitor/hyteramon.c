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

#define NUMSLOTS 2
#define SLOT1 4369
#define SLOT2 8738
#define VCALL 4369
#define DCALL 26214
#define CALL  2
#define CALLEND 3
#define VFRAMESIZE 72

struct UDP_hdr {
        unsigned short int uh_sport;			//Source Port
        unsigned short int uh_dport;			//Destnation Port
        unsigned short int uh_ulen;			//Datagram Length
        unsigned short int uh_sum;			//Datagram Checksum
};

typedef struct str_slot {
        _Bool status;
        unsigned int source_id;                          //0 - 16777215
        unsigned int destination_id;
        unsigned short int destination_type;             //1 group, 2 private, 3 all
        unsigned short int call_type;
        struct tm *datetime;
} str_slot;

struct str_slot str_status[NUMSLOTS];

typedef struct str_repeater {
        int repeater_id;
        struct str_status *status;
        struct str_repeater *left;
        struct str_repeater *right;

} str_repeater;

str_repeater *Insert(str_repeater *leaf, int repeater_id)
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

str_repeater *Find(str_repeater *leaf, int repeater_id)
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
}
struct str_repeater *repeater = NULL;

int debug = 0;
char *devname = NULL;
void usage(int8_t e);
void printdata(struct str_repeater *leaf, int debug);

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
        struct ip *ip;
        //struct UDP_hdr *udp;
        struct str_status *tmp_status = NULL;
        struct str_repeater *tmp_repeater = NULL;
	int PacketType = 0;
        int sync = 0;
        int slot = 0;
        unsigned int capture_len = pkthdr->len;
        unsigned int IP_header_length;
        time_t Time;
	tmp_repeater = (str_repeater *)malloc(sizeof(str_repeater));
	//tmp_status = (str_slot*)malloc(sizeof(str_slot));
        packet += sizeof(struct ether_header);
        capture_len -= sizeof(struct ether_header);
        ip = (struct ip *) packet;
        IP_header_length = ip->ip_hl * 4;
        packet += IP_header_length;
        capture_len -= IP_header_length;
        //udp = (struct UDP_hdr *) packet;
        packet += sizeof(struct UDP_hdr);
        capture_len -= sizeof(struct UDP_hdr);
        Time = time(NULL);
        PacketType = *(packet + 8);
        sync = *(packet + 22) << 8 | *(packet + 23);
        if (capture_len == VFRAMESIZE) {
                if ((*(packet + 16) << 8 | *(packet + 17)) == SLOT1) {
                        slot = 1;
                };

                if ((*(packet + 16) << 8 | *(packet + 17)) == SLOT2) {
                        slot = 2;
                };
                if (sync) {
                        tmp_status->slot[slot]->source_id = *(packet + 38) << 16 | *(packet + 40) << 8 | *(packet + 42);

                        switch (sync) {
                        case VCALL:				//VOICE TRAFFIC PAYLOAD
                                tmp_status->slot[slot]->call_type = 1;
                                break;
                        case DCALL:				//DATA PAYLOAD
                                tmp_status->slot[slot]->call_type = 2;
                                break;
                        };
                };

                if ((PacketType == 2) & (sync != 0)) {  	//NEW OR CONTINUED TRANSMISSION
                        tmp_status->slot[slot]->status = 1;
                };

                if (PacketType == 3) {                  	//END OF TRANSMISSION
                        tmp_status->slot[slot]->status = 0;
                };
		printf("SLOT:%i",slot);
		tmp_status->slot[slot]->destination_id = *(packet + 66) << 16 | *(packet + 65) << 8 | *(packet + 64);

                tmp_status->slot[slot]->datetime = gmtime(&Time);

                tmp_status->slot[slot]->destination_type = 1;     //Set to group call by default for now, until found in stream

                tmp_repeater->status = tmp_status;		//store the temp status into the temp repeater for insertion into the btree

                tmp_repeater->repeater_id = ip->ip_src.s_addr;

                tmp_repeater->left = NULL;			//set the left and right to null since we are not using em here

                tmp_repeater->right = NULL;
        };
        //repeater = Insert(tmp_repeater, ip->ip_src.s_addr);

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
        printf("hytera 0.05\n");
        exit(1);
}


void printdata(struct str_repeater *leaf, int debug)
{
        if (debug == 2) {
                //printf("%s",inet_ntoa(ip->ip_src));
                //printf(":%d -> ",ntohs(udp->uh_sport));
                //printf("%s", inet_ntoa(ip->ip_dst));
                //printf(":%d -> ",ntohs(udp->uh_dport));
                //while (i < capture_len) {
                //        printf("%02X", packet[i]);
                //        i++;
                //}
                //printf("\n");
        };

        if (debug == 1) {
                //printf("Source Repeater: %i\tSlot: %i\t Call Type: ",leaf->repeater_id, Data->SlotNum);
                //if (leaf->call_type == 1){
                //	printf("Voice");
                //};
                //if (leaf->call_type == 2){
                //       	printf("Data");
                //};
                //printf("\tDestination Type: ");
                //if (leaf->call_type == 1){
                //        printf("Group ");
                //};
                //if (leaf->call_type == 2){
                //        printf("Private ");
                //};
                //if (leaf->call_type == 3){
                //        printf("All ");
                //};
                //printf("\tSource ID: %i\tDestination ID: %i\n", leaf->source_id, leaf->destination_id);
        }

        if (debug == 0) {
                //printf("%04d-%02d-%02d ",Data->DateTime->tm_year+1900, Data->DateTime->tm_mon+1, Data->DateTime->tm_mday);
                //printf("%02d:%02d:%02d ",Data->DateTime->tm_hour, Data->DateTime->tm_min, Data->DateTime->tm_sec);
                //printf("%s %i %i %i %i %i\n",inet_ntoa(Data->RepeaterID), Data->SlotNum, Data->CallType, Data->DstType,  Data->SourceID, Data->DestinationID);
        }

};
