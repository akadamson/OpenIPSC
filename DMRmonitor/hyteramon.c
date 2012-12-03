/*
dmrmonitor-hytera - monitor hytera repeater and send to server
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
#define NUMREPEATERS 10

struct UDP_hdr {
        unsigned short int uh_sport;			//Source Port
        unsigned short int uh_dport;			//Destnation Port
        unsigned short int uh_ulen;			//Datagram Length
        unsigned short int uh_sum;			//Datagram Checksum
};

struct status{
        _Bool Status;					//1 active, 0 inactice
        unsigned short int SlotNum;			//1 = Slot 1, 2 = Slot 2
	unsigned short int DstType ;			//1 group, 2 private, 3 all. Need o implement detection.
	unsigned short int CallType;			//1 voice, 2 data
        unsigned int SourceID;				//0 - 16777215
        unsigned int DestinationID;			//0 - 16777215
	struct in_addr RepeaterID;			//IP Address for now
	struct tm *DateTime;				//TimeStamp
};

struct str_slot{
	_Bool Status;
	unsigned int SourceID;                          //0 - 16777215
        unsigned int DestinationID;
	unsigned short int DstType;                     //1 group, 2 private, 3 all
        unsigned short int CallType;
};

struct str_repeater{
        struct str_slot slot[2];			//2 slots for DMR
        struct in_addr DmrID;				//Using IP address as Peer ID 
};

struct str_repeater repeater[NUMREPEATERS];		//ARRAY OF REPEATERS

int debug = 0;
char *devname = NULL;

void usage( int8_t e );
void printdata (struct status *data, int debug);
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	int i=0,*counter = (int *)arg;
        int PacketType = 0;
        struct ip * ip;
        struct UDP_hdr * udp;
        struct status Data;
        int  sync = 0;
	char buffer[15];
	unsigned int capture_len = pkthdr->len;
        unsigned int IP_header_length;
       	time_t Time; 
	packet += sizeof (struct ether_header);
        capture_len -= sizeof(struct ether_header);
        ip = (struct ip*) packet;
        IP_header_length = ip->ip_hl *4;
        packet += IP_header_length;
        capture_len -= IP_header_length;
        udp = (struct UDP_hdr*) packet;
        packet += sizeof (struct UDP_hdr);
        capture_len -= sizeof (struct UDP_hdr);
	Time = time(NULL);
        PacketType = *(packet+8);	
	sync  = *(packet+22)<<8|*(packet+23);
	
	if ( (*(packet+16)<<8|*(packet+17)) == 4369){
		Data.SlotNum = 1;
	};
	if ( (*(packet+16)<<8|*(packet+17)) == 8738){
		Data.SlotNum = 2;
	};		
	
	if (sync){ 
		Data.SourceID = *(packet+38)<<16|*(packet+40)<<8|*(packet+42); 
		switch (sync) {
		case 4369:			//VOICE TRAFFIC PAYLOAD
        		Data.CallType = 1;
	                break;
		case 26214:			//DATA PAYLOAD
			Data.CallType = 2;
 			break;
	        };
	};
	Data.DestinationID = *(packet+66)<<16|*(packet+65)<<8|*(packet+64);
        Data.DateTime = gmtime(&Time);
        Data.RepeaterID = ip->ip_src;
	Data.DstType = 1;			//Set to group by default for now


	if ((PacketType == 2) & (sync != 0)) {  //NEW OR CONTINUED TRANSMISSION
                                                //NEED TO FIGURE OUT WHAT TO DO!!
        };
        if (PacketType == 3) {                  //END OF TRANSMISSION
                                                //NEED TO FIGURE OUT WHAT TO DO!
        };

	if (debug != 2) { printdata(&Data, debug); };
	if (debug == 2){			//Need to move this out of here!!!
		printf("%s",inet_ntoa(ip->ip_src));
                printf(":%d -> ",ntohs(udp->uh_sport));
                printf("%s", inet_ntoa(ip->ip_dst));
                printf(":%d ",ntohs(udp->uh_dport));
                printf("PT: %i SYNC: %i ",PacketType, sync);
		while (i < capture_len) {
                	printf("%02X", packet[i]);
                        i++;
                };
                printf("\n");
	};
};

int main(int argc, char *argv[] )
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

        if ( pcap_loop(handle, -1, processPacket, (u_char *)&count) == -1) {
                fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
                exit(1);
        }
        return 0;
}
void usage(int8_t e)
{
        printf(	"Usage: DMRmontiorHytera [OPTION]... \n"
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

int version ( void )
{
        printf ("hytera 0.04\n");
        exit(1);
}

void printdata (struct status *Data, int debug)
{
	if (debug == 2){
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
		printf("Source Repeater: %s\tSlot: %i\t Call Type: ",inet_ntoa(Data->RepeaterID), Data->SlotNum);
		if (Data->CallType == 1){
                	printf("Voice");
                };
                if (Data->CallType == 2){
                       	printf("Data");
                };
		printf("\tDestination Type: ");
		if (Data->CallType == 1){
                        printf("Group ");
                };
                if (Data->CallType == 2){
                        printf("Private ");
                };
		if (Data->CallType == 3){
                        printf("All ");
                };
		printf("\tSource ID: %i\tDestination ID: %i\n", Data->SourceID, Data->DestinationID);
	}
	if (debug == 0) {
		printf("%04d-%02d-%02d ",Data->DateTime->tm_year+1900, Data->DateTime->tm_mon+1, Data->DateTime->tm_mday);
	        printf("%02d:%02d:%02d ",Data->DateTime->tm_hour, Data->DateTime->tm_min, Data->DateTime->tm_sec);
        	printf("%s %i %i %i %i %i\n",inet_ntoa(Data->RepeaterID), Data->SlotNum, Data->CallType, Data->DstType,  Data->SourceID, Data->DestinationID);
	}

}
