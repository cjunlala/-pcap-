/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#define HAVE_REMOTE

#ifndef _XKEYCHECK_H
#define _XKEYCHECK_H
#endif
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <remote-ext.h>
#include <iostream>
#include <iomanip> 
#include <fstream>
#include <cstdio>
#include <time.h>
#include <cstdlib>
using namespace std;
#define threshold 1024*1024
/* IP????????? */
typedef struct ip_header {
	u_char ver_ihl;				//Version (4 bits) + Internet header length (4 bits)
	u_char tos;					//Type of service
	u_short tlen;				//Total length
	u_short identification;		//Identification
	u_short flags_fo;			//Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl;					//Time to live
	u_char proto;				//Protocol
	u_short crc;				//Header checksum
	u_char saddr[4];			//Source address
	u_char daddr[4];			//Destination address
	u_int op_pad;				//Option + Padding
} ip_header;

/* ????????????????????????????????? */
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

//typedef struct udp_header{
//    u_short sport;          // ?????????(Source port)
//    u_short dport;          // ????????????(Destination port)
//    u_short len;            // UDP???????????????(Datagram length)
//    u_short crc;            // ?????????(Checksum)
//}udp_header;

/*
* ??????????????????????????????
* packet_handler??????????????????????????????????????????
* ??????????????????????????????????????????????????????????????????????????????libpcap?????????
*/
/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main() {
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	struct bpf_program fcode;
	char packet_filter[] = "ip and udp";

	/* ?????????????????? */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		//fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		cout << "Error in pcap_findalldevs: " << errbuf << "\n" << endl;
		system("pause");
		exit(1);
	}
	/* ???????????? */
	for (d = alldevs; d; d = d->next) {
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	cin >> inum;

	if (inum < 1 || inum > i) {
		printf("\nInterface number out of range.\n");
		/* ?????????????????? */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	/* ??????????????????????????? */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* ??????????????? */
	if ((adhandle = pcap_open(
		d->name,					//?????????
		65536,						//?????????,65536???????????????????????????????????????????????????????????????????????????
		PCAP_OPENFLAG_PROMISCUOUS,  //????????????
		1000,						//??????????????????
		NULL,						//??????????????????
		errbuf						//???????????????
	)) == NULL) {
		//fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap.\n", d->name);
		cout << "Unable to open the adapter. " << d->name << " is not supported by WinPcap.\n" << endl;
		/* ?????????????????? */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	/* ????????? */
	//?????????????????????,??????????????????
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		//fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		cout << "This program works only on Ethernet networks." << endl;
		/* ?????????????????? */
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	if (d->addresses != NULL)
		/* ???????????????????????????????????? */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* ????????????????????????,????????????C???????????? */
		netmask = 0xffffff;

	/* ???????????????????????? */
	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0) {
		cout << "\nUnable to compile the packet filter.Check the syntax." << endl;
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}
	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0) {
		cout << "\nError setting the filter." << endl;
		pcap_freealldevs(alldevs);
		system("pause");
		return -1;
	}

	printf("\nListening on %s...\n", d->description);
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* ???????????? */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	system("pause");
	return 0;

}

/* ??????libpcap???????????????????????????????????????????????? */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	mac_header* mh;
	ip_header* ih;
	ofstream fout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	for (int i = 0; i < length; i++) {
		printf("%02X ", pkt_data[i]);		//????????????????????????
		if ((i & 0xF) == 0xF)
			printf("\n");
	}

	printf("\n");

	/* ?????????????????? */
	mh = (mac_header*)pkt_data;			//????????????????????????,?????????????????????????????????????????????
	printf("mac_header:\n");
	printf("\tdest_addr: ");
	for(int i = 0; i < 6; i++){
		printf("%02X ", mh->dest_addr[i]);
	}
	printf("\n");
	printf("\tsrc_addr: ");
	for(int i = 0; i < 6; i++){
		printf("%02X ", mh->src_addr[i]);
	}
	printf("\n");
	printf("\ttype: %04X", ntohs((u_short)mh->type));
	printf("\n");

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data + sizeof(mac_header));	//length of ethernet header
	//????????????????????????,?????????????????????????????????????????????

	printf("ip_header\n");
	printf("\t%-10s: %02X\n", "ver_ihl", ih->ver_ihl);
	printf("\t%-10s: %02X\n", "tos", ih->tos);
	printf("\t%-10s: %04X\n", "tlen", ntohs(ih->tlen));
	printf("\t%-10s: %04X\n", "identification", ntohs(ih->identification));
	printf("\t%-10s: %04X\n", "flags_fo", ih->flags_fo);
	printf("\t%-10s: %02X\n", "ttl", ih->ttl);
	printf("\t%-10s: %02X\n", "proto", ih->proto);
	printf("\t%-10s: %04X\n", "crc", ih->crc);
	printf("\t%-10s: %08X\n", "op_pad", ih->op_pad);
	printf("\t%-10s: ", "saddr");
	for(int i = 0; i < 4; i++){
		printf("%02X ",ih->saddr[i]);
	}
	printf(" ");
	for(int i = 0; i < 4; i++){
		printf("%d.",ih->saddr[i]);
	}
	printf("\n");
	printf("\t%-10s: ", "daddr");
	for(int i = 0; i < 4; i++){
		printf("%02X ",ih->daddr[i]);
	}
	printf(" ");
	for(int i = 0; i < 4; i++){
		printf("%d.",ih->daddr[i]);
	}
	printf("\n");

	if (ntohs(ih->tlen) < threshold) {
		FILE* file = fopen("output.txt", "w");
		time_t tt = time(NULL);//?????????????????????????????????cuo
		tm* t = localtime(&tt);
		fprintf_s(file, "%d-%d-%d %d:%d:%d,", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->src_addr[i]);//???MAC??????
		}
		fprintf_s(file, "%02X,", mh->src_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->saddr[i]);//???IP??????
		}
		fprintf_s(file, "%d,", ih->saddr[3]);
		for (int i = 0; i < 5; i++) {
			fprintf_s(file, "%02X-", mh->dest_addr[i]);//??????MAC??????
		}
		fprintf_s(file, "%02X,", mh->dest_addr[5]);
		for (int i = 0; i < 3; i++) {
			fprintf_s(file, "%d.", ih->daddr[i]);//??????IP??????
		}
		fprintf_s(file, "%d,", ih->daddr[3]);
		fprintf_s(file, "%d", ntohs(ih->tlen));
		fclose(file);
	}
	else {
		time_t tt = time(NULL);//?????????????????????????????????cuo
		tm* t = localtime(&tt);
		printf("[%d-%d-%d %d:%d:%d]", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		printf("[");
		for (int i = 0; i < 5; i++) {
			printf("%02X-", mh->src_addr[i]);
		}
		printf("%02X,", mh->src_addr[5]);
		for (int i = 0; i < 3; i++) {
			printf("%02X.", ih->saddr[i]);
		}
		printf("%02X", ih->saddr[3]);
		printf("] SNED");
		printf("%d", ntohs(ih->tlen));
		printf("bytes out of limit.");

		printf("[%d-%d-%d %d:%d:%d]", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
		printf("[");
		for (int i = 0; i < 5; i++) {
			printf("%02X-", mh->dest_addr[i]);
		}
		printf("%02X,", mh->dest_addr[5]);
		for (int i = 0; i < 3; i++) {
			printf("%02X.", ih->daddr[i]);
		}
		printf_s("%02X,", ih->daddr[3]);
		printf("] RECV");
		printf("%d", ntohs(ih->tlen));
		printf("bytes out of limit.");
	}

	//struct tm *ltime;
	//char timestr[16];
	//ip_header *ih;
	//mac_header* mh;

	//udp_header *uh;
	//u_int ip_len;
	//u_short sport,dport;
	//time_t local_tv_sec;

	///*
	// * unused parameter
	// */
	//(VOID)(param);

	///* convert the timestamp to readable format */
	//local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

	///* print timestamp and length of the packet */
	//printf("%s.%.6d len:%d ", timestr, header->ts.tv_usec, header->len);

	///* retireve the position of the ip header */
	//ih = (ip_header *) (pkt_data +
	//	14); //length of ethernet header

	///* retireve the position of the udp header */
	//ip_len = (ih->ver_ihl & 0xf) * 4;
	////uh = (udp_header *) ((u_char*)ih + ip_len);

	///* convert from network byte order to host byte order */
	////sport = ntohs( uh->sport );
	////dport = ntohs( uh->dport );

	///* print ip addresses and udp ports */
	//printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
	//	ih->saddr.byte1,
	//	ih->saddr.byte2,
	//	ih->saddr.byte3,
	//	ih->saddr.byte4,
	//	sport,
	//	ih->daddr.byte1,
	//	ih->daddr.byte2,
	//	ih->daddr.byte3,
	//	ih->daddr.byte4,
	//	dport);
	
}
