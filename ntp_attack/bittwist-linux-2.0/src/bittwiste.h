/*
 * bittwiste - pcap capture file editor
 * Copyright (C) 2006 - 2012 Addy Yeow Chin Heng <ayeowch@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef _BITTWISTE_H_
#define _BITTWISTE_H_

#include "def.h"

void parse_header_options(int argc, char **argv);
void parse_trace(char *infile, char *outfile);
u_short parse_ethernet(const u_char *pkt_data,
                       u_char *new_pkt_data,
                       struct pcap_sf_pkthdr *header);
u_short parse_arp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header);
u_short parse_ip(const u_char *pkt_data,
                 u_char *new_pkt_data,
                 struct pcap_sf_pkthdr *header,
                 struct ip *ip_hdr,
                 int flag);
u_short parse_icmp(const u_char *pkt_data,
                   u_char *new_pkt_data,
                   struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr);
u_short parse_tcp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr);
u_short parse_udp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr);
u_short cksum(u_char *cp, u_short len);
void info(void);
void notice(const char *, ...);
void error(const char *, ...);
struct ether_addr *ether_aton(const char *a);
int inet_aton(const char *cp, struct in_addr *addr);
void usage(void);

#endif  /* !_BITTWISTE_H_ */
