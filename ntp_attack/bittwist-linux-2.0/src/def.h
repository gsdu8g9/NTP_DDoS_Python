/*
 * def.h
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

#ifndef _DEF_H_
#define _DEF_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <poll.h>
#include <ifaddrs.h>
#define _NET_IF_ARP_H_ /* OpenBSD's if.h takes in if_arp.h */
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef __BSD_VISIBLE /* Linux does not have net/if_dl.h */
#include <net/if_dl.h>
#endif
#include <pcap.h>

struct pcap_timeval {
    bpf_int32 tv_sec;       /* seconds */
    bpf_int32 tv_usec;      /* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
};

#define BITTWIST_VERSION    "2.0"
#define BITTWISTE_VERSION   BITTWIST_VERSION

#define ETHER_ADDR_LEN      6           /* Ethernet address length */
#define ETHER_HDR_LEN       14          /* Ethernet header length */
#define ETHER_MAX_LEN       1514        /* maximum frame length, excluding CRC */
#define ARP_HDR_LEN         28          /* Ethernet ARP header length */
#define IP_ADDR_LEN         4           /* IP address length */
#define IP_HDR_LEN          20          /* default IP header length */
#define ICMP_HDR_LEN        4           /* ICMP header length */
#define TCP_HDR_LEN         20          /* default TCP header length */
#define UDP_HDR_LEN         8           /* UDP header length */

#define ETHERTYPE_IP        0x0800      /* IP protocol */
#define ETHERTYPE_ARP       0x0806      /* address resolution protocol */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP        1           /* internet control message protocol */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP         6           /* transmission control protocol */
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP         17          /* user datagram protocol */
#endif

/* bittwist */
#define LINERATE_MIN        1           /* Mbps */
#define LINERATE_MAX        10000       /* Mbps */
#define SPEED_MIN           0.000001    /* minimum positive value for speed (interval multiplier) */
#define SLEEP_MAX           2146        /* maximum interval in seconds */
#define PKT_PAD             0x00        /* packet padding */

/* bittwiste */
#define PAYLOAD_MAX         1500        /* maximum payload in bytes */
#define ETH                 1           /* supported header specification (dummy values) */
#define ARP                 2
#define IP                  3
#define ICMP                4
#define TCP                 5
#define UDP                 6
#define IP_FO_MAX           7770        /* maximum IP fragment offset (number of 64-bit segments) */

#define PCAP_HDR_LEN        16          /* pcap generic header length */
#define PCAP_MAGIC          0xa1b2c3d4  /* pcap magic number */

#ifndef TIMEVAL_TO_TIMESPEC
#define TIMEVAL_TO_TIMESPEC(tv, ts) {       \
    (ts)->tv_sec = (tv)->tv_sec;            \
    (ts)->tv_nsec = (tv)->tv_usec * 1000;   \
}
#endif

#define ROUND(f) (f >= 0 ? (long)(f + 0.5) : (long)(f - 0.5))

/* 10Mbps Ethernet header */
struct ether_header {
    u_char  ether_dhost[ETHER_ADDR_LEN];
    u_char  ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

/* 48-bit Ethernet address */
struct ether_addr {
    u_char  octet[ETHER_ADDR_LEN];
};

/* Ethernet ARP header */
struct arphdr {
    u_short ar_hrd;                 /* format of hardware address */
#define ARPHRD_ETHER        1       /* ethernet hardware format */
#define ARPHRD_IEEE802      6       /* token-ring hardware format */
#define ARPHRD_ARCNET       7       /* arcnet hardware format */
#define ARPHRD_FRELAY       15      /* frame relay hardware format */
#define ARPHRD_IEEE1394     24      /* firewire hardware format */
    u_short ar_pro;                 /* format of protocol address */
    u_char  ar_hln;                 /* length of hardware address */
    u_char  ar_pln;                 /* length of protocol address */
    u_short ar_op;                  /* one of: */
#define ARPOP_REQUEST       1       /* request to resolve address */
#define ARPOP_REPLY         2       /* response to previous request */
#define ARPOP_REVREQUEST    3       /* request protocol address given hardware */
#define ARPOP_REVREPLY      4       /* response giving protocol address */
#define ARPOP_INVREQUEST    8       /* request to identify peer */
#define ARPOP_INVREPLY      9       /* response identifying peer */
    u_char  ar_sha[ETHER_ADDR_LEN]; /* sender hardware address */
    u_char  ar_spa[IP_ADDR_LEN];    /* sender protocol address */
    u_char  ar_tha[ETHER_ADDR_LEN]; /* target hardware address */
    u_char  ar_tpa[IP_ADDR_LEN];    /* target protocol address */
};

/* IP header */
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int   ip_hl:4,                /* header length */
            ip_v:4;                 /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int   ip_v:4,                 /* version */
            ip_hl:4;                /* header length */
#endif
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                /* reserved fragment flag */
#define IP_DF 0x4000                /* dont fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and destination address */
} __packed;

/*
 * IPv4 pseudo header, used for computing the TCP and UDP checksums.
 */
struct ippseudo {
    struct  in_addr ippseudo_src;   /* source internet address */
    struct  in_addr ippseudo_dst;   /* destination internet address */
    u_char  ippseudo_pad;           /* pad, must be zero */
    u_char  ippseudo_p;             /* protocol */
    u_short ippseudo_len;           /* protocol length */
};

/* ICMP header */
struct icmphdr {
    u_char  icmp_type;  /* type of message */
    u_char  icmp_code;  /* type sub code */
    u_short icmp_cksum; /* ones complement cksum of struct */
};

typedef u_int32_t tcp_seq;

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int   th_x2:4,    /* (unused) */
            th_off:4;   /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int   th_off:4,   /* data offset */
            th_x2:4;    /* (unused) */
#endif
    u_char  th_flags;
#define TH_FIN      0x01
#define TH_SYN      0x02
#define TH_RST      0x04
#define TH_PUSH     0x08
#define TH_ACK      0x10
#define TH_URG      0x20
#define TH_ECE      0x40
#define TH_CWR      0x80
#define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};

/*
 * UDP header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
    u_short uh_sport;   /* source port */
    u_short uh_dport;   /* destination port */
    u_short uh_ulen;    /* udp length */
    u_short uh_sum;     /* udp checksum */
};

/*
 * Structures for bittwiste header specific options.
 */
struct ethopt {
    u_char  ether_old_dhost[ETHER_ADDR_LEN];
    u_char  ether_new_dhost[ETHER_ADDR_LEN];
    u_char  ether_dhost_flag;
    u_char  ether_old_shost[ETHER_ADDR_LEN];
    u_char  ether_new_shost[ETHER_ADDR_LEN];
    u_char  ether_shost_flag;
    u_short ether_type;
};

struct arpopt {
    u_short ar_op;                          /* opcode */
    u_char  ar_op_flag;
    u_char  ar_old_sha[ETHER_ADDR_LEN];     /* sender hardware address */
    u_char  ar_new_sha[ETHER_ADDR_LEN];
    u_char  ar_sha_flag;
    u_char  ar_old_spa[IP_ADDR_LEN];        /* sender protocol address */
    u_char  ar_new_spa[IP_ADDR_LEN];
    u_char  ar_spa_flag;
    u_char  ar_old_tha[ETHER_ADDR_LEN];     /* target hardware address */
    u_char  ar_new_tha[ETHER_ADDR_LEN];
    u_char  ar_tha_flag;
    u_char  ar_old_tpa[IP_ADDR_LEN];        /* target protocol address */
    u_char  ar_new_tpa[IP_ADDR_LEN];
    u_char  ar_tpa_flag;

};

struct ipopt {
    u_short ip_id;                  /* identification */
    u_char  ip_id_flag;
    u_char  ip_flag_r;              /* reserved bit */
    u_char  ip_flag_d;              /* don't fragment bit */
    u_char  ip_flag_m;              /* more fragment bit */
    u_char  ip_flags_flag;
    u_short ip_fo;                  /* fragment offset in bytes */
    u_char  ip_fo_flag;
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_ttl_flag;
    u_char  ip_p;                   /* protocol */
    u_char  ip_p_flag;
    struct  in_addr ip_old_src;     /* source address */
    struct  in_addr ip_new_src;
    u_char  ip_src_flag;
    struct  in_addr ip_old_dst;     /* destination address */
    struct  in_addr ip_new_dst;
    u_char  ip_dst_flag;
};

struct icmpopt {
    u_char  icmp_type;              /* type of message */
    u_char  icmp_type_flag;
    u_char  icmp_code;              /* type sub code */
    u_char  icmp_code_flag;
};

struct tcpopt {
    u_short th_old_sport;           /* source port */
    u_short th_new_sport;
    u_char  th_sport_flag;
    u_short th_old_dport;           /* destination port */
    u_short th_new_dport;
    u_char  th_dport_flag;
    tcp_seq th_seq;                 /* sequence number */
    u_char  th_seq_flag;
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_ack_flag;
    u_char  th_flag_u;              /* URG */
    u_char  th_flag_a;              /* ACK */
    u_char  th_flag_p;              /* PSH */
    u_char  th_flag_r;              /* RST */
    u_char  th_flag_s;              /* SYN */
    u_char  th_flag_f;              /* FIN */
    u_char  th_flags_flag;
    u_short th_win;                 /* window */
    u_char  th_win_flag;
    u_short th_urp;                 /* urgent pointer */
    u_char  th_urp_flag;
};

struct udpopt {
    u_short uh_old_sport;           /* source port */
    u_short uh_new_sport;
    u_char  uh_sport_flag;
    u_short uh_old_dport;           /* destination port */
    u_short uh_new_dport;
    u_char  uh_dport_flag;
};

#endif  /* !_DEF_H_ */
