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

#include "bittwiste.h"

char *program_name;

/* general options */
int header_opt = 0;             /* specifies which header to edit */
int layer_opt = 0;              /* copy up to the specified layer only */
int start_opt = 0;              /* copy the specified range of packets only */
int end_opt = 0;
int start_oset_opt = 0;         /* delete the specified byte offset */
int end_oset_opt = 0;
time_t start_sec_opt = 0;       /* copy packets within the specified timeframe only */
time_t end_sec_opt = 0;
int csum_opt = 1;               /* set to 0 to disable checksum correction */
u_char *payload_opt = NULL;     /* payload in hex digits *NOTFREED* */
u_short payload_len_opt = 0;    /* length of payload in bytes */
int linktype_opt = -1;          /* pcap preamble link type field, -1 -> no override */

/* header specific options *NOTFREED* */
struct ethopt *ethopt;          /* Ethernet options */
struct arpopt *arpopt;          /* ARP options */
struct ipopt *ipopt;            /* IP options */
struct icmpopt *icmpopt;        /* ICMP options */
struct tcpopt *tcpopt;          /* TCP options */
struct udpopt *udpopt;          /* UDP options */

/* stats */
static u_int pkts = 0;
static u_int bytes = 0;

int main(int argc, char **argv)
{
    char *cp;
    int c, i;
    char *str = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    struct tm *tm = NULL;

    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    /* process general options */
    while ((c = getopt(argc, argv, "I:O:L:X:CM:D:R:S:T:h")) != -1) {
        switch (c) {
            case 'I':
                infile = optarg;
                break;
            case 'O':
                outfile = optarg;
                break;
            case 'L':
                layer_opt = strtol(optarg, NULL, 0);
                /*
                 * 2 - Ethernet
                 * 3 - ARP, IP
                 * 4 - ICMP, TCP, UDP
                 */
                if (layer_opt < 2 || layer_opt > 4)
                    error("layer is out of range");
                break;
            case 'X': /* ignored if option -L and -T are not specified */
                c = strlen(optarg);
                if (c > (PAYLOAD_MAX * 2) || (c % 2) != 0)
                    error("invalid payload specification");
                for (i = 0; i < c; i++) {
                    if (!isxdigit(optarg[i]))
                        error("invalid payload specification");
                }
                payload_len_opt = (u_short)c / 2; /* possible resizing in editing functions */
                payload_opt = (u_char *)malloc(sizeof(u_char) * payload_len_opt);
                if (payload_opt == NULL)
                    error("malloc(): cannot allocate memory for payload_opt");
                /* make a byte of data from every 2 characters of optarg */
                for (i = 0; i < payload_len_opt; i++) {
                    /* ugly - let me know if there is a better way to achieve this */
                    sscanf(optarg, "%02x", &payload_opt[i]);
                    *optarg++; *optarg++; /* move pass 2 characters */
                }
                break;
            case 'C':
                csum_opt = 0; /* DISABLE checksum correction */
                break;
            case 'M':
                linktype_opt = strtol(optarg, NULL, 0);
                /*
                 * 1 - Ethernet
                 * 9 - PPP
                 * 12 - Raw IP
                 * 51 - PPPoE
                 * 105 - IEEE 802.11 wireless
                 * 117 - OpenBSD pflog
                 * 118 - Cisco IOS
                 * 119 - 802.11 with Prism header
                 */
                if (linktype_opt < 0 || linktype_opt > UCHAR_MAX)
                    error("linktype is out of range");
                break;
            case 'D': /* -D 15-18, delete from byte 15th through byte 18th (inclusive), starting from link-layer header */
                str = strdup(optarg);
                if (str == NULL)
                    error("strdup(): cannot allocate memory for str");
                if ((cp = (char *)strtok(str, "-")) == NULL)
                    error("invalid offset specification");
                start_oset_opt = strtol(cp, NULL, 0);
                if ((cp = (char *)strtok(NULL, "-")) == NULL)
                    end_oset_opt = start_oset_opt; /* delete a single byte, e.g. -D 15 */
                else
                    end_oset_opt = strtol(cp, NULL, 0);
                free(str); str = NULL;
                if (start_oset_opt == 0 || end_oset_opt == 0 || (start_oset_opt > end_oset_opt))
                    error("invalid offset specification");
                break;
            case 'R': /* range: 5-21 */
                str = strdup(optarg);
                if (str == NULL)
                    error("strdup(): cannot allocate memory for str");
                if ((cp = (char *)strtok(str, "-")) == NULL)
                    error("invalid range specification");
                start_opt = strtol(cp, NULL, 0);
                if ((cp = (char *)strtok(NULL, "-")) == NULL)
                    end_opt = start_opt; /* only one packet */
                else
                    end_opt = strtol(cp, NULL, 0);
                free(str); str = NULL;
                if (start_opt == 0 || end_opt == 0 || (start_opt > end_opt))
                    error("invalid range specification");
                break;
            case 'S':
                /*
                 * time frame with one-second resolution: -S 22/10/2006,21:47:35-24/10/2006,13:16:05
                 * format: -S DD/MM/YYYY,HH:MM:SS-DD/MM/YYYY,HH:MM:SS
                 * note that -S 22/10/2006-24/10/2006 is equivalent to -S 22/10/2006,00:00:00-24/10/2006,00:00:00
                 */
                str = strdup(optarg);
                if (str == NULL)
                    error("strdup(): cannot allocate memory for str");
                if ((cp = (char *)strtok(str, "-")) == NULL)
                    error("invalid timeframe specification");
                tm = (struct tm *)malloc(sizeof(struct tm));
                if (tm == NULL)
                    error("malloc(): cannot allocate memory for tm");
                if (!strptime(cp, "%d/%m/%Y,%T", tm))
                    error("invalid timeframe specification");
                start_sec_opt = mktime(tm);
                if ((cp = (char *)strtok(NULL, "-")) == NULL)
                    end_sec_opt = start_sec_opt; /* only the packets within the one-second resolution */
                else {
                    if (!strptime(cp, "%d/%m/%Y,%T", tm))
                        error("invalid timeframe specification");
                }
                end_sec_opt = mktime(tm);
                free(tm); tm = NULL; free(str); str = NULL;
                if (start_sec_opt > end_sec_opt)
                    error("invalid timeframe specification");
                break;
            case 'T':
            if (strcasecmp(optarg, "eth") == 0)
                header_opt = ETH;
            else if (strcasecmp(optarg, "arp") == 0)
                header_opt = ARP;
            else if (strcasecmp(optarg, "ip") == 0)
                header_opt = IP;
            else if (strcasecmp(optarg, "icmp") == 0)
                header_opt = ICMP;
            else if (strcasecmp(optarg, "tcp") == 0)
                header_opt = TCP;
            else if (strcasecmp(optarg, "udp") == 0)
                header_opt = UDP;
            else
                error("invalid header specification");
            /* process header specific options */
            parse_header_options(argc, argv);
                break;
            case 'h':
            default:
                usage();
        }
    }

    if (infile == NULL)
        error("input file not specified");

    if (outfile == NULL)
        error("output file not specified");

    if (strcmp(infile, outfile) == 0)
        error("invalid outfile specification");

    parse_trace(infile, outfile);

    info();
    exit(EXIT_SUCCESS);
}

void parse_header_options(int argc, char **argv)
{
    char *cp;
    int c;
    double d; /* validate and store TCP sequence and acknowledgment number */
    struct ether_addr *ether_addr;
    struct in_addr in_addr;
    char *str = NULL;

    if (header_opt == ETH) {
        ethopt = (struct ethopt *)malloc(sizeof(struct ethopt));
        if (ethopt == NULL)
            error("malloc(): cannot allocate memory for ethopt");
        memset(ethopt, 0, sizeof(struct ethopt));
        while ((c = getopt(argc, argv, "d:s:t:")) != -1) {
            switch (c) {
                case 'd': /* destination MAC */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid destination MAC address");
                    if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                        error("invalid destination MAC address");
                    memcpy(ethopt->ether_old_dhost, ether_addr, sizeof(struct ether_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all destination MAC */
                        ethopt->ether_dhost_flag = 1;
                    else { /* overwrite matching destination MAC only */
                        ethopt->ether_dhost_flag = 2;
                        if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                            error("invalid destination MAC address");
                        memcpy(ethopt->ether_new_dhost, ether_addr, sizeof(struct ether_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 's': /* source MAC */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid source MAC address");
                    if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                        error("invalid source MAC address");
                    memcpy(ethopt->ether_old_shost, ether_addr, sizeof(struct ether_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all source MAC */
                        ethopt->ether_shost_flag = 1;
                    else { /* overwrite matching source MAC only */
                        ethopt->ether_shost_flag = 2;
                        if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                            error("invalid source MAC address");
                        memcpy(ethopt->ether_new_shost, ether_addr, sizeof(struct ether_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 't': /* type */
                    if (strcasecmp(optarg, "ip") == 0)
                        ethopt->ether_type = ETHERTYPE_IP;
                    else if (strcasecmp(optarg, "arp") == 0)
                        ethopt->ether_type = ETHERTYPE_ARP;
                    else
                        error("invalid Ethernet type specification");
                    break;
                default:
                    usage();
            }
        }
    }
    else if (header_opt == ARP) {
        arpopt = (struct arpopt *)malloc(sizeof(struct arpopt));
        if (arpopt == NULL)
            error("malloc(): cannot allocate memory for arpopt");
        memset(arpopt, 0, sizeof(struct arpopt));
        while ((c = getopt(argc, argv, "o:s:p:t:q:")) != -1) {
            switch (c) {
                case 'o': /* opcode */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("ARP opcode is out of range");
                    arpopt->ar_op = (u_short)c;
                    arpopt->ar_op_flag = 1;
                    break;
                case 's': /* sender MAC */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid sender MAC address");
                    if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                        error("invalid sender MAC address");
                    memcpy(arpopt->ar_old_sha, ether_addr, sizeof(struct ether_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all sender MAC */
                        arpopt->ar_sha_flag = 1;
                    else { /* overwrite matching sender MAC only */
                        arpopt->ar_sha_flag = 2;
                        if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                            error("invalid sender MAC address");
                        memcpy(arpopt->ar_new_sha, ether_addr, sizeof(struct ether_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 'p': /* sender IP */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid sender IP address");
                    if (inet_aton(cp, &in_addr) == 0)
                        error("invalid sender IP address");
                    memcpy(&arpopt->ar_old_spa, &in_addr, sizeof(struct in_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all sender IP address */
                        arpopt->ar_spa_flag = 1;
                    else { /* overwrite matching IP address only */
                        arpopt->ar_spa_flag = 2;
                        if (inet_aton(cp, &in_addr) == 0)
                            error("invalid sender IP address");
                        memcpy(&arpopt->ar_new_spa, &in_addr, sizeof(struct in_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 't': /* target MAC */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid target MAC address");
                    if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                        error("invalid target MAC address");
                    memcpy(arpopt->ar_old_tha, ether_addr, sizeof(struct ether_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all target MAC */
                        arpopt->ar_tha_flag = 1;
                    else { /* overwrite matching target MAC only */
                        arpopt->ar_tha_flag = 2;
                        if ((ether_addr = (struct ether_addr *)ether_aton(cp)) == NULL)
                            error("invalid target MAC address");
                        memcpy(arpopt->ar_new_tha, ether_addr, sizeof(struct ether_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 'q': /* target IP */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid target IP address");
                    if (inet_aton(cp, &in_addr) == 0)
                        error("invalid target IP address");
                    memcpy(&arpopt->ar_old_tpa, &in_addr, sizeof(struct in_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all target IP address */
                        arpopt->ar_tpa_flag = 1;
                    else { /* overwrite matching IP address only */
                        arpopt->ar_tpa_flag = 2;
                        if (inet_aton(cp, &in_addr) == 0)
                            error("invalid target IP address");
                        memcpy(&arpopt->ar_new_tpa, &in_addr, sizeof(struct in_addr));
                    }
                    free(str); str = NULL;
                    break;
                default:
                    usage();
            }
        }
    }
    else if (header_opt == IP) {
        ipopt = (struct ipopt *)malloc(sizeof(struct ipopt));
        if (ipopt == NULL)
            error("malloc(): cannot allocate memory for ipopt");
        memset(ipopt, 0, sizeof(struct ipopt));
        while ((c = getopt(argc, argv, "i:f:o:t:p:s:d:")) != -1) {
            switch (c) {
                case 'i': /* identification */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("IP identification is out of range");
                    ipopt->ip_id = (u_short)c;
                    ipopt->ip_id_flag = 1;
                    break;
                case 'f': /* flags */
                    for (c = 0; optarg[c]; c++)
                        optarg[c] = tolower(optarg[c]);
                    if (strchr(optarg, 'r') != NULL) /* reserved bit */
                        ipopt->ip_flag_r = 1;
                    if (strchr(optarg, 'd') != NULL) /* don't fragment bit */
                        ipopt->ip_flag_d = 1;
                    if (strchr(optarg, 'm') != NULL) /* more fragment bit */
                        ipopt->ip_flag_m = 1;
                    if (strchr(optarg, '-') != NULL) { /* remove flags */
                        ipopt->ip_flag_r = 0;
                        ipopt->ip_flag_d = 0;
                        ipopt->ip_flag_m = 0;
                    }
                    ipopt->ip_flags_flag = 1;
                    break;
                case 'o': /* fragment offset */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > IP_FO_MAX)
                        error("IP fragment offset is out of range");
                    ipopt->ip_fo = (u_short)c;
                    ipopt->ip_fo_flag = 1;
                    break;
                case 't': /* time to live */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > UCHAR_MAX)
                        error("IP time to live is out of range");
                    ipopt->ip_ttl = (u_char)c;
                    ipopt->ip_ttl_flag = 1;
                    break;
                case 'p': /* protocol */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > UCHAR_MAX)
                        error("IP protocol is out of range");
                    ipopt->ip_p = (u_char)c;
                    ipopt->ip_p_flag = 1;
                    break;
                case 's': /* source IP */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid source IP address");
                    if (inet_aton(cp, &in_addr) == 0)
                        error("invalid source IP address");
                    memcpy(&ipopt->ip_old_src, &in_addr, sizeof(struct in_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all source IP address */
                        ipopt->ip_src_flag = 1;
                    else { /* overwrite matching IP address only */
                        ipopt->ip_src_flag = 2;
                        if (inet_aton(cp, &in_addr) == 0)
                            error("invalid source IP address");
                        memcpy(&ipopt->ip_new_src, &in_addr, sizeof(struct in_addr));
                    }
                    free(str); str = NULL;
                    break;
                case 'd': /* destination IP */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid destination IP address");
                    if (inet_aton(cp, &in_addr) == 0)
                        error("invalid destination IP address");
                    memcpy(&ipopt->ip_old_dst, &in_addr, sizeof(struct in_addr));
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all destination IP address */
                        ipopt->ip_dst_flag = 1;
                    else { /* overwrite matching IP address only */
                        ipopt->ip_dst_flag = 2;
                        if (inet_aton(cp, &in_addr) == 0)
                            error("invalid destination IP address");
                        memcpy(&ipopt->ip_new_dst, &in_addr, sizeof(struct in_addr));
                    }
                    free(str); str = NULL;
                    break;
                default:
                    usage();
            }
        }
    }
    else if (header_opt == ICMP) {
        icmpopt = (struct icmpopt *)malloc(sizeof(struct icmpopt));
        if (icmpopt == NULL)
            error("malloc(): cannot allocate memory for icmpopt");
        memset(icmpopt, 0, sizeof(struct icmpopt));
        while ((c = getopt(argc, argv, "t:c:")) != -1) {
            switch (c) {
                case 't': /* type */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > UCHAR_MAX)
                        error("ICMP type is out of range");
                    icmpopt->icmp_type = (u_char)c;
                    icmpopt->icmp_type_flag = 1;
                    break;
                case 'c': /* code */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > UCHAR_MAX)
                        error("ICMP code is out of range");
                    icmpopt->icmp_code = (u_char)c;
                    icmpopt->icmp_code_flag = 1;
                    break;
                default:
                    usage();
            }
        }
    }
    else if (header_opt == TCP) {
        tcpopt = (struct tcpopt *)malloc(sizeof(struct tcpopt));
        if (tcpopt == NULL)
            error("malloc(): cannot allocate memory for tcpopt");
        memset(tcpopt, 0, sizeof(struct tcpopt));
        while ((c = getopt(argc, argv, "s:d:q:a:f:w:u:")) != -1) {
            switch (c) {
                case 's': /* source port */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid TCP source port specification");
                    c = strtol(cp, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("TCP source port is out of range");
                    tcpopt->th_old_sport = (u_short)c;
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all source port */
                        tcpopt->th_sport_flag = 1;
                    else { /* overwrite matching port only */
                        c = strtol(cp, NULL, 0);
                        if (c < 0 || c > USHRT_MAX)
                            error("TCP source port is out of range");
                        tcpopt->th_new_sport = (u_short)c;
                        tcpopt->th_sport_flag = 2;
                    }
                    free(str); str = NULL;
                    break;
                case 'd': /* destination port */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid TCP destination port specification");
                    c = strtol(cp, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("TCP destination port is out of range");
                    tcpopt->th_old_dport = (u_short)c;
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all destination port */
                        tcpopt->th_dport_flag = 1;
                    else { /* overwrite matching port only */
                        c = strtol(cp, NULL, 0);
                        if (c < 0 || c > USHRT_MAX)
                            error("TCP destination port is out of range");
                        tcpopt->th_new_dport = (u_short)c;
                        tcpopt->th_dport_flag = 2;
                    }
                    free(str); str = NULL;
                    break;
                case 'q': /* sequence number */
                    d = strtod(optarg, NULL);
                    if (d < 0 || d > UINT_MAX)
                        error("TCP sequence number is out of range");
                    tcpopt->th_seq = (tcp_seq)d;
                    tcpopt->th_seq_flag = 1;
                    break;
                case 'a': /* acknowledgment number */
                    d = strtod(optarg, NULL);
                    if (d < 0 || d > UINT_MAX)
                        error("TCP acknowledgment number is out of range");
                    tcpopt->th_ack = (tcp_seq)d;
                    tcpopt->th_ack_flag = 1;
                    break;
                case 'f': /* flags */
                    for (c = 0; optarg[c]; c++)
                        optarg[c] = tolower(optarg[c]);
                    if (strchr(optarg, 'u') != NULL) /* URG */
                        tcpopt->th_flag_u = 1;
                    if (strchr(optarg, 'a') != NULL) /* ACK */
                        tcpopt->th_flag_a = 1;
                    if (strchr(optarg, 'p') != NULL) /* PSH */
                        tcpopt->th_flag_p = 1;
                    if (strchr(optarg, 'r') != NULL) /* RST */
                        tcpopt->th_flag_r = 1;
                    if (strchr(optarg, 's') != NULL) /* SYN */
                        tcpopt->th_flag_s = 1;
                    if (strchr(optarg, 'f') != NULL) /* FIN */
                        tcpopt->th_flag_f = 1;
                    if (strchr(optarg, '-') != NULL) { /* remove flags */
                        tcpopt->th_flag_u = 0;
                        tcpopt->th_flag_a = 0;
                        tcpopt->th_flag_p = 0;
                        tcpopt->th_flag_r = 0;
                        tcpopt->th_flag_s = 0;
                        tcpopt->th_flag_f = 0;
                    }
                    tcpopt->th_flags_flag = 1;
                    break;
                case 'w': /* window size */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("TCP window size is out of range");
                    tcpopt->th_win = (u_short)c;
                    tcpopt->th_win_flag = 1;
                    break;
                case 'u': /* urgent pointer */
                    c = strtol(optarg, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("TCP urgent pointer is out of range");
                    tcpopt->th_urp = (u_short)c;
                    tcpopt->th_urp_flag = 1;
                    break;
                default:
                    usage();
            }
        }
    }
    else if (header_opt == UDP) {
        udpopt = (struct udpopt *)malloc(sizeof(struct udpopt));
        if (udpopt == NULL)
            error("malloc(): cannot allocate memory for udpopt");
        memset(udpopt, 0, sizeof(struct udpopt));
        while ((c = getopt(argc, argv, "s:d:")) != -1) {
            switch (c) {
                case 's': /* source port */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid UDP source port specification");
                    c = strtol(cp, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("UDP source port is out of range");
                    udpopt->uh_old_sport = (u_short)c;
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all source port */
                        udpopt->uh_sport_flag = 1;
                    else { /* overwrite matching port only */
                        c = strtol(cp, NULL, 0);
                        if (c < 0 || c > USHRT_MAX)
                            error("UDP source port is out of range");
                        udpopt->uh_new_sport = (u_short)c;
                        udpopt->uh_sport_flag = 2;
                    }
                    free(str); str = NULL;
                    break;
                case 'd': /* destination port */
                    str = strdup(optarg);
                    if (str == NULL)
                        error("strdup(): cannot allocate memory for str");
                    if ((cp = (char *)strtok(str, ",")) == NULL)
                        error("invalid UDP destination port specification");
                    c = strtol(cp, NULL, 0);
                    if (c < 0 || c > USHRT_MAX)
                        error("UDP destination port is out of range");
                    udpopt->uh_old_dport = (u_short)c;
                    if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all destination port */
                        udpopt->uh_dport_flag = 1;
                    else { /* overwrite matching port only */
                        c = strtol(cp, NULL, 0);
                        if (c < 0 || c > USHRT_MAX)
                            error("UDP destination port is out of range");
                        udpopt->uh_new_dport = (u_short)c;
                        udpopt->uh_dport_flag = 2;
                    }
                    free(str); str = NULL;
                    break;
                default:
                    usage();
            }
        }
    }
    /* NOTREACHED */
}

void parse_trace(char *infile, char *outfile)
{
    FILE *fp; /* file pointer to trace file */
    FILE *fp_outfile; /* file pointer to modified trace file */
    struct pcap_file_header preamble;
    struct pcap_sf_pkthdr *header;
    u_char *pkt_data; /* original packet data starting from link-layer header */
    u_char *new_pkt_data; /* modified pkt_data inclusive of pcap generic header is written here */
    int ret;
    int i;
    int pkt_index; /* to check if we are within start_opt and end_opt for range specification */
    int len; /* original header->caplen */
    int end_o; /* aligned end_oset_opt */

    notice("input file: %s", infile);
    if ((fp = fopen(infile, "rb")) == NULL)
        error("fopen(): error reading %s", infile);

    notice("output file: %s", outfile);
    if ((fp_outfile = fopen(outfile, "wb")) == NULL)
        error("fopen(): error creating %s", outfile);

    /* preamble occupies the first 24 bytes of a trace file */
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        error("fread(): error reading %s", infile);
    if (preamble.magic != PCAP_MAGIC)
        error("%s is not a valid pcap based trace file", infile);

    /* override pcap preamble link type with user specified link type */
    if (linktype_opt >= 0)
        preamble.linktype = linktype_opt;

    /* write preamble to modified trace file */
    if (fwrite(&preamble, sizeof(preamble), 1, fp_outfile) != 1)
        error("fwrite(): error writing %s", outfile);

    /* pcap generic header */
    header = (struct pcap_sf_pkthdr *)malloc(PCAP_HDR_LEN);
    if (header == NULL)
        error("malloc(): cannot allocate memory for header");

    /*
     * loop through the remaining data by reading the pcap generic header first.
     * pcap generic header (16 bytes) = secs. + usecs. + caplen + len
     */
    pkt_index = 1;
    while ((ret = fread(header, PCAP_HDR_LEN, 1, fp))) {
        if (ret == 0)
            error("fread(): error reading %s", infile);

        /* original packet data starting from link-layer header */
        pkt_data = (u_char *)malloc(sizeof(u_char) * header->caplen);
        if (pkt_data == NULL)
            error("malloc(): cannot allocate memory for pkt_data");
        memset(pkt_data, 0, header->caplen);

        /* copy captured packet data starting from link-layer header into pkt_data */
        if (fread(pkt_data, header->caplen, 1, fp) == 0)
            error("fread(): error reading %s", infile);

        if ((pkt_index >= start_opt && pkt_index <= end_opt) ||
                (start_opt == 0 && end_opt == 0)) {
            if ((header->ts.tv_sec >= start_sec_opt && header->ts.tv_sec <= end_sec_opt) ||
                    (start_sec_opt == 0 && end_sec_opt == 0)) {
                /* byte deletion mode, no content modification (parse_ethernet(), etc.) */
                if (start_oset_opt != 0 && end_oset_opt != 0 &&
                        start_oset_opt <= header->caplen) {
                    /* align end_oset_opt so that it does not go beyond header->caplen */
                    if (end_oset_opt > header->caplen)
                        end_o = header->caplen;
                    else
                        end_o = end_oset_opt;

                    len = header->caplen; /* original capture length (before byte deletion) */
                    header->caplen = header->len = len - ((end_o - start_oset_opt) + 1);

                    /* write pcap generic header */
                    if (fwrite(header, PCAP_HDR_LEN, 1, fp_outfile) != 1)
                        error("fwrite(): error writing %s", outfile);

                    for (i = 0; i < start_oset_opt - 1; i++) {
                        if (fputc(pkt_data[i], fp_outfile) == EOF)
                            error("fputc(): error writing %s", outfile);
                    }

                    for (i = end_o; i < len; i++) {
                        if (fputc(pkt_data[i], fp_outfile) == EOF)
                            error("fputc(): error writing %s", outfile);
                    }
                }
                else {
                    /* modified pkt_data inclusive of pcap generic header */
                    new_pkt_data = (u_char *)malloc(sizeof(u_char) * (PCAP_HDR_LEN + ETHER_MAX_LEN)); /* 16 + 1514 bytes */
                    if (new_pkt_data == NULL)
                        error("malloc(): cannot allocate memory for new_pkt_data");
                    memset(new_pkt_data, 0, PCAP_HDR_LEN + ETHER_MAX_LEN);

                    /*
                     * encapsulated editing function starting from link-layer header.
                     * ret = bytes written in new_pkt_data
                     */
                    ret = parse_ethernet(pkt_data, new_pkt_data, header) + PCAP_HDR_LEN;

                    /* copy pcap generic header into new_pkt_data */
                    memcpy(new_pkt_data, header, PCAP_HDR_LEN);

                    /* no changes */
                    if (ret == PCAP_HDR_LEN) {  /* parse_ethernet() returns 0 */
                        /* write pcap generic header */
                        if (fwrite(header, PCAP_HDR_LEN, 1, fp_outfile) != 1)
                            error("fwrite(): error writing %s", outfile);

                        if (fwrite(pkt_data, header->caplen, 1, fp_outfile) != 1)
                            error("fwrite(): error writing %s", outfile);
                    }
                    /* overwrite the entire pkt_data with new_pkt_data */
                    else if (ret == header->caplen + PCAP_HDR_LEN) {
                        if (fwrite(new_pkt_data, ret, 1, fp_outfile) != 1)
                            error("fwrite(): error writing %s", outfile);
                    }
                    else {
                        if (fwrite(new_pkt_data, ret, 1, fp_outfile) != 1)
                            error("fwrite(): error writing %s", outfile);

                        /* write remaining bytes from pkt_data */
                        for (i = ret - PCAP_HDR_LEN; i < header->caplen; i++) {
                            if (fputc(pkt_data[i], fp_outfile) == EOF)
                                error("fputc(): error writing %s", outfile);
                        }
                    }

                    free(new_pkt_data); new_pkt_data = NULL;
                }
                ++pkts; /* packets written */
                bytes += header->caplen; /* bytes written */
            }
        }

        free(pkt_data); pkt_data = NULL;
        ++pkt_index;
    } /* end while */

    free(header); header = NULL;
    (void)fclose(fp);
    (void)fclose(fp_outfile);
}

u_short parse_ethernet(const u_char *pkt_data,
                       u_char *new_pkt_data,
                       struct pcap_sf_pkthdr *header)
{
    /*
     * Ethernet header (14 bytes)
     * 1. destination MAC (6 bytes)
     * 2. source MAC (6 bytes)
     * 3. type (2 bytes)
     */
    struct ether_header *eth_hdr;
    u_short ether_type;
    int i;

    /* do nothing if Ethernet header is truncated */
    if (header->caplen < ETHER_HDR_LEN)
        return (0);

    eth_hdr = (struct ether_header *)malloc(ETHER_HDR_LEN);
    if (eth_hdr == NULL)
        error("malloc(): cannot allocate memory for eth_hdr");

    /* copy Ethernet header from pkt_data into eth_hdr */
    memcpy(eth_hdr, pkt_data, ETHER_HDR_LEN);

    /* we are editing Ethernet header */
    if (header_opt == ETH) {
        /* overwrite destination MAC */
        if (ethopt->ether_dhost_flag == 1) /* overwrite all destination MAC */
            memcpy(eth_hdr->ether_dhost, ethopt->ether_old_dhost, ETHER_ADDR_LEN);
        else if (ethopt->ether_dhost_flag == 2 && /* overwrite matching destination MAC only */
                memcmp(eth_hdr->ether_dhost, ethopt->ether_old_dhost, ETHER_ADDR_LEN) == 0)
            memcpy(eth_hdr->ether_dhost, ethopt->ether_new_dhost, ETHER_ADDR_LEN);

        /* overwrite source MAC */
        if (ethopt->ether_shost_flag == 1) /* overwrite all source MAC */
            memcpy(eth_hdr->ether_shost, ethopt->ether_old_shost, ETHER_ADDR_LEN);
        else if (ethopt->ether_shost_flag == 2 && /* overwrite matching source MAC only */
                memcmp(eth_hdr->ether_shost, ethopt->ether_old_shost, ETHER_ADDR_LEN) == 0)
            memcpy(eth_hdr->ether_shost, ethopt->ether_new_shost, ETHER_ADDR_LEN);

        /* overwrite Ethernet type */
        if (ethopt->ether_type != 0)
            eth_hdr->ether_type = htons(ethopt->ether_type);
    }
    ether_type = ntohs(eth_hdr->ether_type);

    /*
     * go pass pcap generic header in new_pkt_data then copy eth_hdr into
     * new_pkt_data and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN)
        *new_pkt_data++;

    memcpy(new_pkt_data, eth_hdr, ETHER_HDR_LEN);
    free(eth_hdr); eth_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN)
        *new_pkt_data--;

    /* copy up to layer 2 only, discard remaining data */
    if (layer_opt == 2) {
        /* we are editing Ethernet header and we have payload */
        if (header_opt == ETH && payload_len_opt > 0) {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETHER_HDR_LEN) > ETHER_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN) - ETHER_MAX_LEN;
            /*
             * go pass pcap generic header and Ethernet header in new_pkt_data
             * then copy payload_opt into new_pkt_data and reset pointer to the
             * beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
                *new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
                *new_pkt_data--;

            header->caplen = header->len = ETHER_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETHER_HDR_LEN;

        return (header->caplen);
    }

    /* parse ARP datagram */
    if (ether_type == ETHERTYPE_ARP)
        return (parse_arp(pkt_data, new_pkt_data, header));
    /* parse IP datagram */
    else if (ether_type == ETHERTYPE_IP)
        return (parse_ip(pkt_data, new_pkt_data, header, NULL, 0));
    /* no further editing support for other datagram */
    else
        return (ETHER_HDR_LEN);
}

u_short parse_arp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header)
{
    /*
     * Ethernet ARP header (28 bytes)
     *  1. hardware type (2 bytes)
     *  2. protocol type (2 bytes)
     *  3. hardware address length (1 byte)
     *  4. protocol address length (1 byte)
     *  5. opcode (2 bytes)
     *  6. sender hardware address (6 bytes)
     *  7. sender protocol address (4 bytes)
     *  8. target hardware address (6 bytes)
     *  9. target protocol address (4 bytes)
     */
    struct arphdr *arp_hdr;
    int i;

    /* do nothing if ARP header is truncated */
    if (header->caplen < ETHER_HDR_LEN + ARP_HDR_LEN)
        return (ETHER_HDR_LEN);

    /* go pass Ethernet header in pkt_data */
    i = 0;
    while (i++ < ETHER_HDR_LEN)
        *pkt_data++;

    arp_hdr = (struct arphdr *)malloc(ARP_HDR_LEN);
    if (arp_hdr == NULL)
        error("malloc(): cannot allocate memory for arp_hdr");

    /* copy ARP header from pkt_data into arp_hdr */
    memcpy(arp_hdr, pkt_data, ARP_HDR_LEN);

    /* reset pointer to the beginning of pkt_data */
    i = 0;
    while (i++ < ETHER_HDR_LEN)
        *pkt_data--;

    /* do nothing if this is an unsupported ARP header */
    if (arp_hdr->ar_hln != ETHER_ADDR_LEN || arp_hdr->ar_pln != IP_ADDR_LEN) {
        free(arp_hdr); arp_hdr = NULL;
        return (ETHER_HDR_LEN);
    }

    /* we are editing ARP header */
    if (header_opt == ARP) {
        /* overwrite opcode */
        if (arpopt->ar_op_flag)
            arp_hdr->ar_op = htons(arpopt->ar_op);

        /* overwrite sender MAC */
        if (arpopt->ar_sha_flag == 1) /* overwrite all sender MAC */
            memcpy(arp_hdr->ar_sha, arpopt->ar_old_sha, ETHER_ADDR_LEN);
        else if (arpopt->ar_sha_flag == 2 && /* overwrite matching sender MAC only */
                memcmp(arp_hdr->ar_sha, arpopt->ar_old_sha, ETHER_ADDR_LEN) == 0)
            memcpy(arp_hdr->ar_sha, arpopt->ar_new_sha, ETHER_ADDR_LEN);

        /* overwrite sender IP */
        if (arpopt->ar_spa_flag == 1) /* overwrite all sender IP */
            memcpy(arp_hdr->ar_spa, arpopt->ar_old_spa, IP_ADDR_LEN);
        else if (arpopt->ar_spa_flag == 2 && /* overwrite matching IP only */
                memcmp(arp_hdr->ar_spa, arpopt->ar_old_spa, IP_ADDR_LEN) == 0)
            memcpy(arp_hdr->ar_spa, arpopt->ar_new_spa, IP_ADDR_LEN);

        /* overwrite target MAC */
        if (arpopt->ar_tha_flag == 1) /* overwrite all target MAC */
            memcpy(arp_hdr->ar_tha, arpopt->ar_old_tha, ETHER_ADDR_LEN);
        else if (arpopt->ar_tha_flag == 2 && /* overwrite matching target MAC only */
                memcmp(arp_hdr->ar_tha, arpopt->ar_old_tha, ETHER_ADDR_LEN) == 0)
            memcpy(arp_hdr->ar_tha, arpopt->ar_new_tha, ETHER_ADDR_LEN);

        /* overwrite target IP */
        if (arpopt->ar_tpa_flag == 1) /* overwrite all target IP */
            memcpy(arp_hdr->ar_tpa, arpopt->ar_old_tpa, IP_ADDR_LEN);
        else if (arpopt->ar_tpa_flag == 2 && /* overwrite matching IP only */
                memcmp(arp_hdr->ar_tpa, arpopt->ar_old_tpa, IP_ADDR_LEN) == 0)
            memcpy(arp_hdr->ar_tpa, arpopt->ar_new_tpa, IP_ADDR_LEN);
    }

    /*
     * go pass pcap generic header and Ethernet header in new_pkt_data
     * then copy arp_hdr into new_pkt_data and reset pointer to the
     * beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
        *new_pkt_data++;

    memcpy(new_pkt_data, arp_hdr, ARP_HDR_LEN);
    free(arp_hdr); arp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
        *new_pkt_data--;

    /* copy up to layer 3 only, discard remaining data */
    if (layer_opt == 3) {
        /* we are editing ARP header and we have payload */
        if (header_opt == ARP && payload_len_opt > 0) {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETHER_HDR_LEN + ARP_HDR_LEN) > ETHER_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN + ARP_HDR_LEN) - ETHER_MAX_LEN;
            /*
             * go pass pcap generic header, Ethernet header and ARP header in
             * new_pkt_data then copy payload_opt into new_pkt_data and reset
             * pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ARP_HDR_LEN)
                *new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ARP_HDR_LEN)
                *new_pkt_data--;

            header->caplen = header->len = ETHER_HDR_LEN + ARP_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETHER_HDR_LEN + ARP_HDR_LEN;

        return (header->caplen);
    }

    /* no further editing support after ARP header */
    return (ETHER_HDR_LEN + ARP_HDR_LEN);
}

u_short parse_ip(const u_char *pkt_data,
                 u_char *new_pkt_data,
                 struct pcap_sf_pkthdr *header,
                 struct ip *ip_hdr,
                 int flag)
{
    /*
     * IP header (20 bytes + optional X bytes for options)
     *  1. version (4 bits)
     *  2. header length (4 bits)
     *  3. service type (1 byte)
     *  4. total length (2 bytes)
     *  5. id (2 bytes)
     *  6. flag (3 bits)
     *  7. fragment offset (13 bits)
     *  8. ttl (1 byte)
     *  9. protocol (1 byte)
     * 10. header checksum (2 bytes)
     * 11. source IP (4 bytes)
     * 12. destination IP (4 bytes)
     * 13. options (X bytes)
     */
    u_char *ip_hdr_o;       /* IP header with options (for header checksum calculation) */
    u_short ip_hlb;         /* header length in bytes */
    u_short ip_fo;          /* fragment offset (number of 64-bit segments) */
    u_char r = '\0';        /* flags */
    u_char d = '\0';
    u_char m = '\0';
    u_char ip_p = '\0';     /* protocol */
    u_char *ip_o = NULL;    /* options (X bytes) */
    int i, j;

    /*
     * flag is 0; entry from Ethernet header to edit IP header.
     * flag is 1; entry from ICMP, TCP or UDP header to update IP total length
     *            and recalculate checksum for IP header.
     */
    if (flag == 0) {
        /* do nothing if IP header is truncated */
        if (header->caplen < ETHER_HDR_LEN + IP_HDR_LEN)
            return (ETHER_HDR_LEN);

        /* go pass Ethernet header in pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data++;

        ip_hdr = (struct ip *)malloc(IP_HDR_LEN);
        if (ip_hdr == NULL)
            error("malloc(): cannot allocate memory for ip_hdr");

        /* copy IP header from pkt_data into ip_hdr */
        memcpy(ip_hdr, pkt_data, IP_HDR_LEN);
    }

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* have IP options */
    if (ip_hlb > IP_HDR_LEN) {
        /* do nothing if IP header with options is truncated */
        if (header->caplen < ETHER_HDR_LEN + ip_hlb) {
            /* reset pointer to the beginning of pkt_data */
            i = 0;
            while (i++ < ETHER_HDR_LEN)
                *pkt_data--;

            free(ip_hdr); ip_hdr = NULL;
            return (ETHER_HDR_LEN);
        }

        ip_o = (u_char *)malloc(sizeof(u_char) * (ip_hlb - IP_HDR_LEN));
        if (ip_o == NULL)
            error("malloc(): cannot allocate memory for ip_o");

        /* copy IP options into ip_o */
        for (i = 0, j = IP_HDR_LEN; i < (ip_hlb - IP_HDR_LEN); i++, j++)
            ip_o[i] = pkt_data[j];
    }

    if (flag == 0) {
        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data--;

        /* we are editing IP header */
        if (header_opt == IP) {
            /* overwrite identification */
            if (ipopt->ip_id_flag)
                ip_hdr->ip_id = htons(ipopt->ip_id);

            /* original fragment offset */
            ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

            /* original flags */
            r = (ntohs(ip_hdr->ip_off) & IP_RF) > 0 ? 1 : 0;
            d = (ntohs(ip_hdr->ip_off) & IP_DF) > 0 ? 1 : 0;
            m = (ntohs(ip_hdr->ip_off) & IP_MF) > 0 ? 1 : 0;

            /* overwrite fragment offset only */
            if (ipopt->ip_fo_flag & !ipopt->ip_flags_flag) {
                ip_hdr->ip_off = htons((ipopt->ip_fo & IP_OFFMASK) |
                    (r ? IP_RF : 0) |
                    (d ? IP_DF : 0) |
                    (m ? IP_MF : 0));
            }
            /* overwrite flags only */
            else if (!ipopt->ip_fo_flag & ipopt->ip_flags_flag) {
                ip_hdr->ip_off = htons((ip_fo & IP_OFFMASK) |
                    ((ipopt->ip_flag_r) ? IP_RF : 0) |
                    ((ipopt->ip_flag_d) ? IP_DF : 0) |
                    ((ipopt->ip_flag_m) ? IP_MF : 0));
            }
            /* overwrite fragment offset and flags */
            else if (ipopt->ip_fo_flag & ipopt->ip_flags_flag) {
                ip_hdr->ip_off = htons((ipopt->ip_fo & IP_OFFMASK) |
                    ((ipopt->ip_flag_r) ? IP_RF : 0) |
                    ((ipopt->ip_flag_d) ? IP_DF : 0) |
                    ((ipopt->ip_flag_m) ? IP_MF : 0));
            }

            /* overwrite time to live */
            if (ipopt->ip_ttl_flag)
                ip_hdr->ip_ttl = ipopt->ip_ttl;

            /* overwrite protocol */
            if (ipopt->ip_p_flag)
                ip_hdr->ip_p = ipopt->ip_p;

            /* overwrite source IP */
            if (ipopt->ip_src_flag == 1) /* overwrite all source IP */
                memcpy(&ip_hdr->ip_src, &ipopt->ip_old_src, sizeof(struct in_addr));
            else if (ipopt->ip_src_flag == 2 && /* overwrite matching IP only */
                    memcmp(&ip_hdr->ip_src, &ipopt->ip_old_src, sizeof(struct in_addr)) == 0)
                memcpy(&ip_hdr->ip_src, &ipopt->ip_new_src, sizeof(struct in_addr));

            /* overwrite destination IP */
            if (ipopt->ip_dst_flag == 1) /* overwrite all destination IP */
                memcpy(&ip_hdr->ip_dst, &ipopt->ip_old_dst, sizeof(struct in_addr));
            else if (ipopt->ip_dst_flag == 2 && /* overwrite matching IP only */
                    memcmp(&ip_hdr->ip_dst, &ipopt->ip_old_dst, sizeof(struct in_addr)) == 0)
                memcpy(&ip_hdr->ip_dst, &ipopt->ip_new_dst, sizeof(struct in_addr));
        }
        /*
         * if more fragment flag is set, we should not parse the protocol header
         * (ICMP, TCP, or UDP) just yet since this is a fragmented packet
         */
        m = (ntohs(ip_hdr->ip_off) & IP_MF) > 0 ? 1 : 0;
        ip_p = ip_hdr->ip_p;

        /* we are going to copy up to layer 3 only, change total length */
        if (layer_opt == 3) {
            /* we are editing IP header and we have payload, include its length in total length */
            if (header_opt == IP && payload_len_opt > 0) {
                /* truncate payload if it is too large */
                if ((payload_len_opt + ETHER_HDR_LEN + ip_hlb) > ETHER_MAX_LEN)
                    payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN + ip_hlb) - ETHER_MAX_LEN;
                ip_hdr->ip_len = htons(ip_hlb + payload_len_opt);
            }
            else
                ip_hdr->ip_len = htons(ip_hlb);
        }
    }

    /* recalculate checksum (cover IP header only) */
    if (csum_opt) {
        ip_hdr->ip_sum = 0x0000; /* clear checksum field */

        /* have IP options */
        if (ip_hlb > IP_HDR_LEN) {
            ip_hdr_o = (u_char *)malloc(sizeof(u_char) * ip_hlb);
            if (ip_hdr_o == NULL)
                error("malloc(): cannot allocate memory for ip_hdr_o");

            /*
             * copy ip_hdr into ip_hdr_o, go pass IP header in ip_hdr_o then
             * copy ip_o into ip_hdr_o and reset pointer to the beginning of
             * ip_hdr_o and finally calculate checksum of ip_hdr_o
             */
            memcpy(ip_hdr_o, ip_hdr, IP_HDR_LEN);

            i = 0;
            while (i++ < IP_HDR_LEN)
                *ip_hdr_o++;

            memcpy(ip_hdr_o, ip_o, ip_hlb - IP_HDR_LEN);

            i = 0;
            while (i++ < IP_HDR_LEN)
                *ip_hdr_o--;

            ip_hdr->ip_sum = htons(cksum(ip_hdr_o, ip_hlb));
            free(ip_hdr_o); ip_hdr_o = NULL;
        }
        else
            ip_hdr->ip_sum = htons(cksum((u_char *)ip_hdr, ip_hlb));
    }

    /*
     * go pass pcap generic header and Ethernet header in new_pkt_data
     * then copy ip_hdr and ip_o (if exist) into new_pkt_data and reset
     * pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
        *new_pkt_data++;

    memcpy(new_pkt_data, ip_hdr, IP_HDR_LEN);

    /* have IP options */
    if (ip_hlb > IP_HDR_LEN) {
        i = 0;
        while (i++ < IP_HDR_LEN)
            *new_pkt_data++;

        memcpy(new_pkt_data, ip_o, ip_hlb - IP_HDR_LEN);
        free(ip_o); ip_o = NULL;

        i = 0;
        while (i++ < IP_HDR_LEN)
            *new_pkt_data--;
    }

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN)
        *new_pkt_data--;

    if (flag == 0) {
        /* copy up to layer 3 only, discard remaining data */
        if (layer_opt == 3) {
            /* we are editing IP header and we have payload */
            if (header_opt == IP && payload_len_opt > 0) {
                /*
                 * go pass pcap generic header, Ethernet header and IP header in
                 * new_pkt_data then copy payload_opt into new_pkt_data and reset
                 * pointer to the beginning of new_pkt_data
                 */
                i = 0;
                while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
                    *new_pkt_data++;

                memcpy(new_pkt_data, payload_opt, payload_len_opt);

                i = 0;
                while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
                    *new_pkt_data--;

                header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + payload_len_opt;

                /*
                 * if payload is specified and it applies to ICMP, TCP, or UDP header + data,
                 * and checksum correction on this payload is needed,
                 * and more fragment flag is not set -> not a fragmented packet
                 */
                if (csum_opt && !m) {
                    /* parse ICMP datagram */
                    if (ip_p == IPPROTO_ICMP)
                        return (parse_icmp(pkt_data, new_pkt_data, header, ip_hdr));
                    /* parse TCP datagram */
                    else if (ip_p == IPPROTO_TCP)
                        return (parse_tcp(pkt_data, new_pkt_data, header, ip_hdr));
                    /* parse UDP datagram */
                    else if (ip_p == IPPROTO_UDP)
                        return (parse_udp(pkt_data, new_pkt_data, header, ip_hdr));
                }
            }
            else
                header->caplen = header->len = ETHER_HDR_LEN + ip_hlb;

            free(ip_hdr); ip_hdr = NULL;
            return (header->caplen);
        }

        /* !m means more fragment flag is not set -> not a fragmented packet */
        if (!m) {
            /* parse ICMP datagram */
            if (ip_p == IPPROTO_ICMP)
                return (parse_icmp(pkt_data, new_pkt_data, header, ip_hdr));
            /* parse TCP datagram */
            else if (ip_p == IPPROTO_TCP)
                return (parse_tcp(pkt_data, new_pkt_data, header, ip_hdr));
            /* parse UDP datagram */
            else if (ip_p == IPPROTO_UDP)
                return (parse_udp(pkt_data, new_pkt_data, header, ip_hdr));
        }

        /* no further editing support for other datagram or fragmented packet */
        free(ip_hdr); ip_hdr = NULL;
        return (ETHER_HDR_LEN + ip_hlb);
    }
    return (0); /* flag is 1 */
}

u_short parse_icmp(const u_char *pkt_data,
                   u_char *new_pkt_data,
                   struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr)
{
    /*
     * ICMP header (4 bytes)
     *  1. type (1 byte)
     *  2. code (1 byte)
     *  3. checksum (2 bytes)
     */
    struct icmphdr *icmp_hdr;
    u_char *icmpp;      /* ICMP header + trailing data */
    u_short icmpp_len;
    u_short ip_hlb;     /* IP header length in bytes */
    u_short ip_fo;      /* IP fragment offset (number of 64-bit segments) */
    int i;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if ICMP header is truncated */
    if (header->caplen < ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN) {
        free(ip_hdr); ip_hdr = NULL;
        return (ETHER_HDR_LEN + ip_hlb);
    }

    icmp_hdr = (struct icmphdr *)malloc(ICMP_HDR_LEN);
    if (icmp_hdr == NULL)
        error("malloc(): cannot allocate memory for icmp_hdr");

    /*
     * we have payload which covers ICMP header + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
        /*
         * go pass pcap generic header, Ethernet header and IP header
         * in new_pkt_data then copy ICMP header from new_pkt_data
         * into icmp_hdr and reset pointer to the beginning of
         * new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data++;

        memcpy(icmp_hdr, new_pkt_data, ICMP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data--;
    }
    else {
        /*
         * go pass Ethernet header and IP header in pkt_data
         * then copy ICMP header from pkt_data into icmp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data++;

        memcpy(icmp_hdr, pkt_data, ICMP_HDR_LEN);

        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data--;

        /* we are editing ICMP header */
        if (header_opt == ICMP) {
            /* overwrite type */
            if (icmpopt->icmp_type_flag)
                icmp_hdr->icmp_type = icmpopt->icmp_type;

            /* overwrite code */
            if (icmpopt->icmp_code_flag)
                icmp_hdr->icmp_code = icmpopt->icmp_code;
        }

        /* we are going to copy up to layer 4 only */
        if (layer_opt == 4) {
            /*
             * we are editing ICMP header and we have payload, attach
             * the payload first before checksum calculation.
             */
            if (header_opt == ICMP && payload_len_opt > 0) {
                /* truncate payload if it is too large */
                if ((payload_len_opt + ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN) > ETHER_MAX_LEN)
                    payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN) - ETHER_MAX_LEN;

                /*
                 * go pass pcap generic header, Ethernet header, IP header
                 * and ICMP header in new_pkt_data then copy payload_opt
                 * into new_pkt_data and reset pointer to the beginning of
                 * new_pkt_data
                 */
                i = 0;
                while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN)
                    *new_pkt_data++;

                memcpy(new_pkt_data, payload_opt, payload_len_opt);

                i = 0;
                while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN)
                    *new_pkt_data--;

                header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN + payload_len_opt;
            }
            else
                header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN;

            /* update IP total length */
            ip_hdr->ip_len = htons(header->caplen - ETHER_HDR_LEN);

            /* go pass Ethernet header in pkt_data */
            i = 0;
            while (i++ < ETHER_HDR_LEN)
                *pkt_data++;

            /*
             * reuse parsing function for IP header to update IP total length in
             * new_pkt_data and recalculate checksum for IP header if required.
             */
            (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

            /* reset pointer to the beginning of pkt_data */
            i = 0;
            while (i++ < ETHER_HDR_LEN)
                *pkt_data--;
        }
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /* recalculate checksum for ICMP header (cover ICMP header + trailing data) */
    if (csum_opt && ip_fo == 0) {
        /* recalculate checksum if we have enough data */
        if (header->caplen >= (ETHER_HDR_LEN + ntohs(ip_hdr->ip_len))) {
            icmpp_len = ntohs(ip_hdr->ip_len) - ip_hlb;

            /* icmpp_len must be even for correct checksum calculation */
            if ((icmpp_len % 2) != 0)
                icmpp = (u_char *)malloc(sizeof(u_char) * (icmpp_len + 1));
            else
                icmpp = (u_char *)malloc(sizeof(u_char) * icmpp_len);

            if (icmpp == NULL)
                error("malloc(): cannot allocate memory for icmpp");

            if ((icmpp_len % 2) != 0)
                memset(icmpp, 0, icmpp_len + 1);
            else
                memset(icmpp, 0, icmpp_len);

            /* clear checksum field */
            icmp_hdr->icmp_cksum = 0x0000;

            /* copy ICMP header from icmp_hdr into icmpp */
            memcpy(icmpp, icmp_hdr, ICMP_HDR_LEN);

            /* copy trailing data from payload_opt into icmpp */
            if (layer_opt == 4 && header_opt == ICMP && payload_len_opt > 0) {
                for (i = ICMP_HDR_LEN; i < (ICMP_HDR_LEN + payload_len_opt); i++)
                    icmpp[i] = payload_opt[i - ICMP_HDR_LEN];
            }
            /* copy trailing data from payload_opt (payload after IP header) into icmpp */
            else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
                for (i = ICMP_HDR_LEN; i < payload_len_opt; i++)
                    icmpp[i] = payload_opt[i];
            }
            /* copy trailing data from pkt_data into icmpp */
            else {
                for (i = ICMP_HDR_LEN; i < icmpp_len; i++)
                    icmpp[i] = pkt_data[ETHER_HDR_LEN + ip_hlb + i];
            }

            /* recalculate checksum */
            if ((icmpp_len % 2) != 0)
                icmp_hdr->icmp_cksum = cksum(icmpp, icmpp_len + 1);
            else
                icmp_hdr->icmp_cksum = cksum(icmpp, icmpp_len);
            icmp_hdr->icmp_cksum = htons(icmp_hdr->icmp_cksum);

            free(icmpp); icmpp = NULL;
        }
    }
    free(ip_hdr); ip_hdr = NULL;

    /*
     * go pass pcap generic header, Ethernet header and IP header
     * in new_pkt_data then copy icmp_hdr into new_pkt_data and
     * reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data++;

    memcpy(new_pkt_data, icmp_hdr, ICMP_HDR_LEN);
    free(icmp_hdr); icmp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data--;

    /* no further editing support after ICMP header */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP header) which covers ICMP header + data,
     * checksum for ICMP header corrected above,
     * while ICMP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETHER_HDR_LEN + ip_hlb + ICMP_HDR_LEN);
}

u_short parse_tcp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr)
{
    /*
     * TCP header (20 bytes + optional X bytes for options)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. sequence number (4 bytes)
     *  4. acknowledgment number (4 bytes)
     *  5. data offset (4 bits) - number of 32-bit segments in TCP header
     *  6. reserved (6 bits)
     *  7. flags (6 bits)
     *  8. window (2 bytes)
     *  9. checksum (2 bytes)
     * 10. urgent pointer (2 bytes)
     * 11. options (X bytes)
     */
    struct tcphdr *tcp_hdr;
    u_char *tcp_o = NULL;   /* options (X bytes) */
    u_short tcp_hlb;        /* TCP header length in bytes */
    u_char *tcpp;           /* IP pseudo header + TCP header (with options if exist) + trailing data */
    u_short tcpp_len;
    struct ippseudo *ipp;   /* IP pseudo header */
    u_short ip_hlb;         /* IP header length in bytes */
    u_short ip_fo;          /* IP fragment offset (number of 64-bit segments) */
    int i, j;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if TCP header is truncated */
    if (header->caplen < ETHER_HDR_LEN + ip_hlb + TCP_HDR_LEN) {
        free(ip_hdr); ip_hdr = NULL;
        return (ETHER_HDR_LEN + ip_hlb);
    }

    tcp_hdr = (struct tcphdr *)malloc(TCP_HDR_LEN);
    if (tcp_hdr == NULL)
        error("malloc(): cannot allocate memory for tcp_hdr");

    /*
     * we have payload which covers TCP header + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
        /*
         * go pass pcap generic header, Ethernet header and IP header
         * in new_pkt_data then copy TCP header from new_pkt_data
         * into tcp_hdr and reset pointer to the beginning of
         * new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data++;

        memcpy(tcp_hdr, new_pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data--;
    }
    else {
        /*
         * go pass Ethernet header and IP header in pkt_data
         * then copy TCP header from pkt_data into tcp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data++;

        memcpy(tcp_hdr, pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data--;
    }

    tcp_hlb = tcp_hdr->th_off * 4; /* convert to bytes */

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN) {
        /* do nothing if TCP header with options is truncated */
        if (header->caplen < (ETHER_HDR_LEN + ip_hlb + tcp_hlb)) {
            free(ip_hdr); ip_hdr = NULL;
            free(tcp_hdr); tcp_hdr = NULL;
            return (ETHER_HDR_LEN + ip_hlb);
        }

        tcp_o = (u_char *)malloc(sizeof(u_char) * (tcp_hlb - TCP_HDR_LEN));
        if (tcp_o == NULL)
            error("malloc(): cannot allocate memory for tcp_o");

        if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
            /* copy TCP options from new_pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = new_pkt_data[PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + j];
        }
        else {
            /* copy TCP options from pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = pkt_data[ETHER_HDR_LEN + ip_hlb + j];
        }
    }

    /* we are editing TCP header */
    if (header_opt == TCP) {
        /* overwrite source port */
        if (tcpopt->th_sport_flag == 1) /* overwrite all source port */
            tcp_hdr->th_sport = htons(tcpopt->th_old_sport);
        else if (tcpopt->th_sport_flag == 2 && /* overwrite matching port only */
                tcp_hdr->th_sport == htons(tcpopt->th_old_sport))
            tcp_hdr->th_sport = htons(tcpopt->th_new_sport);

        /* overwrite destination port */
        if (tcpopt->th_dport_flag == 1) /* overwrite all destination port */
            tcp_hdr->th_dport = htons(tcpopt->th_old_dport);
        else if (tcpopt->th_dport_flag == 2 && /* overwrite matching port only */
                tcp_hdr->th_dport == htons(tcpopt->th_old_dport))
            tcp_hdr->th_dport = htons(tcpopt->th_new_dport);

        /* overwrite sequence number */
        if (tcpopt->th_seq_flag)
            tcp_hdr->th_seq = htonl(tcpopt->th_seq);

        /* overwrite acknowledgment number */
        if (tcpopt->th_ack_flag)
            tcp_hdr->th_ack = htonl(tcpopt->th_ack);

        /* overwrite flags */
        if (tcpopt->th_flags_flag)
            tcp_hdr->th_flags = ((tcpopt->th_flag_u ? TH_URG : 0) |
                (tcpopt->th_flag_a ? TH_ACK : 0) |
                (tcpopt->th_flag_p ? TH_PUSH : 0) |
                (tcpopt->th_flag_r ? TH_RST : 0) |
                (tcpopt->th_flag_s ? TH_SYN : 0) |
                (tcpopt->th_flag_f ? TH_FIN : 0));

        /* overwrite window size */
        if (tcpopt->th_win_flag)
            tcp_hdr->th_win = htons(tcpopt->th_win);

        /* overwrite urgent pointer */
        if (tcpopt->th_urp_flag)
            tcp_hdr->th_urp = htons(tcpopt->th_urp);
    }

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4) {
        /*
         * we are editing TCP header and we have payload, attach
         * the payload first before checksum calculation
         */
        if (header_opt == TCP && payload_len_opt > 0) {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETHER_HDR_LEN + ip_hlb + tcp_hlb) > ETHER_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN + ip_hlb + tcp_hlb) - ETHER_MAX_LEN;

            /*
             * go pass pcap generic header, Ethernet header, IP header
             * and TCP header in new_pkt_data then copy payload_opt
             * into new_pkt_data and reset pointer to the beginning of
             * new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + tcp_hlb)
                *new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + tcp_hlb)
                *new_pkt_data--;

            header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + tcp_hlb + payload_len_opt;
        }
        else
            header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + tcp_hlb;

        /* update IP total length */
        ip_hdr->ip_len = htons(header->caplen - ETHER_HDR_LEN);

        /* go pass Ethernet header in pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data++;

        /*
         * reuse parsing function for IP header to update IP total length in
         * new_pkt_data and recalculate checksum for IP header if required.
         */
        (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data--;
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /* recalculate checksum for TCP header (cover IP pseudo header + TCP header + trailing data) */
    if (csum_opt && ip_fo == 0) {
        /* recalculate checksum if we have enough data */
        if (header->caplen >= (ETHER_HDR_LEN + ntohs(ip_hdr->ip_len))) {
            /* create IP pseudo header */
            ipp = (struct ippseudo *)malloc(sizeof(struct ippseudo));
            if (ipp == NULL)
                error("malloc(): cannot allocate memory for ipp");

            memcpy(&ipp->ippseudo_src, &ip_hdr->ip_src, sizeof(struct in_addr));
            memcpy(&ipp->ippseudo_dst, &ip_hdr->ip_dst, sizeof(struct in_addr));
            ipp->ippseudo_pad = 0x00;
            ipp->ippseudo_p = ip_hdr->ip_p;
            ipp->ippseudo_len = htons(ntohs(ip_hdr->ip_len) - ip_hlb);

            tcpp_len = sizeof(struct ippseudo) + ntohs(ipp->ippseudo_len);

            /* tcpp_len must be even for correct checksum calculation */
            if ((tcpp_len % 2) != 0)
                tcpp = (u_char *)malloc(sizeof(u_char) * (tcpp_len + 1));
            else
                tcpp = (u_char *)malloc(sizeof(u_char) * tcpp_len);

            if (tcpp == NULL)
                error("malloc(): cannot allocate memory for tcpp");

            if ((tcpp_len % 2) != 0)
                memset(tcpp, 0, tcpp_len + 1);
            else
                memset(tcpp, 0, tcpp_len);

            /* copy IP pseudo header from ipp into tcpp */
            memcpy(tcpp, ipp, sizeof(struct ippseudo));
            free(ipp); ipp = NULL;

            /* go pass IP pseudo header in tcpp */
            i = 0;
            while (i++ < sizeof(struct ippseudo))
                *tcpp++;

            /* clear checksum field */
            tcp_hdr->th_sum = 0x0000;

            /* copy TCP header from tcp_hdr into tcpp */
            memcpy(tcpp, tcp_hdr, TCP_HDR_LEN);

            /*
             * have TCP options, go pass TCP header in tcpp then copy tcp_o into tcpp
             * and reset pointer of tcpp to go pass IP pseudo header only
             */
            if (tcp_hlb > TCP_HDR_LEN) {
                i = 0;
                while (i++ < TCP_HDR_LEN)
                    *tcpp++;

                memcpy(tcpp, tcp_o, tcp_hlb - TCP_HDR_LEN);

                i = 0;
                while (i++ < TCP_HDR_LEN)
                    *tcpp--;
            }

            /* reset pointer to the beginning of tcpp */
            i = 0;
            while (i++ < sizeof(struct ippseudo))
                *tcpp--;

            /* copy trailing data from payload_opt into tcpp */
            if (layer_opt == 4 && header_opt == TCP && payload_len_opt > 0) {
                for (i = tcp_hlb; i < (tcpp_len - sizeof(struct ippseudo)); i++)
                    tcpp[i + sizeof(struct ippseudo)] = payload_opt[i - tcp_hlb];
            }
            /* copy trailing data from payload_opt (payload after IP header) into tcpp */
            else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
                for (i = tcp_hlb; i < payload_len_opt; i++)
                    tcpp[i + sizeof(struct ippseudo)] = payload_opt[i];
            }
            /* copy trailing data from pkt_data into tcpp */
            else {
                for (i = tcp_hlb; i < (tcpp_len - sizeof(struct ippseudo)); i++)
                    tcpp[i + sizeof(struct ippseudo)] = pkt_data[ETHER_HDR_LEN + ip_hlb + i];
            }

            /* recalculate checksum */
            if ((tcpp_len % 2) != 0)
                tcp_hdr->th_sum = cksum(tcpp, tcpp_len + 1);
            else
                tcp_hdr->th_sum = cksum(tcpp, tcpp_len);
            tcp_hdr->th_sum = htons(tcp_hdr->th_sum);

            free(tcpp); tcpp = NULL;
        }
    }
    free(ip_hdr); ip_hdr = NULL;

    /*
     * go pass pcap generic header, Ethernet header and IP header
     * in new_pkt_data then copy tcp_hdr and tcp_o (if exist) into
     * new_pkt_data and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data++;

    memcpy(new_pkt_data, tcp_hdr, TCP_HDR_LEN);
    free(tcp_hdr); tcp_hdr = NULL;

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN) {
        i = 0;
        while (i++ < TCP_HDR_LEN)
            *new_pkt_data++;

        memcpy(new_pkt_data, tcp_o, tcp_hlb - TCP_HDR_LEN);
        free(tcp_o); tcp_o = NULL;

        i = 0;
        while (i++ < TCP_HDR_LEN)
            *new_pkt_data--;
    }

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data--;

    /* no further editing support after TCP header */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP header) which covers TCP header + data,
     * checksum for TCP header corrected above,
     * while TCP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETHER_HDR_LEN + ip_hlb + tcp_hlb);
}

u_short parse_udp(const u_char *pkt_data,
                  u_char *new_pkt_data,
                  struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr)
{
    /*
     * UDP header (8 bytes)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. length (2 bytes)
     *  4. checksum (2 bytes)
     */
    struct udphdr *udp_hdr;
    u_char *udpp;           /* IP pseudo header + UDP header + trailing data */
    u_short udpp_len;
    struct ippseudo *ipp;   /* IP pseudo header */
    u_short ip_hlb;         /* IP header length in bytes */
    u_short ip_fo;          /* IP fragment offset (number of 64-bit segments) */
    int i;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if UDP header is truncated */
    if (header->caplen < ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN) {
        free(ip_hdr); ip_hdr = NULL;
        return (ETHER_HDR_LEN + ip_hlb);
    }

    udp_hdr = (struct udphdr *)malloc(UDP_HDR_LEN);
    if (udp_hdr == NULL)
        error("malloc(): cannot allocate memory for udp_hdr");

    /*
     * we have payload which covers UDP header + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
        /*
         * go pass pcap generic header, Ethernet header and IP header
         * in new_pkt_data then copy UDP header from new_pkt_data
         * into udp_hdr and reset pointer to the beginning of
         * new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data++;

        memcpy(udp_hdr, new_pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
            *new_pkt_data--;
    }
    else {
        /*
         * go pass Ethernet header and IP header in pkt_data
         * then copy UDP header from pkt_data into udp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data++;

        memcpy(udp_hdr, pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < (ETHER_HDR_LEN + ip_hlb))
            *pkt_data--;
    }

    /* we are editing UDP header */
    if (header_opt == UDP) {
        /* overwrite source port */
        if (udpopt->uh_sport_flag == 1) /* overwrite all source port */
            udp_hdr->uh_sport = htons(udpopt->uh_old_sport);
        else if (udpopt->uh_sport_flag == 2 && /* overwrite matching port only */
                udp_hdr->uh_sport == htons(udpopt->uh_old_sport))
            udp_hdr->uh_sport = htons(udpopt->uh_new_sport);

        /* overwrite destination port */
        if (udpopt->uh_dport_flag == 1) /* overwrite all destination port */
            udp_hdr->uh_dport = htons(udpopt->uh_old_dport);
        else if (udpopt->uh_dport_flag == 2 && /* overwrite matching port only */
                udp_hdr->uh_dport == htons(udpopt->uh_old_dport))
            udp_hdr->uh_dport = htons(udpopt->uh_new_dport);
    }

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4) {
        /*
         * we are editing UDP header and we have payload, attach
         * the payload first before checksum calculation
         */
        if (header_opt == UDP && payload_len_opt > 0) {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN) > ETHER_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN) - ETHER_MAX_LEN;

            /*
             * go pass pcap generic header, Ethernet header, IP header
             * and UDP header in new_pkt_data then copy payload_opt
             * into new_pkt_data and reset pointer to the beginning of
             * new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN)
                *new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN)
                *new_pkt_data--;

            header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN;

        /* update UDP length */
        udp_hdr->uh_ulen = htons(header->caplen - (ETHER_HDR_LEN + ip_hlb));

        /* update IP total length */
        ip_hdr->ip_len = htons(header->caplen - ETHER_HDR_LEN);

        /* go pass Ethernet header in pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data++;

        /*
         * reuse parsing function for IP header to update IP total length in
         * new_pkt_data and recalculate checksum for IP header if required.
         */
        (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETHER_HDR_LEN)
            *pkt_data--;
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /* recalculate checksum for UDP header (cover IP pseudo header + UDP header + trailing data) */
    if (csum_opt && ip_fo == 0) {
        /* recalculate checksum if we have enough data */
        if (header->caplen >= (ETHER_HDR_LEN + ntohs(ip_hdr->ip_len))) {
            /* create IP pseudo header */
            ipp = (struct ippseudo *)malloc(sizeof(struct ippseudo));
            if (ipp == NULL)
                error("malloc(): cannot allocate memory for ipp");

            memcpy(&ipp->ippseudo_src, &ip_hdr->ip_src, sizeof(struct in_addr));
            memcpy(&ipp->ippseudo_dst, &ip_hdr->ip_dst, sizeof(struct in_addr));
            ipp->ippseudo_pad = 0x00;
            ipp->ippseudo_p = ip_hdr->ip_p;
            ipp->ippseudo_len = htons(ntohs(ip_hdr->ip_len) - ip_hlb);

            udpp_len = sizeof(struct ippseudo) + ntohs(ipp->ippseudo_len);

            /* udpp_len must be even for correct checksum calculation */
            if ((udpp_len % 2) != 0)
                udpp = (u_char *)malloc(sizeof(u_char) * (udpp_len + 1));
            else
                udpp = (u_char *)malloc(sizeof(u_char) * udpp_len);

            if (udpp == NULL)
                error("malloc(): cannot allocate memory for udpp");

            if ((udpp_len % 2) != 0)
                memset(udpp, 0, udpp_len + 1);
            else
                memset(udpp, 0, udpp_len);

            /* copy IP pseudo header from ipp into udpp */
            memcpy(udpp, ipp, sizeof(struct ippseudo));
            free(ipp); ipp = NULL;

            /* go pass IP pseudo header in udpp */
            i = 0;
            while (i++ < sizeof(struct ippseudo))
                *udpp++;

            /* clear checksum field */
            udp_hdr->uh_sum = 0x0000;

            /* copy UDP header from udp_hdr into udpp */
            memcpy(udpp, udp_hdr, UDP_HDR_LEN);

            /* reset pointer to the beginning of udpp */
            i = 0;
            while (i++ < sizeof(struct ippseudo))
                *udpp--;

            /* copy trailing data from payload_opt into udpp */
            if (layer_opt == 4 && header_opt == UDP && payload_len_opt > 0) {
                for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ippseudo)); i++)
                    udpp[i + sizeof(struct ippseudo)] = payload_opt[i - UDP_HDR_LEN];
            }
            /* copy trailing data from payload_opt (payload after IP header) into udpp */
            else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0) {
                for (i = UDP_HDR_LEN; i < payload_len_opt; i++)
                    udpp[i + sizeof(struct ippseudo)] = payload_opt[i];
            }
            /* copy trailing data from pkt_data into udpp */
            else {
                for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ippseudo)); i++)
                    udpp[i + sizeof(struct ippseudo)] = pkt_data[ETHER_HDR_LEN + ip_hlb + i];
            }

            /* recalculate checksum */
            if ((udpp_len % 2) != 0)
                udp_hdr->uh_sum = cksum(udpp, udpp_len + 1);
            else
                udp_hdr->uh_sum = cksum(udpp, udpp_len);
            udp_hdr->uh_sum = htons(udp_hdr->uh_sum);

            free(udpp); udpp = NULL;
        }
    }
    free(ip_hdr); ip_hdr = NULL;

    /*
     * go pass pcap generic header, Ethernet header and IP header
     * in new_pkt_data then copy udp_hdr into new_pkt_data and reset
     * pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data++;

    memcpy(new_pkt_data, udp_hdr, UDP_HDR_LEN);
    free(udp_hdr); udp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETHER_HDR_LEN + ip_hlb)
        *new_pkt_data--;

    /* no further editing support after UDP header */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP header) which covers UDP header + data,
     * checksum for UDP header corrected above,
     * while UDP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETHER_HDR_LEN + ip_hlb + UDP_HDR_LEN);
}

/* Reference: rfc1071.txt */
u_short cksum(u_char *cp, u_short len)
{
    u_short word_16; /* 16-bit word */
    u_int sum = 0;
    u_short i;

    /* from 2 adjacent 8-bit words, create a 16-bit word, add all 16-bit words */
    for (i = 0; i < len; i = i + 2) {
        word_16 = ((cp[i] << 8) & 0xff00) + (cp[i + 1] & 0xff);
        sum += (u_int)word_16;
    }

    /* take 16 bits out of the 32-bit sum */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    /* one's complement the sum */
    return ((u_short)~sum);
}

void info(void)
{
    (void)putchar('\n');
    notice("%u packets (%u bytes) written", pkts, bytes);
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void notice(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void error(const char *fmt, ...)
{
    va_list ap;
    (void)fprintf(stderr, "%s: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    exit(EXIT_FAILURE);
}

/*
 * Reference: FreeBSD's /usr/src/lib/libc/net/ether_addr.c
 *
 * Copyright (c) 1995
 *      Bill Paul <wpaul@ctr.columbia.edu>.  All rights reserved.
 *
 */
struct ether_addr *ether_aton(const char *a)
{
    int i;
    static struct ether_addr o;
    unsigned int o0, o1, o2, o3, o4, o5;

    i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

    if (i != 6)
        return (NULL);

    o.octet[0]=o0;
    o.octet[1]=o1;
    o.octet[2]=o2;
    o.octet[3]=o3;
    o.octet[4]=o4;
    o.octet[5]=o5;

    return ((struct ether_addr *)&o);
}

/*
 * Reference: FreeBSD's /usr/src/lib/libc/inet/inet_addr.c
 *
 * Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 */
int inet_aton(const char *cp, struct in_addr *addr)
{
    u_long val;
    int base, n;
    char c;
    u_int8_t parts[4];
    u_int8_t *pp = parts;
    int digit;

    c = *cp;
    for (;;) {
        /*
         * Collect number up to ".".
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if (!isdigit((unsigned char)c))
            return (0);
        val = 0; base = 10; digit = 0;
        if (c == '0') {
            c = *++cp;
            if (c == 'x' || c == 'X')
                base = 16, c = *++cp;
            else {
                base = 8;
                digit = 1;
            }
        }
        for (;;) {
            if (isascii(c) && isdigit((unsigned char)c)) {
                if (base == 8 && (c == '8' || c == '9'))
                    return (0);
                val = (val * base) + (c - '0');
                c = *++cp;
                digit = 1;
            } else if (base == 16 && isascii(c) &&
                    isxdigit((unsigned char)c)) {
                val = (val << 4) |
                    (c + 10 - (islower((unsigned char)c) ? 'a' : 'A'));
                c = *++cp;
                digit = 1;
            } else
                break;
        }
        if (c == '.') {
            /*
             * Internet format:
             *      a.b.c.d
             *      a.b.c   (with c treated as 16 bits)
             *      a.b     (with b treated as 24 bits)
             */
            if (pp >= parts + 3 || val > 0xffU)
                return (0);
            *pp++ = val;
            c = *++cp;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && (!isascii(c) || !isspace((unsigned char)c)))
        return (0);
    /*
     * Did we get a valid digit?
     */
    if (!digit)
        return (0);
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    n = pp - parts + 1;
    switch (n) {
        case 1:                         /* a -- 32 bits */
            break;

        case 2:                         /* a.b -- 8.24 bits */
            if (val > 0xffffffU)
                return (0);
            val |= parts[0] << 24;
                break;

        case 3:                         /* a.b.c -- 8.8.16 bits */
            if (val > 0xffffU)
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16);
                break;

        case 4:                         /* a.b.c.d -- 8.8.8.8 bits */
            if (val > 0xffU)
                return (0);
            val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
                break;
    }
    if (addr != NULL)
        addr->s_addr = htonl(val);
    return (1);
}

void usage(void)
{
    (void)fprintf(stderr, "%s version %s\n"
        "%s\n"
        "Usage: %s [-I input] [-O output] [-L layer] [-X payload] [-C]\n"
        "                 [-M linktype] [-D offset] [-R range] [-S timeframe]\n"
        "                 [-T header] [header-specific-options] [-h]\n"
        "\nOptions:\n"
        " -I input        Input pcap based trace file.\n"
        " -O output       Output trace file.\n"
        " -L layer        Copy up to the specified 'layer' and discard the remaining\n"
        "                 data. Value for 'layer' must be either 2, 3 or 4 where\n"
        "                 2 for Ethernet, 3 for ARP or IP, and 4 for ICMP, TCP or UDP.\n"
        " -X payload      Append 'payload' in hex digits to the end of each packet.\n"
        "                 Example: -X 0302aad1\n"
        "                 -X flag is ignored if -L and -T flag are not specified.\n"
        " -C              Specify this flag to disable checksum correction.\n"
        "                 Checksum correction is applicable for non-fragmented IP,\n"
        "                 ICMP, TCP, and UDP packets only.\n"
        " -M linktype     Replace the 'linktype' stored in the pcap file header.\n"
        "                 Typically, value for 'linktype' is 1 for Ethernet.\n"
        "                 Example: -M 12 (for raw IP), -M 51 (for PPPoE)\n"
        " -D offset       Delete the specified byte 'offset' from each packet.\n"
        "                 First byte (starting from link layer header) starts from 1.\n"
        "                 -L, -X, -C and -T flag are ignored if -D flag is specified.\n"
        "                 Example: -D 15-40, -D 10 or -D 18-9999\n"
        " -R range        Save only the specified 'range' of packets.\n"
        "                 Example: -R 5-21 or -R 9\n"
        " -S timeframe    Save only the packets within the specified 'timeframe' with\n"
        "                 up to one-second resolution using DD/MM/YYYY,HH:MM:SS as the\n"
        "                 format for start and end time in 'timeframe'.\n"
        "                 Example: -S 22/10/2006,21:47:35-24/10/2006,13:16:05\n"
        "                 -S flag is evaluated after -R flag.\n"
        " -T header       Edit only the specified 'header'. Possible keywords for\n"
        "                 'header' are, eth, arp, ip, icmp, tcp, or udp.\n"
        "                 -T flag must appear last among the general options.\n"
        " -h              Print version information and usage.\n",
        program_name, BITTWISTE_VERSION, pcap_lib_version(), program_name);
    exit(EXIT_SUCCESS);
}
