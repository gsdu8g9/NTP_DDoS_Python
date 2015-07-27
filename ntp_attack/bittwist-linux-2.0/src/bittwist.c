/*
 * bittwist - pcap based ethernet packet generator
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

#include "bittwist.h"

char *program_name;

int32_t thiszone; /* offset from GMT to local time in seconds */

char ebuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer */

/* options */
int vflag = 0;      /* 1 - print timestamp, 2 - print timestamp and hex data */
int len = 0;        /* packet length to send (-1 = captured, 0 = on wire, or positive value <= 65535) */
double speed = 1;   /* multiplier for timestamp difference between 2 adjacent packets */
int linerate = 0;   /* limit packet throughput at the specified Mbps (0 means no limit) */
int interval = 0;   /* a constant interval in seconds (0 means actual interval will be used instead) */
int max_pkts = 0;   /* send up to the specified number of packets */

pcap_t *pd = NULL;          /* pcap descriptor */
u_char *pkt_data = NULL;    /* packet data including the link-layer header */

/* stats */
static u_int pkts_sent = 0;
static u_int bytes_sent = 0;
static u_int failed = 0;
struct timeval start = {0,0};
struct timeval end = {0,0};

int main(int argc, char **argv)
{
    char *cp;
    int c;
    pcap_if_t *devptr;
    int i;
    int devnum;
    char *device = NULL;
    int loop = 1;
    thiszone = gmt2local(0);

    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    /* process options */
    while ((c = getopt(argc, argv, "dvi:s:l:c:m:r:p:h")) != -1) {
        switch (c) {
            case 'd':
                if (pcap_findalldevs(&devptr, ebuf) < 0)
                    error("%s", ebuf);
                else {
                    for (i = 0; devptr != 0; i++) {
                        (void)printf("%d. %s", i + 1, devptr->name);
                        if (devptr->description != NULL)
                            (void)printf(" (%s)", devptr->description);
                        (void)putchar('\n');
                        devptr = devptr->next;
                    }
                }
                exit(EXIT_SUCCESS);
            case 'v':
                ++vflag;
                break;
            case 'i':
                if ((devnum = atoi(optarg)) != 0) {
                    if (devnum < 0)
                        error("invalid adapter index");
                    if (pcap_findalldevs(&devptr, ebuf) < 0)
                        error("%s", ebuf);
                    else {
                        for (i = 0; i < devnum - 1; i++) {
                            devptr = devptr->next;
                            if (devptr == NULL)
                                error("invalid adapter index");
                        }
                    }
                    device = devptr->name;
                } else {
                    device = optarg;
                }
                break;
            case 's':
                len = strtol(optarg, NULL, 0);
                if (len != -1 && len != 0) {
                    if (len < ETHER_HDR_LEN || len > ETHER_MAX_LEN)
                        error("value for length must be between %d to %d", ETHER_HDR_LEN, ETHER_MAX_LEN);
                }
                break;
            case 'l':
                loop = strtol(optarg, NULL, 0); /* loop infinitely of loop <= 0 */
                break;
            case 'c':
                max_pkts = strtol(optarg, NULL, 0); /* send all packets if max_pkts <= 0 */
                break;
            case 'm':
                speed = strtod(optarg, NULL);
                if (speed > 0 && speed < SPEED_MIN)
                    error("positive value for speed must be at least %f", SPEED_MIN);
                break;
            case 'r':
                linerate = strtol(optarg, NULL, 0);
                if (linerate < LINERATE_MIN || linerate > LINERATE_MAX)
                    error("value for rate must be between %d to %d", LINERATE_MIN, LINERATE_MAX);
                break;
            case 'p':
                interval = strtol(optarg, NULL, 0);
                if (interval < 1 || interval > SLEEP_MAX)
                    error("value for sleep must be between 1 to %d", SLEEP_MAX);
                break;
            case 'h':
            default:
                usage();
        }
    }

    if (device == NULL)
        error("device not specified");

    if (argv[optind] == NULL)
        error("trace file not specified");

    notice("sending packets through %s", device);

    /* empty error buffer to grab warning message (if exist) from pcap_open_live() below */
    *ebuf = '\0';

    /* note that we are doing this for sending packets, not capture */
    pd = pcap_open_live(device,
                        ETHER_MAX_LEN,  /* portion of packet to capture */
                        1,              /* promiscuous mode is on */
                        1000,           /* read timeout, in milliseconds */
                        ebuf);

    if (pd == NULL)
        error("%s", ebuf);
    else if (*ebuf)
        notice("%s", ebuf); /* warning message from pcap_open_live() above */

    /* buffer to store data for each packet including its link-layer header, freed in cleanup() */
    pkt_data = (u_char *)malloc(sizeof(u_char) * ETHER_MAX_LEN);
    if (pkt_data == NULL)
        error("malloc(): cannot allocate memory for pkt_data");
    memset(pkt_data, 0, ETHER_MAX_LEN);

    /* set signal handler for SIGINT (Control-C) */
    (void)signal(SIGINT, cleanup);

    if (gettimeofday(&start, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));

    if (loop > 0) {
        while (loop--) {
            for (i = optind; i < argc; i++) /* for each trace file */
                send_packets(device, argv[i]);
        }
    }
    /* send infinitely if loop <= 0 until user Control-C */
    else {
        while (1) {
            for (i = optind; i < argc; i++)
                send_packets(device, argv[i]);
        }
    }

    cleanup(0);

    /* NOTREACHED */
    exit(EXIT_SUCCESS);
}

void send_packets(char *device, char *trace_file)
{
    FILE *fp; /* file pointer to trace file */
    struct pcap_file_header preamble;
    struct pcap_sf_pkthdr header;
    int pkt_len; /* packet length to send */
    int ret;
    int i;
    struct pcap_timeval p_ts;
    struct timeval ts;
    struct timeval sleep = {0,0};
    struct timeval cur_ts;
    struct timeval prev_ts = {0,0};
    struct timespec nsleep;
    sigset_t block_sig;

    (void)sigemptyset(&block_sig);
    (void)sigaddset(&block_sig, SIGINT);

    notice("trace file: %s", trace_file);
    if ((fp = fopen(trace_file, "rb")) == NULL)
        error("fopen(): error reading %s", trace_file);

    /* preamble occupies the first 24 bytes of a trace file */
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        error("fread(): error reading %s", trace_file);
    if (preamble.magic != PCAP_MAGIC)
        error("%s is not a valid pcap based trace file", trace_file);

    /*
     * loop through the remaining data by reading the packet header first.
     * packet header (16 bytes) = timestamp + length
     */
    while ((ret = fread(&header, sizeof(header), 1, fp))) {
        if (ret == 0)
            error("fread(): error reading %s", trace_file);

        /* copy timestamp for current packet */
        memcpy(&p_ts, &header.ts, sizeof(p_ts));
        cur_ts.tv_sec = p_ts.tv_sec;
        cur_ts.tv_usec = p_ts.tv_usec;

        if (len < 0)        /* captured length */
            pkt_len = header.caplen;
        else if (len == 0)  /* actual length */
            pkt_len = header.len;
        else                /* user specified length */
            pkt_len = len;

        if (timerisset(&prev_ts)) { /* pass first packet */
            if (speed != 0) {
                if (interval > 0) {
                    /* user specified interval is in seconds only */
                    sleep.tv_sec = interval;
                    if (speed != 1)
                        timer_div(&sleep, speed); /* speed factor */
                }
                else {
                    /* grab captured interval */
                    timersub(&cur_ts, &prev_ts, &sleep);
                    if (speed != 1) {
                        if (sleep.tv_sec > SLEEP_MAX) /* to avoid integer overflow in timer_div() */
                            notice("ignoring speed due to large interval");
                        else
                            timer_div(&sleep, speed);
                    }
                }

                if (linerate > 0) {
                    i = linerate_interval(pkt_len);
                    /* check if we exceed line rate */
                    if ((sleep.tv_sec == 0) && (sleep.tv_usec < i))
                        sleep.tv_usec = i; /* exceeded -> adjust */
                }
            }
            else { /* send immediately */
                if (linerate > 0)
                    sleep.tv_usec = linerate_interval(pkt_len);
            }

            if (timerisset(&sleep)) {
                /* notice("sleep %d seconds %d microseconds", sleep.tv_sec, sleep.tv_usec); */
                TIMEVAL_TO_TIMESPEC(&sleep, &nsleep);
                if (nanosleep(&nsleep, NULL) == -1) /* create the artificial slack time */
                    notice("nanosleep(): %s", strerror(errno));
            }
        }

        for (i = 0; i < pkt_len; i++) {
            /* copy captured packet data starting from link-layer header */
            if (i < header.caplen) {
                if ((ret = fgetc(fp)) == EOF)
                    error("fgetc(): error reading %s", trace_file);
                pkt_data[i] = ret;
            }
            else
                /* pad trailing bytes with zeros */
                pkt_data[i] = PKT_PAD;
        }
        /* move file pointer to the end of this packet data */
        if (i < header.caplen) {
            if (fseek(fp, header.caplen - pkt_len, SEEK_CUR) != 0)
                error("fseek(): error reading %s", trace_file);
        }

        (void)sigprocmask(SIG_BLOCK, &block_sig, NULL); /* hold SIGINT */

        /* finish the injection and verbose output before we give way to SIGINT */
        if (pcap_sendpacket(pd, pkt_data, pkt_len) == -1) {
            notice("%s", pcap_geterr(pd));
            ++failed;
        }
        else {
            ++pkts_sent;
            bytes_sent += pkt_len;

            /* copy timestamp for previous packet sent */
            memcpy(&prev_ts, &cur_ts, sizeof(struct timeval));

            /* verbose output */
            if (vflag) {
                if (gettimeofday(&ts, NULL) == -1)
                    notice("gettimeofday(): %s", strerror(errno));
                else
                    ts_print(&ts);

                (void)printf("#%d (%d bytes)", pkts_sent, pkt_len);

                if (vflag > 1)
                    hex_print(pkt_data, pkt_len);
                else
                    putchar('\n');

                fflush(stdout);
            }
        }

        (void)sigprocmask(SIG_UNBLOCK, &block_sig, NULL); /* release SIGINT */

        if ((max_pkts > 0) && (pkts_sent >= max_pkts))
            cleanup(0);
    } /* end while */

    (void)fclose(fp);
}

/*
 * Calculate line rate interval in microseconds for the given
 * pkt_len (bytes) and linerate (Mbps)
 *
 * to send packets at line rate with assumption of link speed at X:
 * interval = ((packet length * bits per byte) / (X to bits)) * 1000000
 * +---------------------------------------------------+
 * |            | 10Mbps      | 100Mbps    | 1000Mbps  |
 * +---------------------------------------------------+
 * |   14 bytes | 11 usecs.   | 1 usecs.   | 0 usecs.  |
 * | 1514 bytes | 1155 usecs. | 116 usecs. | 12 usecs. |
 * +---------------------------------------------------+
 */
int linerate_interval(int pkt_len)
{
    return ROUND(((float)pkt_len * 8) / (linerate * 1024 * 1024) * 1000000);
}

void info(void)
{
    struct timeval elapsed;
    float seconds;

    if (gettimeofday(&end, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));
    timersub(&end, &start, &elapsed);
    seconds = elapsed.tv_sec + (float)elapsed.tv_usec / 1000000;

    (void)putchar('\n');
    notice("%u packets (%u bytes) sent", pkts_sent, bytes_sent);
    if (failed)
        notice("%u write attempts failed", failed);
    notice("Elapsed time = %f seconds", seconds);
}

void cleanup(int signum)
{
    free(pkt_data); pkt_data = NULL;
    if (signum == -1)
        exit(EXIT_FAILURE);
    else
        info();
    exit(EXIT_SUCCESS);
}

void timer_div(struct timeval *tvp, double speed)
{
    double interval;

    interval = (tvp->tv_sec * 1000000 + tvp->tv_usec) / speed;
    tvp->tv_sec = interval / 1000000;
    tvp->tv_usec = ROUND(interval) - ((double)tvp->tv_sec * 1000000);
}

/*
 * Reference: tcpdump's gmt2local.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
int32_t gmt2local(time_t t)
{
    register int dt, dir;
    register struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
            (loc->tm_min - gmt->tm_min) * 60;

    /*
     * If the year or julian day is different, we span 00:00 GMT
     * and must add or subtract a day. Check the year first to
     * avoid problems when the julian day wraps.
     */
    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    return (dt);
}

/*
 * Reference: tcpdump's print-ascii.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void hex_print(register const u_char *cp, register u_int length)
{
    register u_int i, s;
    register int nshorts;
    register u_int oset = 0;

    nshorts = (u_int)length / sizeof(u_short);
    i = 0;
    while (--nshorts >= 0) {
        if ((i++ % 8) == 0) {
            (void)printf("\n\t0x%04x: ", oset);
            oset += 16;
        }
        s = *cp++;
        (void)printf(" %02x%02x", s, *cp++);
    }
    if (length & 1) {
        if ((i % 8) == 0)
            (void)printf("\n\t0x%04x: ", oset);
        (void)printf(" %02x", *cp);
    }
    (void)putchar('\n');
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void ts_print(register const struct timeval *tvp)
{
    register int s;

    s = (tvp->tv_sec + thiszone) % 86400;
    (void)printf("%02d:%02d:%02d.%06u ",
            s / 3600, (s % 3600) / 60, s % 60, (unsigned)tvp->tv_usec);
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
    cleanup(-1);
}

void usage(void)
{
    (void)fprintf(stderr, "%s version %s\n"
        "%s\n"
        "Usage: %s [-d] [-v] [-i interface] [-s length] [-l loop] [-c count]\n"
        "                [-m speed] [-r rate] [-p sleep] [-h] pcap-file(s)\n"
        "\nOptions:\n"
        " -d             Print a list of network interfaces available.\n"
        " -v             Print timestamp for each packet.\n"
        " -vv            Print timestamp and hex data for each packet.\n"
        " -i interface   Send 'pcap-file(s)' out onto the network through 'interface'.\n"
        " -s length      Packet length to send. Set 'length' to:\n"
        "                     0 to send the actual packet length. This is the default.\n"
        "                    -1 to send the captured length.\n"
        "                or any other value from %d to %d.\n"
        " -l loop        Send 'pcap-file(s)' out onto the network for 'loop' times.\n"
        "                Set 'loop' to 0 to send 'pcap-file(s)' until stopped.\n"
        "                To stop, type Control-C.\n"
        " -c count       Send up to 'count' packets.\n"
        "                Default is to send all packets from 'pcap-file(s)'.\n"
        " -m speed       Set interval multiplier to 'speed'.\n"
        "                Set 'speed' to 0 or less to send the next packet immediately.\n"
        "                Minimum positive value for 'speed' is %f.\n"
        " -r rate        Limit the sending to 'rate' Mbps.\n"
        "                Value for 'rate' must be between %d to %d.\n"
        "                This option is meant to limit the maximum packet throughput.\n"
        "                If you want to send packets at line rate of 100Mbps,\n"
        "                try -m 0 -r 100\n"
        " -p sleep       Set interval to 'sleep' (in seconds), ignoring the actual\n"
        "                interval.\n"
        "                Value for 'sleep' must be between 1 to %d.\n"
        " -h             Print version information and usage.\n",
        program_name, BITTWIST_VERSION, pcap_lib_version(), program_name, ETHER_HDR_LEN,
        ETHER_MAX_LEN, SPEED_MIN, LINERATE_MIN, LINERATE_MAX, SLEEP_MAX);
    exit(EXIT_SUCCESS);
}
