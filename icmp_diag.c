/*
 * Simple ICMP‐based network diagnostic suite
 *
 * This program implements two common network diagnostic tools: ping and
 * traceroute.  It is intentionally designed to be straightforward so that
 * students can follow the logic without needing to understand advanced
 * programming techniques.  The code uses raw ICMP sockets for both IPv4
 * and IPv6.  Because raw sockets require administrative privileges, this
 * program must be run with superuser rights (see the Swarthmore lab notes
 * on raw sockets【395386799409465†L8-L13】).  The ping mode sends a series of
 * ICMP echo requests to a destination and reports round‑trip times and
 * packet loss.  The traceroute mode manipulates the TTL (time‑to‑live)
 * field of the outgoing packets to discover the routers along the path
 * towards the destination【395386799409465†L344-L377】.
 *
 * Usage examples:
 *   sudo ./icmp_diag ping example.com 8.8.8.8
 *   sudo ./icmp_diag traceroute example.com
 *
 * The first argument selects the mode ("ping" or "traceroute").  One or
 * more destinations may follow.  When multiple destinations are given,
 * the program loops over each and performs the requested diagnostic.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
/*
 * Include system networking headers for portability.  On some systems,
 * such as macOS and BSD, the IPv4 and ICMP header structures differ
 * from Linux.  We include <netinet/ip.h> and <netinet/ip_icmp.h> for
 * IPv4 and <netinet/icmp6.h> for IPv6.  We also include <stdint.h> for
 * fixed width integer types used in our fallback structures.
 */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdint.h>

/* Fallback definitions for ICMP types when the platform does not
 * provide them.  RFC 792 defines type 8 as Echo Request and type 0
 * as Echo Reply for IPv4.  RFC 4443 defines type 128 as Echo Request
 * and type 129 as Echo Reply for IPv6.
 */
#ifndef ICMP_ECHO
#define ICMP_ECHO      8
#define ICMP_ECHOREPLY 0
#endif
#ifndef ICMP6_ECHO_REQUEST
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129
#endif

/* Minimal ICMP header for IPv4.  Some platforms only forward declare
 * struct icmphdr; by defining our own structure we avoid incomplete
 * type errors.  This header contains only the fields needed by this
 * program: type, code, checksum, identifier and sequence number.
 */
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} IcmpHeader;

/* Minimal ICMP header for IPv6.  The fields mirror those of the
 * official struct icmp6_hdr (type, code, checksum, id, seq).  We use
 * this structure to avoid depending on platform specific definitions.
 */
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} Icmp6Header;

/* Compute the Internet checksum (RFC 1071) for IPv4 ICMP.  The checksum is
 * the 16‑bit one's complement of the one's complement sum of the ICMP
 * header and payload.  This function is borrowed from many examples
 * online (see GeeksforGeeks ping example【933600446301287†L161-L189】) and is
 * reused here for both ping and traceroute.  For ICMPv6 the kernel can
 * compute the checksum if we set IPV6_CHECKSUM (see code below).
 */
static unsigned short checksum(const void *data, int len)
{
    unsigned long sum = 0;
    const unsigned short *ptr = data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *((const unsigned char *)ptr);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

/* Helper to get current time in milliseconds as a double. */
static double now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

/* Resolve a hostname to a list of addrinfo structures.  The hints specify
 * that we allow both IPv4 and IPv6, use raw sockets, and leave the
 * protocol unspecified so that we can fill it later depending on whether
 * we create an ICMP or UDP socket.  Returns 0 on success or a negative
 * error code.  On success, *res_out points to a linked list of
 * addrinfo nodes that should be freed with freeaddrinfo().
 */
static int resolve_host(const char *host, struct addrinfo **res_out)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_RAW;     /* We will create raw sockets */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;            /* Any protocol */
    int ret = getaddrinfo(host, NULL, &hints, res_out);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(ret));
        return -1;
    }
    return 0;
}

/* Send one ICMP echo request and wait for a reply.  This function takes a
 * socket descriptor 'sockfd' that has already been created for the
 * appropriate address family.  The addr points to the remote peer.
 * sequence and id identify this request; id can be a per‑process value
 * like getpid() & 0xFFFF.  The function returns the round‑trip time in
 * milliseconds if a reply is received, or -1 if timed out or error.  It
 * also returns in *lost whether the packet was considered lost (1 for
 * lost, 0 for success).  This routine works for both IPv4 and IPv6 by
 * switching on addr->sa_family.
 */
static double send_echo(int sockfd, const struct sockaddr *addr, socklen_t addrlen,
                        int id, int seq, int timeout_ms, int *lost)
{
    /* prepare buffer for ICMP header and small payload */
    unsigned char buf[64];
    ssize_t pkt_len = 0;
    if (addr->sa_family == AF_INET) {
        IcmpHeader *icmp = (IcmpHeader *)buf;
        memset(buf, 0, sizeof(buf));
        icmp->type = ICMP_ECHO;
        icmp->code = 0;
        icmp->id = htons(id);
        icmp->sequence = htons(seq);
        /* Put some pattern in payload */
        const char *payload = "ICMPDIAG";
        size_t payload_len = strlen(payload);
        memcpy(buf + sizeof(IcmpHeader), payload, payload_len);
        pkt_len = sizeof(IcmpHeader) + payload_len;
        icmp->checksum = 0;
        icmp->checksum = checksum(buf, pkt_len);
    } else if (addr->sa_family == AF_INET6) {
        Icmp6Header *icmp6 = (Icmp6Header *)buf;
        memset(buf, 0, sizeof(buf));
        icmp6->type = ICMP6_ECHO_REQUEST;
        icmp6->code = 0;
        icmp6->id = htons(id);
        icmp6->sequence = htons(seq);
        /* Add some payload */
        const char *payload = "ICMPDIAG";
        size_t payload_len = strlen(payload);
        memcpy(buf + sizeof(Icmp6Header), payload, payload_len);
        pkt_len = sizeof(Icmp6Header) + payload_len;
        /* The kernel will compute the checksum when IPV6_CHECKSUM is set */
    } else {
        fprintf(stderr, "Unsupported address family\n");
        *lost = 1;
        return -1.0;
    }
    double send_time = now_ms();
    if (sendto(sockfd, buf, pkt_len, 0, addr, addrlen) < 0) {
        perror("sendto");
        *lost = 1;
        return -1.0;
    }
    /* Wait for reply with timeout */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) {
        *lost = 1;
        return -1.0;
    }
    /* Receive the packet */
    unsigned char rbuf[1024];
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    ssize_t r = recvfrom(sockfd, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&from, &fromlen);
    double recv_time = now_ms();
    if (r <= 0) {
        *lost = 1;
        return -1.0;
    }
    /* Verify this is our echo reply */
    if (from.ss_family == AF_INET) {
        /* The lower four bits of the first byte give the IPv4 header length in 32‑bit words. */
        int iphdr_len = (rbuf[0] & 0x0F) * 4;
        IcmpHeader *icmp = (IcmpHeader *)(rbuf + iphdr_len);
        if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->id) == id
            && ntohs(icmp->sequence) == seq) {
            *lost = 0;
            return recv_time - send_time;
        }
    } else if (from.ss_family == AF_INET6) {
        Icmp6Header *icmp6 = (Icmp6Header *)rbuf;
        if (icmp6->type == ICMP6_ECHO_REPLY &&
            ntohs(icmp6->id) == id &&
            ntohs(icmp6->sequence) == seq) {
            *lost = 0;
            return recv_time - send_time;
        }
    }
    /* Not a matching reply */
    *lost = 1;
    return -1.0;
}

/* Run the ping diagnostic for a single host.  Performs a fixed number of
 * echo requests (count) with a given interval between them.  At the end
 * prints a summary similar to the standard ping tool.  Uses raw ICMP
 * sockets and works for both IPv4 and IPv6.
 */
static void do_ping(const char *host)
{
    printf("\nPING %s:\n", host);
    struct addrinfo *res;
    if (resolve_host(host, &res) != 0) {
        return;
    }
    /* Iterate over resolved addresses and try to ping each until one
     * succeeds in sending.  If one fails to create a socket we move
     * on to the next.
     */
    int sent = 0, received = 0;
    double total_rtt = 0.0;
    int id = getpid() & 0xFFFF;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int sockfd;
        if (ai->ai_family == AF_INET) {
            sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        } else if (ai->ai_family == AF_INET6) {
            sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            /* Tell kernel to compute checksum at offset 2 in ICMPv6 header */
            int offset = 2;
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_CHECKSUM,
                       &offset, sizeof(offset));
        } else {
            continue;
        }
        if (sockfd < 0) {
            perror("socket");
            continue;
        }
        /* Set receive timeout of 1 second for the socket */
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        int count = 4;
        for (int seq = 0; seq < count; ++seq) {
            int lost;
            double rtt = send_echo(sockfd, ai->ai_addr, ai->ai_addrlen,
                                   id, seq, 1000, &lost);
            sent++;
            if (!lost) {
                received++;
                total_rtt += rtt;
                /* Print line for this reply */
                char addrstr[NI_MAXHOST];
                getnameinfo(ai->ai_addr, ai->ai_addrlen,
                            addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
                printf("Reply from %s: seq=%d rtt=%.2f ms\n",
                       addrstr, seq, rtt);
            } else {
                printf("Request timeout for seq %d\n", seq);
            }
            usleep(500000); /* half second between pings */
        }
        close(sockfd);
        break; /* Only use the first successful address */
    }
    freeaddrinfo(res);
    /* Summary */
    int lost_pkts = sent - received;
    double loss_pct = sent ? ((double)lost_pkts * 100.0 / sent) : 0.0;
    double avg_rtt = received ? (total_rtt / received) : 0.0;
    printf("\n--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
           sent, received, loss_pct);
    if (received)
        printf("average rtt = %.2f ms\n", avg_rtt);
}

/* Run the traceroute diagnostic for a single host.  Uses ICMP echo
 * requests with increasing TTL (IPv4) or hop limit (IPv6) to find each
 * router along the path.  For simplicity, we send one probe per hop and
 * stop after either reaching the destination or hitting the maximum
 * number of hops.  The timeout per hop is 3 seconds, following
 * conventions described in the Swarthmore lab【395386799409465†L344-L377】.  If no
 * reply is received within the timeout, an asterisk is printed.
 */
static void do_traceroute(const char *host)
{
    printf("\nTraceroute to %s:\n", host);
    struct addrinfo *res;
    if (resolve_host(host, &res) != 0) {
        return;
    }
    int max_hops = 30;
    int id = getpid() & 0xFFFF;
    for (struct addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
        int sockfd;
        if (ai->ai_family == AF_INET) {
            sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        } else if (ai->ai_family == AF_INET6) {
            sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            int offset = 2;
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_CHECKSUM,
                       &offset, sizeof(offset));
        } else {
            continue;
        }
        if (sockfd < 0) {
            perror("socket");
            continue;
        }
        /* Loop over TTL values */
        for (int ttl = 1; ttl <= max_hops; ++ttl) {
            /* Set TTL/hop limit */
            if (ai->ai_family == AF_INET) {
                setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
            } else {
                setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                           &ttl, sizeof(ttl));
            }
            /* Send echo request with this TTL */
            int lost;
            double send_time = now_ms();
            unsigned char buf[64];
            size_t pkt_len;
            if (ai->ai_family == AF_INET) {
                IcmpHeader *icmp = (IcmpHeader *)buf;
                memset(buf, 0, sizeof(buf));
                icmp->type = ICMP_ECHO;
                icmp->code = 0;
                icmp->id = htons(id);
                icmp->sequence = htons(ttl);
                const char *payload = "TRACE";
                size_t payload_len = strlen(payload);
                memcpy(buf + sizeof(IcmpHeader), payload, payload_len);
                pkt_len = sizeof(IcmpHeader) + payload_len;
                icmp->checksum = 0;
                icmp->checksum = checksum(buf, pkt_len);
            } else {
                Icmp6Header *icmp6 = (Icmp6Header *)buf;
                memset(buf, 0, sizeof(buf));
                icmp6->type = ICMP6_ECHO_REQUEST;
                icmp6->code = 0;
                icmp6->id = htons(id);
                icmp6->sequence = htons(ttl);
                const char *payload = "TRACE";
                size_t payload_len = strlen(payload);
                memcpy(buf + sizeof(Icmp6Header), payload, payload_len);
                pkt_len = sizeof(Icmp6Header) + payload_len;
            }
            if (sendto(sockfd, buf, pkt_len, 0, ai->ai_addr, ai->ai_addrlen) < 0) {
                perror("sendto");
                break;
            }
            /* Wait for reply */
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec = 3;
            tv.tv_usec = 0;
            int ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
            if (ret <= 0) {
                printf("%2d  *\n", ttl);
                continue;
            }
            unsigned char rbuf[1024];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            ssize_t r = recvfrom(sockfd, rbuf, sizeof(rbuf), 0,
                                 (struct sockaddr *)&from, &fromlen);
            double recv_time = now_ms();
            if (r <= 0) {
                printf("%2d  *\n", ttl);
                continue;
            }
            /* Determine the hop address */
            char addrstr[NI_MAXHOST];
            getnameinfo((struct sockaddr *)&from, fromlen,
                        addrstr, sizeof(addrstr), NULL, 0, NI_NUMERICHOST);
            /* Parse packet to see if it is time exceeded or echo reply */
            int done = 0;
            if (from.ss_family == AF_INET) {
                int iphdr_len = (rbuf[0] & 0x0F) * 4;
                IcmpHeader *icmp = (IcmpHeader *)(rbuf + iphdr_len);
                if (icmp->type == ICMP_ECHOREPLY &&
                    ntohs(icmp->id) == id &&
                    ntohs(icmp->sequence) == ttl) {
                    done = 1;
                }
            } else if (from.ss_family == AF_INET6) {
                Icmp6Header *icmp6 = (Icmp6Header *)rbuf;
                if (icmp6->type == ICMP6_ECHO_REPLY &&
                    ntohs(icmp6->id) == id &&
                    ntohs(icmp6->sequence) == ttl) {
                    done = 1;
                }
            }
            printf("%2d  %s  %.2f ms\n", ttl, addrstr, recv_time - send_time);
            if (done) {
                /* reached destination */
                break;
            }
        }
        close(sockfd);
        break;
    }
    freeaddrinfo(res);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <ping|traceroute> <destination1> [destination2 ...]\n",
                argv[0]);
        return 1;
    }
    /* Determine mode */
    int is_ping = 0, is_trace = 0;
    if (strcmp(argv[1], "ping") == 0) {
        is_ping = 1;
    } else if (strcmp(argv[1], "traceroute") == 0) {
        is_trace = 1;
    } else {
        fprintf(stderr, "First argument must be 'ping' or 'traceroute'\n");
        return 1;
    }
    /* Loop over all destinations */
    for (int i = 2; i < argc; ++i) {
        if (is_ping) {
            do_ping(argv[i]);
        } else {
            do_traceroute(argv[i]);
        }
    }
    return 0;
}