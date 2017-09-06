/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@avet.com.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_NIDS_H
#define _NIDS_NIDS_H
#define NIDS_MAJOR 1
#define NIDS_MINOR 20
#include <sys/types.h>
enum
{
  NIDS_WARN_IP = 1,
  NIDS_WARN_TCP,
  NIDS_WARN_UDP,
  NIDS_WARN_SCAN
};

enum
{
  NIDS_WARN_UNDEFINED = 0,
  NIDS_WARN_IP_OVERSIZED,
  NIDS_WARN_IP_INVLIST,
  NIDS_WARN_IP_OVERLAP,
  NIDS_WARN_IP_HDR,
  NIDS_WARN_IP_SRR,
  NIDS_WARN_TCP_TOOMUCH,
  NIDS_WARN_TCP_HDR,
  NIDS_WARN_TCP_BIGQUEUE,
  NIDS_WARN_TCP_BADFLAGS
};

#define NIDS_JUST_EST 1
#define NIDS_DATA 2
#define NIDS_CLOSE 3
#define NIDS_RESET 4
#define NIDS_TIMED_OUT 5
#define NIDS_EXITING   6	/* nids is exiting; last chance to get data */

#define NIDS_DO_CHKSUM  0
#define NIDS_DONT_CHKSUM 1

struct tuple4
{
  u_short source;      // source port
  u_short dest;        // destination port
  u_int saddr;
  u_int daddr;
};

struct half_stream
{
  char state;
  char collect;
  char collect_urg;

  char *data;
  int offset;
  int count;
  int count_new;
  int bufsize;
  int rmem_alloc;

  int urg_count;
  u_int acked;
  u_int seq;
  u_int ack_seq;
  u_int first_data_seq;
  u_char urgdata;
  u_char count_new_urg;
  u_char urg_seen;
  u_int urg_ptr;
  u_short window;
  u_char ts_on;
  u_char wscale_on;
  u_int curr_ts; 
  u_int wscale;
  struct skbuff *list;
  struct skbuff *listtail;
};

struct tcp_stream
{
  struct tuple4 addr;
  char nids_state;
  struct lurker_node *listeners;
  struct half_stream client;
  struct half_stream server;
  struct tcp_stream *next_node;
  struct tcp_stream *prev_node;
  int hash_index;
  struct tcp_stream *next_time;
  struct tcp_stream *prev_time;
  int read;
  struct tcp_stream *next_free;
};

struct nids_prm
{
  int n_tcp_streams;  // Size of the hash table used for storing TCP connection information 
                      // (a maximum of 3/4 * n_tcp_streams TCP connections will be followed simultaneously). 
                      // Default value: 1024
  int n_hosts;        // Size of the hash table used for storing IP defragmentation information. Default value: 256
  char *device;       // Interface to monitor. Default value: NULL(in which case an appropriate device is determined automatically).
                      // If this variable is assigned value all, libnids will attempt to capture packets on all interfaces (which works on Linux only)
  char *filename;     // It this variable is set, libnids will call pcap_open_offline 
                      // with this variable as the argument (instead of pcap_open_live()). Default value: NULL
  int sk_buff_size;   // Size of struct sk_buff (used for queuing packets), which should be set to
                      // match the value on the hosts being monitored. Default value: 168
  int dev_addon;      // Number of bytes in struct sk_buff reserved for link-layer information. Default value: 
                      // -1 (in which case an appropriate offset if determined automatically based on link-layer type)
  void (*syslog) ();  // Syslog callback function, used to report unusual conditions, such as port scan attempts, invalid TCP header flags, etc. 
                      // Default value: nids_syslog (which logs messages via syslog without regard for message rate per second or free disk space)
  int syslog_level;   // Log level used by nids_syslog for reporting events via syslog. Default value: LOG_ALERT  
  int scan_num_hosts; // Size of hash table used for storing portscan information (the maximum number portscans that will be detected simultaneously). 
                      // If set to 0, portscan detection will be disabled. Default value: 256
  int scan_delay;     // Maximum delay (in milliseconds) between connections to different ports for them to 
                      // be identified as part of a portscan. Default value: 3000
  int scan_num_ports; // Minimum number of ports that must be scanned from the same source host before it is 
                      // identifed as a portscan. Default value: 10
  void (*no_mem) (char *); // Out-of-memory callback function, used to terminate the calling process gracefully.
  int (*ip_filter) ();// IP filtering callback function, used to selectively discard IP packets, inspected after reassembly. 
                      // If the function returns a non-zero value, the packet is processed; otherwise, it is discarded. 
                      // Default value: nids_ip_filter (which always returns 1)
  char *pcap_filter;  // pcap filter string applied to the link-layer (raw, unassembled) packets. 
                      // Note: filters like ''tcp dst port 23'' will NOT correctly handle appropriately 
                      // fragmented traffic, e.g. 8-byte IP fragments; one should add "or (ip[6:2] & 0x1fff != 0)" 
                      // at the end of the filter to process reassembled packets. Default value: NULL
  int promisc;        // If non-zero, libnids will set the interface(s) it listens on to promiscuous mode. Default value: 1
  int one_loop_less;  // Disabled by default; see comments in API.html file
  int pcap_timeout;   // Sets the pcap read timeout, which may or may not be supported by your platform. Default value: 1024.
};

int nids_init (void);
void nids_register_ip_frag (void (*));
void nids_register_ip (void (*));
void nids_register_tcp (void (*));
void nids_register_udp (void (*));
void nids_killtcp (struct tcp_stream *);
void nids_discard (struct tcp_stream *, int);
void nids_run (void);
int nids_getfd (void);
int nids_dispatch (int);
int nids_next (void);

extern struct nids_prm nids_params;
extern char *nids_warnings[];
extern char nids_errbuf[];
extern struct pcap_pkthdr *nids_last_pcap_header;

struct nids_chksum_ctl {
	u_int netaddr;
	u_int mask;
	u_int action;
	u_int reserved;
};
extern void nids_register_chksum_ctl(struct nids_chksum_ctl *, int);

#define print(A) fprintf(stderr, A);\
                 fprintf(stderr,"\n");

#define printcat(A) fprintf(stderr,A)

#endif /* _NIDS_NIDS_H */
