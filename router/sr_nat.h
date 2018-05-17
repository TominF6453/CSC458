
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#define NAT_INTERNAL_IF "eth1"
#define NAT_EXTERNAL_IF "eth2"

#define MAX_16B 65535
/* Can't use the common ports */
#define MIN_TCP_PORT 1024 
#define TOTAL_TCP_PORTS MAX_16B - MIN_TCP_PORT

#define TOTAL_ICMP_IDS MAX_16B - 1

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_protocol.h"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

/* enum for TCP states */
typedef enum {
	CLOSE_WAIT,
	CLOSED,
	CLOSING,
	ESTABLISHED,
	FIN_1,
	FIN_2,
	LAST_ACK,
	LISTEN,
	SYN_RCVD,
	SYN_SENT,
	TIME_WAIT
} sr_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
	uint16_t ip;
	uint16_t port;
	time_t lastup;
	uint32_t client;
	uint32_t server;
	sr_ip_hdr_t *syn;
	sr_tcp_state state;
  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  
  /* timeouts */
  unsigned int icmp_to;
  unsigned int tcp_estb_to;
  unsigned int tcp_trns_to;
  
  /* mapping */
  uint32_t ext_ip;
  uint16_t first_port;
  /*
  uint16_t free_icmp_ids[TOTAL_ICMP_IDS];
  uint16_t free_tcp_ports[TOTAL_TCP_PORTS];
	*/
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
  
int sr_nat_generate_icmp_id(struct sr_nat *nat);
int sr_nat_generate_tcp_port(struct sr_nat *nat);

#endif