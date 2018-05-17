/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */
	/* NAT */
	if (sr->nat_active) {
		sr_nat_init(&(sr->nat));
	}
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

	/* Get and check ethernet header */
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	if (check_hdr_len(len, ETH_HDR)) {
		return;
	}
	/* Get packet type, send to respective handler function */
	uint16_t type = ethertype((uint8_t *)eth_hdr);
	if (type == ethertype_ip) {
		/* IP packet */
		sr_handle_ip_packet(sr, packet, len, interface);
	} else if (type == ethertype_arp) {
		/* ARP packet */
		sr_handle_arp_packet(sr, packet, len, interface);
	}
}/* end sr_ForwardPacket */

/* HANDLER FUNCTIONS */
/* IP Packet Handler */
void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet,
		unsigned int len, char *iface) {
	/* Get arp cache now */
	struct sr_arpcache *cache = &sr->cache;
	/* Get headers */
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	/*sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
	sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet);*/
	uint8_t protocol = ip_protocol((uint8_t *)ip_hdr);
	/* Check length is valid */
	if (check_hdr_len(len, IP_PACKET)) {
		return;
	}
	/* Checksum */
	if (check_ip_checksum(ip_hdr)) {
		return;
	}
	
	struct sr_if *targ_if = get_router_interface(ip_hdr->ip_dst, sr);
	struct sr_rt *lpm = routing_lpm(sr, ip_hdr->ip_dst);
	
	/* Need to check if NAT is enabled, different procedures */
	if (targ_if) {
		if (sr->nat_active) {
			struct sr_if *out_if = sr_get_interface(sr, NAT_INTERNAL_IF);
			if (ip_hdr->ip_p == ip_protocol_icmp) { /* Inbound ICMP packet */
				sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
				if (icmp_hdr->icmp_type == echo_reply_type) { 
					struct sr_nat_mapping *lookup = sr_nat_lookup_external(&(sr->nat),
							icmp_hdr->icmp_id, nat_mapping_icmp);
					if (!lookup) {
						/* No mapping exists, drop the packet */
						return;
					} else {
						ip_hdr->ip_dst = lookup->ip_int;
						icmp_hdr->icmp_id = lookup->aux_int;
						icmp_hdr->icmp_sum = 0;
						icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) -
								sizeof(sr_ip_hdr_t));						
					}
					free(lookup);
				}
			} else if (ip_hdr->ip_p == ip_protocol_tcp) { /* Inbound TCP packet */
				sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet);
				struct sr_nat_mapping *lookup = sr_nat_lookup_external(&(sr->nat),
						tcp_hdr->dst_port, nat_mapping_tcp);
				if (!lookup) { /* No mapping exists ... */
					if (tcp_hdr->ctrl_bits & TCP_SYN) { 
						/* Unsolicited SYN? Wait for 6 secs */
						if (ntohs(tcp_hdr->dst_port) >= MIN_TCP_PORT) {
							sleep(6.0);
						}
						/* Send ICMP Port Unreachable */
						int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
								sizeof(sr_icmp_t3_hdr_t);
						uint8_t *newpac = malloc(paclen);
						/* Create headers */
						create_ethernet_header(eth_hdr, newpac, 
								sr_get_interface(sr, iface)->addr, eth_hdr->ether_shost,
								htons(ethertype_ip));
						create_ip_header(ip_hdr, newpac, targ_if->ip, ip_hdr->ip_src);
						create_icmp3_header(ip_hdr, newpac, port_unreachable_type,
								port_unreachable_code);
						/* Send packet */
						sr_send_packet(sr, newpac, paclen, iface);
						free(newpac);
						return;
					}
					return;
				} else { /* Mapping does exist */
					ip_hdr->ip_dst = lookup->ip_int;
					tcp_hdr->dst_port = lookup->aux_int;
					tcp_hdr->tcp_sum = 0;
					tcp_hdr->tcp_sum = cksum(tcp_hdr, sizeof(sr_tcp_hdr_t));
				}
				ip_hdr->ip_sum = 0;
				ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
				free(lookup);
			} else { /* It's UDP. Send ICMP Port Unreachable. */
				/* Send ICMP Port Unreachable */
				int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
						sizeof(sr_icmp_t3_hdr_t);
				uint8_t *newpac = malloc(paclen);
				/* Create headers */
				create_ethernet_header(eth_hdr, newpac, 
						sr_get_interface(sr, iface)->addr, eth_hdr->ether_shost,
						htons(ethertype_ip));
				create_ip_header(ip_hdr, newpac, targ_if->ip, ip_hdr->ip_src);
				create_icmp3_header(ip_hdr, newpac, port_unreachable_type,
						port_unreachable_code);
				/* Send packet */
				sr_send_packet(sr, newpac, paclen, iface);
				free(newpac);
				return;
			}			
			/* Send packet to next hop */
			struct sr_arpentry *entry = sr_arpcache_lookup(cache, ip_hdr->ip_dst);
			if (entry) { /* Found in ARP cache, next hop */
				memcpy(eth_hdr->ether_shost, out_if->addr,
						sizeof(uint8_t)*ETHER_ADDR_LEN);
				memcpy(eth_hdr->ether_dhost, entry->mac,
						sizeof(unsigned char)*ETHER_ADDR_LEN);
				sr_send_packet(sr, packet, len, NAT_INTERNAL_IF);
				return;
			} else { /* Not in ARP cache, ARP req */
				struct sr_arpreq *req = sr_arpcache_queuereq(cache,
						ip_hdr->ip_dst, packet, len, NAT_EXTERNAL_IF);
				handle_arpreq(req, sr);
				return;
			}
		} else if (ip_hdr->ip_p != ip_protocol_icmp) {
			int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
					sizeof(sr_icmp_t3_hdr_t);
			uint8_t *newpac = malloc(paclen);
			/* Create headers */
			create_ethernet_header(eth_hdr, newpac, 
					sr_get_interface(sr, iface)->addr, eth_hdr->ether_shost,
					htons(ethertype_ip));
			create_ip_header(ip_hdr, newpac, targ_if->ip, ip_hdr->ip_src);
			create_icmp3_header(ip_hdr, newpac, port_unreachable_type,
					port_unreachable_code);
			/* Send packet */
			sr_send_packet(sr, newpac, paclen, iface);
			free(newpac);
			return;
		} else { /* ICMP coming in without NAT to internal router interface */
			sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
			/* ICMP packet */
			if (check_hdr_len(len, ICMP_PACKET)) {
				return;
			}
			if (check_icmp_checksum(icmp_hdr, ICMP_PACKET, len)) {
				return;
			}
			/* Echo request? */
			if (icmp_hdr->icmp_type == icmp_echo_request) {
				echo_reply(sr, packet, len, iface);
				return;
			} else {
				/* Don't need to handle anything else */
			return;
			}
		}
	}
	if (sr->nat_active) { /* NAT enabled, new code */
		struct sr_if *out_if = sr_get_interface(sr, NAT_EXTERNAL_IF);
		sr->nat.ext_ip = out_if->ip;
		if (ip_hdr->ip_p == ip_protocol_icmp) { /* Outbound ICMP packet */
			sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
			struct sr_nat_mapping *lookup = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src,
					icmp_hdr->icmp_id, nat_mapping_icmp);
			if (!lookup) { /* Mapping doesn't exist, make one */
				lookup = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, icmp_hdr->icmp_id,
						nat_mapping_icmp);
			}
			ip_hdr->ip_src = lookup->ip_ext;
			icmp_hdr->icmp_id = lookup->aux_ext;
			icmp_hdr->icmp_sum = 0;
			icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) -
					sizeof(sr_ip_hdr_t));
			free(lookup);
		} else if (ip_hdr->ip_p == ip_protocol_tcp) { /* Outbound TCP packet */
			sr_tcp_hdr_t *tcp_hdr = get_tcp_hdr(packet);
			struct sr_nat_mapping *lookup = sr_nat_lookup_internal(&(sr->nat), ip_hdr->ip_src,
					tcp_hdr->src_port, nat_mapping_tcp);
			if (!lookup) { /* Mapping doesn't exist, make one */
				lookup = sr_nat_insert_mapping(&(sr->nat), ip_hdr->ip_src, tcp_hdr->src_port,
						nat_mapping_tcp);
			}
			ip_hdr->ip_src = lookup->ip_ext;
			tcp_hdr->src_port = lookup->aux_ext;
			
			tcp_hdr->tcp_sum = 0;
			tcp_hdr->tcp_sum = cksum(tcp_hdr, sizeof(sr_tcp_hdr_t));
			free(lookup);
		}
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		/* Send packet to next hop */
		struct sr_arpentry *entry = sr_arpcache_lookup(cache, ip_hdr->ip_dst);
		if (entry) { /* Found in ARP cache, next hop */
			memcpy(eth_hdr->ether_shost, out_if->addr,
					sizeof(uint8_t)*ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_dhost, entry->mac,
					sizeof(unsigned char)*ETHER_ADDR_LEN);
			sr_send_packet(sr, packet, len, out_if->name);
			return;
		} else { /* Not in ARP cache, ARP req */
			struct sr_arpreq *req = sr_arpcache_queuereq(cache,
					ip_hdr->ip_dst, packet, len, out_if->name);
			handle_arpreq(req, sr);
			return;
		}
	} else { /* NAT disabled, old code */
		if (targ_if) {
			if (protocol == ip_protocol_icmp) {
				sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
				/* ICMP packet */
				if (check_hdr_len(len, ICMP_PACKET)) {
					return;
				}
				if (check_icmp_checksum(icmp_hdr, ICMP_PACKET, len)) {
					return;
				}
				/* Echo request? */
				if (icmp_hdr->icmp_type == icmp_echo_request) {
					echo_reply(sr, packet, len, iface);
					return;
				} else {
					/* Don't need to handle anything else */
				return;
				}
			} else {
				/* TCP or UDP, respond with ICMP port unreachable */
				int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
						sizeof(sr_icmp_t3_hdr_t);
				uint8_t *newpac = malloc(paclen);
				/* Create headers */
				create_ethernet_header(eth_hdr, newpac, 
						sr_get_interface(sr, iface)->addr, eth_hdr->ether_shost,
						htons(ethertype_ip));
				create_ip_header(ip_hdr, newpac, targ_if->ip, ip_hdr->ip_src);
				create_icmp3_header(ip_hdr, newpac, port_unreachable_type,
						port_unreachable_code);
				/* Send packet */
				sr_send_packet(sr, newpac, paclen, iface);
				free(newpac);
				return;
			}
		} else { /* targ_if is NULL, not one of our interfaces */
			/* Check TTL */
			if (ttl_cksum(ip_hdr)) {
				/* TTL is 0, time exceeded, send packet */
				int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
						sizeof(sr_icmp_t3_hdr_t);
				uint8_t *newpac = malloc(paclen);
				/* Create headers */
				create_ethernet_header(eth_hdr, newpac, sr_get_interface(sr, iface)->addr,
						eth_hdr->ether_shost, htons(ethertype_ip));
				create_ip_header(ip_hdr, newpac, sr_get_interface(sr, iface)->ip, 
						ip_hdr->ip_src);
				create_icmp3_header(ip_hdr, newpac, time_exceeded_type,
						time_exceeded_code);
				/* Send packet */
				struct sr_arpentry *entry = sr_arpcache_lookup(cache, ip_hdr->ip_src);
				if (entry) {
					sr_send_packet(sr, newpac, paclen, iface);
				} else {
					struct sr_arpreq *req = sr_arpcache_queuereq(cache, ip_hdr->ip_src,
							newpac, paclen, iface);
					handle_arpreq(req, sr);
				}
				free(newpac);
				return;
			}
			/* Try to find in routing table */
			if (lpm) { /* Found */
				struct sr_if *out_if = sr_get_interface(sr, lpm->interface);
				struct sr_arpentry *entry = sr_arpcache_lookup(cache, 
						lpm->gw.s_addr);
				if (entry) { /* Found in ARP cache, next hop */
					memcpy(eth_hdr->ether_shost, out_if->addr,
							sizeof(uint8_t)*ETHER_ADDR_LEN);
					memcpy(eth_hdr->ether_dhost, entry->mac,
							sizeof(unsigned char)*ETHER_ADDR_LEN);
					sr_send_packet(sr, packet, len, out_if->name);
					return;
				} else { /* Not in ARP cache, ARP req */
					struct sr_arpreq *req = sr_arpcache_queuereq(cache,
							ip_hdr->ip_dst, packet, len, out_if->name);
					handle_arpreq(req, sr);
					return;
				}
			} else {
				/* Not in routing table, unreachable */ /* NO CHANGES */
				int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
						sizeof(sr_icmp_t3_hdr_t);
				uint8_t *newpac = malloc(paclen);
				/* Create headers */
				create_ethernet_header(eth_hdr, newpac, eth_hdr->ether_dhost,
						eth_hdr->ether_shost, htons(ethertype_ip));
				create_ip_header(ip_hdr, newpac, sr_get_interface(sr, iface)->ip,
						ip_hdr->ip_src);
				create_icmp3_header(ip_hdr, newpac, dest_net_unreachable_type,
						dest_net_unreachable_code);
				/* Send message */
				struct sr_rt *src = routing_lpm(sr, ip_hdr->ip_src);
				send_icmp3(newpac, src, paclen, cache, sr, iface);
				free(newpac);
				return;
			}
		}
	}
}
/* ARP Packet Handler */ /* UNCHANGED FOR NAT */
void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet,
		unsigned int len, char *iface) {
	/* Get arp cache now */
	struct sr_arpcache *cache = &sr->cache;	
	/* Get headers */
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_arp_hdr_t *arp_hdr = get_arp_hdr(packet);
	/* Check valid length */
	if (check_hdr_len(len, ARP_PACKET)) {
		return;
	}
	/* Check if we're target */
	struct sr_if *targ_if = get_router_interface(arp_hdr->ar_tip, sr);
	if (targ_if) { /* It's us */
		if (ntohs(arp_hdr->ar_op) == arp_op_request) { /* Request, reply */
			int paclen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			uint8_t *newpac = malloc(paclen);
			/* Create headers */
			create_ethernet_header(eth_hdr, newpac, 
					sr_get_interface(sr, iface)->addr, eth_hdr->ether_shost,
					htons(ethertype_arp));
			create_arp_header(arp_hdr, newpac, targ_if);
			/* Send packet */
			sr_send_packet(sr, newpac, paclen, targ_if->name);
			free(newpac);
			return;
		} else if (ntohs(arp_hdr->ar_op) == arp_op_reply) { /* Reply */
			send_arpreply(arp_hdr, cache, sr);
			return;
		}
	}
}

/* HELPER FUNCTIONS */
/* Get ethernet header */
sr_ethernet_hdr_t *get_eth_hdr(uint8_t *packet) {
	return (sr_ethernet_hdr_t *) packet;
}
/* Get ARP header */
sr_arp_hdr_t *get_arp_hdr(uint8_t *packet) {
	return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}
/* Get IP header */
sr_ip_hdr_t *get_ip_hdr(uint8_t *packet) {
	return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}
/* Get ICMP header */
sr_icmp_hdr_t *get_icmp_hdr(uint8_t *packet) {
	return (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
				sizeof(sr_ip_hdr_t));
}
/* Get TCP header */
sr_tcp_hdr_t *get_tcp_hdr(uint8_t *packet) {
	return (sr_tcp_hdr_t *) (packet + sizeof (sr_ethernet_hdr_t) +
				sizeof(sr_ip_hdr_t));
}
/* Check IP checksum */
int check_ip_checksum(sr_ip_hdr_t *hdr){
	uint16_t original = hdr->ip_sum;
	memset(&(hdr->ip_sum), 0, sizeof(uint16_t));
	uint16_t new = cksum(hdr, sizeof(sr_ip_hdr_t));
	if (original != new) {
		return 1;
	}
	return 0;
}
/* Check ICMP checksum */
int check_icmp_checksum(sr_icmp_hdr_t *hdr, int type, int len){
	if (type == ICMP_PACKET) {
		uint16_t original = hdr->icmp_sum;
		memset(&(hdr->icmp_sum), 0, sizeof(uint16_t));
		uint16_t new = cksum(hdr, len - sizeof(sr_ethernet_hdr_t) -
			sizeof(sr_ip_hdr_t));
		if (original != new) {
			return 1;
		}
	}
	return 0;
}
/* Decrement TTL and re-compute the packet checksum */
int ttl_cksum(sr_ip_hdr_t *hdr){
	hdr->ip_ttl--;
	if(hdr->ip_ttl <= 0) {
		return 1;
	} else {
		memset(&(hdr->ip_sum), 0, sizeof(uint16_t));
		hdr->ip_sum = cksum(hdr, sizeof(sr_ip_hdr_t));
	}
	return 0;
}
/* Create ethernet header with specific target */
void create_ethernet_header(sr_ethernet_hdr_t *hdr, 
		uint8_t *packet, uint8_t *src, uint8_t *targ, uint16_t type){
	sr_ethernet_hdr_t *new_hdr = get_eth_hdr(packet);
	memcpy(new_hdr->ether_shost, src, sizeof(uint8_t)*ETHER_ADDR_LEN);
	memcpy(new_hdr->ether_dhost, targ, sizeof(uint8_t)*ETHER_ADDR_LEN);
	new_hdr->ether_type = type;
}
/* Create ARP header */
void create_arp_header(sr_arp_hdr_t *hdr, uint8_t *packet,
		struct sr_if *src){
	sr_arp_hdr_t *new_hdr = get_arp_hdr(packet);
	new_hdr->ar_hrd = hdr->ar_hrd;
	new_hdr->ar_pro = hdr->ar_pro;
	new_hdr->ar_hln = hdr->ar_hln;
	new_hdr->ar_pln = hdr->ar_pln;
	new_hdr->ar_op = htons(arp_op_reply);
	memcpy(new_hdr->ar_sha, src->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
	new_hdr->ar_sip = src->ip;
	memcpy(new_hdr->ar_tha, hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
	new_hdr->ar_tip = hdr->ar_sip;
}
/* Create IP header for ICMP3 */
void create_ip_header(sr_ip_hdr_t *hdr, uint8_t *packet,
		uint32_t src, uint32_t dst) {
	sr_ip_hdr_t *new_hdr = get_ip_hdr(packet);
	new_hdr->ip_v = 4;
	new_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
	new_hdr->ip_tos = 0;
	new_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	new_hdr->ip_id = htons(0);
	new_hdr->ip_off = htons(IP_DF);
	new_hdr->ip_ttl = 64;
	new_hdr->ip_dst = dst;
	new_hdr->ip_p = ip_protocol_icmp;
	new_hdr->ip_src = src;
	new_hdr->ip_sum = 0;
	new_hdr->ip_sum = cksum(new_hdr, sizeof(sr_ip_hdr_t));
}
/* Create ICMP 3 header */
void create_icmp3_header(sr_ip_hdr_t *hdr, uint8_t *packet, uint8_t type,
		unsigned int code) {
	sr_icmp_t3_hdr_t *new_hdr = (sr_icmp_t3_hdr_t *)get_icmp_hdr(packet);
	new_hdr->icmp_type = type;
	new_hdr->icmp_code = code;
	new_hdr->unused = 0;
	new_hdr->next_mtu = 0;
	memcpy(new_hdr->data, hdr, ICMP_DATA_SIZE);
	new_hdr->icmp_sum = 0;
	new_hdr->icmp_sum = cksum(new_hdr, sizeof(sr_icmp_t3_hdr_t));
}
/* Handle ICMP echo */
void echo_reply(struct sr_instance *sr, uint8_t *packet,
		unsigned int len, char *iface){
	/* Get headers */
	sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
	sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
	sr_icmp_hdr_t *icmp_hdr = get_icmp_hdr(packet);
	/* Modify headers */
	/* Ethernet */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 
			sizeof(uint8_t)*ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, sr_get_interface(sr, iface)->addr,
			sizeof(uint8_t)*ETHER_ADDR_LEN);
	/* IP */
	uint32_t src = ip_hdr->ip_src;
	ip_hdr->ip_src = ip_hdr->ip_dst;
	ip_hdr->ip_dst = src;
	ip_hdr->ip_ttl = 64; /* Necessary to avoid error? */
	memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
	/* ICMP */
	icmp_hdr->icmp_type = echo_reply_type;
	icmp_hdr->icmp_code = echo_reply_code;
	memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
	icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) -
			sizeof(sr_ip_hdr_t));

	/* Sending */
	struct sr_arpcache *cache = &sr->cache;
	struct sr_arpentry *entry = sr_arpcache_lookup(cache, ip_hdr->ip_dst);
	if (entry) {
		sr_send_packet(sr, packet, len, iface);
	} else {
		struct sr_arpreq *req = sr_arpcache_queuereq(cache, ip_hdr->ip_dst, 
				packet, len, iface);
		handle_arpreq(req, sr);
	}
}
/* Forward ARP reply */
void send_arpreply(sr_arp_hdr_t *arp_hdr, struct sr_arpcache *arpcache, 
		struct sr_instance *sr) {
	struct sr_arpreq *req = sr_arpcache_insert(arpcache, arp_hdr->ar_sha,
			arp_hdr->ar_sip);
	if (req) {
		struct sr_packet *packet = req->packets;
		while (packet) {
			sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet->buf);
			memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, 
					sizeof(unsigned char)*ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_shost, sr_get_interface(sr, packet->iface)->addr,
					sizeof(unsigned char)*ETHER_ADDR_LEN);
			sr_send_packet(sr, packet->buf, packet->len, packet->iface);
			packet = packet->next;
		}
	}
	sr_arpreq_destroy(arpcache, req);
}
/* Check minimum length for headers */
int check_hdr_len(unsigned int len, int type) {
	switch (type) {
		case ETH_HDR:
			return len < sizeof(sr_ethernet_hdr_t);
			break;
		case ARP_PACKET:
			return len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
			break;
		case IP_PACKET:
			return len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
			break;
		case ICMP_PACKET:
			return len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
					sizeof(sr_icmp_hdr_t);
			break;
		case ICMP_TYPE3_PACKET:
			return len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
					sizeof(sr_icmp_t3_hdr_t);
			break;
		default:
			return 1;
	}
}
/* Return interface if target IP is router */
struct sr_if *get_router_interface(uint32_t ip, struct sr_instance *sr) {
	struct sr_if *iface = sr->if_list;
	while (iface) {
		if (iface->ip == ip) {
			return iface;
		}
		iface = iface->next;
	}
	return NULL;
}
/* Longest prefix matching */
struct sr_rt *routing_lpm(struct sr_instance *sr, uint32_t dst) {
	struct sr_rt *routing_table = sr->routing_table;
	int len = 0;
	struct sr_rt *cur = routing_table;
	struct sr_rt *lp = 0;
	while (cur) {
		/* Bitwise AND between subnet mask & target ip, and subnet mask & entry */
		if ((dst & cur->mask.s_addr) == (cur->dest.s_addr & cur->mask.s_addr)){
			if ((dst & cur->mask.s_addr) > len) {
				len = dst & cur->mask.s_addr;
				lp = cur;
			}
		}
		cur = cur->next;
	}
	return lp;
}
/* Send ICMP3 after LPM */
void send_icmp3(uint8_t *packet, struct sr_rt *lp, unsigned int len,
		struct sr_arpcache *arpcache, struct sr_instance *sr, char *iface) {
	if (lp) {
		/* entry must be freed if not NULL */
		struct sr_arpentry *entry = sr_arpcache_lookup(arpcache, lp->gw.s_addr);
		if (entry) {
			struct sr_if *out_if = sr_get_interface(sr, lp->interface);
			/* Modify headers */
			/* Ethernet */
			sr_ethernet_hdr_t *eth_hdr = get_eth_hdr(packet);
			memcpy(eth_hdr->ether_dhost, entry->mac,
					sizeof(uint8_t)*ETHER_ADDR_LEN);
			memcpy(eth_hdr->ether_shost, out_if->addr,
					sizeof(uint8_t)*ETHER_ADDR_LEN);
			/* IP */
			sr_ip_hdr_t *ip_hdr = get_ip_hdr(packet);
			ip_hdr->ip_src = sr_get_interface(sr, iface)->ip;
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
			/* Send and free */
			sr_send_packet(sr, packet, len, out_if->name);
			free(entry);
		} else {
			/* entry NULL, not found in ARP cache, send ARP request */
			struct sr_arpreq *req = sr_arpcache_queuereq(arpcache, 
					lp->gw.s_addr, packet, len, lp->interface);
			handle_arpreq(req, sr);
		}
	}
}
