/*-----------------------------------------------------------------------------
 * file:  sr_rt.h 
 * date:  Mon Oct 07 03:53:53 PDT 2002  
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H
#define MAX_NUM_ENTRIES 25
#ifdef _DARWIN_
#include <sys/types.h>
#endif

#define INFINITY 16
#include <netinet/in.h>

#include "sr_if.h"
#include "sr_protocol.h"
/* ----------------------------------------------------------------------------
 * struct sr_rt
 *
 * Node in the routing table 
 *
 * -------------------------------------------------------------------------- */

struct sr_rt
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    uint32_t metric;
    time_t updated_time;
    struct sr_rt* next;
};

/* ----------------------------------------------------------------------------
 * struct sr_udp_hdr
 *
 * udp header
 *
 * -------------------------------------------------------------------------- */
struct sr_udp_hdr {
    uint16_t port_src, port_dst; /* source and destination port_number */
    uint16_t udp_len;			/* total length */
    uint16_t udp_sum;			/* checksum */
} __attribute__ ((packed)) ;
typedef struct sr_udp_hdr sr_udp_hdr_t;

/* ----------------------------------------------------------------------------
 * struct sr_rip_pkt
 *
 * rip packet
 *
 * -------------------------------------------------------------------------- */
struct sr_rip_pkt {
	uint8_t command;
	uint8_t version;
	uint16_t unused;
	struct entry{
		uint16_t afi; /* Address Family Identifier */
		uint16_t tag; /*Route Tag */
		uint32_t address; /* IP Address */
		uint32_t mask; /* Subnet Mask */
		uint32_t next_hop; /* Next Hop */
		uint32_t metric; /* Metric */
		} entries[MAX_NUM_ENTRIES]; /* #define MAX_NUM_ENTRIES 25 */
} __attribute__ ((packed)) ;
typedef struct sr_rip_pkt sr_rip_pkt_t;

int sr_build_rt(struct sr_instance*);
int sr_load_rt(struct sr_instance*,const char*);
void sr_add_rt_entry(struct sr_instance*, struct in_addr,struct in_addr,
                  struct in_addr, uint32_t metric, char*);
void sr_print_routing_table(struct sr_instance* sr);
void sr_print_routing_entry(struct sr_rt* entry);

void *sr_rip_timeout(void *sr_ptr);
void send_rip_request(struct sr_instance *sr);
void send_rip_update(struct sr_instance *sr);
void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet, sr_rip_pkt_t* rip_packet, char* iface);
#endif  /* --  sr_RT_H -- */