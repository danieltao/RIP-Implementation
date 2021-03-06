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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
    pthread_t arp_thread;

    pthread_create(&arp_thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    srand(time(NULL));
    pthread_mutexattr_init(&(sr->rt_lock_attr));
    pthread_mutexattr_settype(&(sr->rt_lock_attr), PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&(sr->rt_lock), &(sr->rt_lock_attr));

    pthread_attr_init(&(sr->rt_attr));
    pthread_attr_setdetachstate(&(sr->rt_attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->rt_attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t rt_thread;
    pthread_create(&rt_thread, &(sr->rt_attr), sr_rip_timeout, sr);
    /* Add initialization code here! */

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
struct sr_rt * longest_prefix(struct sr_instance* sr, uint32_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;
	struct sr_rt *rt, *ans = NULL;
	long maxl = 0;

	for (rt = sr->routing_table; rt != NULL; rt = rt->next) {
		if (((rt->dest.s_addr & rt->mask.s_addr) == (addr.s_addr & rt->mask.s_addr)) && (maxl <= rt->mask.s_addr)) {
			maxl = rt->mask.s_addr;
			ans = rt;
		}
	}
	return ans;
}


int send_arp_request(struct sr_instance* sr, uint32_t dest_ip)
{
	struct sr_rt *rt;
	rt = longest_prefix(sr, dest_ip);
	if (rt == NULL){
		printf("RT is NUll\n");
		return DEST_NET_UNREACHABLE;
	}

	/* if rt not in the same subnet, transfer to gw instead*/
	if (rt->metric != 0){
		dest_ip = rt->gw.s_addr;
	}

	struct sr_if* interface;
	interface = sr_get_interface(sr, rt->interface);

	struct sr_arp_hdr *arp_packet;
	arp_packet = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_packet->ar_hrd = htons(arp_hrd_ethernet);
	arp_packet->ar_hln = ETHER_ADDR_LEN;
	arp_packet->ar_pln = 4/*IP_ADDR_LEN*/;
	arp_packet->ar_op = htons(arp_op_request);
	memcpy(arp_packet->ar_sha, interface->addr, ETHER_ADDR_LEN);
	arp_packet->ar_pro = htons(arp_pro_ip);
	arp_packet->ar_sip = interface->ip;
	arp_packet->ar_tip = dest_ip;

	/* pack to ethernet*/
	struct sr_ethernet_hdr *ether_packet;
	ether_packet = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(ether_packet->ether_shost, sr_get_interface(sr, interface->name)->addr, ETHER_ADDR_LEN);
	/*memset(ether_packet->ether_dhost, 255, ETHER_ADDR_LEN);
	*/
	int i;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
			ether_packet->ether_dhost[i] = 255;
	}
	ether_packet->ether_type = htons(ethertype_arp);
	int j;
	printf("ether packet destination is ");
	for (j=0;j<ETHER_ADDR_LEN;j++){
		printf("%x", ether_packet->ether_dhost[j]);
	}
	printf("\n");

	uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t), arp_packet, sizeof(sr_arp_hdr_t));
	printf("Request Sent. The longest rt for dest ip %x is %s\n", dest_ip, rt->interface);

	sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rt->interface);
	free(arp_packet);
	free(ether_packet);
	free(packet);

	return 0;
}

void send_arp_reply(struct sr_instance* sr,
		uint32_t source_ip,
		uint32_t dest_ip,
		uint8_t source_mac[ETHER_ADDR_LEN],
		uint8_t dest_mac[ETHER_ADDR_LEN])
{
	sr_arp_hdr_t *arp_packet;
	printf("Reply sent\n");
	arp_packet = (sr_arp_hdr_t*) malloc(sizeof(sr_arp_hdr_t));
	arp_packet->ar_pro = htons(arp_pro_ip);
	arp_packet->ar_hln = ETHER_ADDR_LEN;
	arp_packet->ar_pln = sizeof(uint32_t);
	arp_packet->ar_op = htons(arp_op_reply);
	memcpy(arp_packet->ar_sha, source_mac, ETHER_ADDR_LEN);
	memcpy(arp_packet->ar_tha, dest_mac, ETHER_ADDR_LEN);
	arp_packet->ar_hrd = htons(arp_hrd_ethernet);
	arp_packet->ar_sip = source_ip;
	arp_packet->ar_tip = dest_ip;


	sr_ethernet_hdr_t *ether_packet;
	ether_packet = (sr_ethernet_hdr_t*) malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(ether_packet->ether_shost, source_mac, ETHER_ADDR_LEN);
	memcpy(ether_packet->ether_dhost, dest_mac, ETHER_ADDR_LEN);
	ether_packet->ether_type = htons(ethertype_arp);

	uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t), arp_packet, sizeof(sr_arp_hdr_t));

	struct sr_rt * rt;
	rt=longest_prefix(sr, dest_ip);

	sr_send_packet(sr, packet, sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t), rt->interface);

	free(arp_packet);
	free(ether_packet);
	free(packet);
}

void send_icmp_reply(struct sr_instance* sr,
		uint16_t ip_id,
		uint32_t icmp_unused,
		uint8_t *icmp_data,
		uint16_t icmp_len,
		uint8_t source_mac[ETHER_ADDR_LEN],
		uint8_t dest_mac[ETHER_ADDR_LEN],
		uint32_t source_ip,
		uint32_t dest_ip)
{
	sr_icmp_hdr_t *icmp_reply_hdr;
	icmp_reply_hdr = malloc(icmp_len);
	icmp_reply_hdr->icmp_type = 0;
	icmp_reply_hdr->icmp_code = 0;
	icmp_reply_hdr->unused = icmp_unused;
	/* copy data to the reply packet*/
	memcpy((uint8_t*)icmp_reply_hdr + sizeof(sr_icmp_hdr_t), icmp_data, icmp_len - sizeof(sr_icmp_hdr_t));
	icmp_reply_hdr->icmp_sum = 0;
	icmp_reply_hdr->icmp_sum = cksum(icmp_reply_hdr, icmp_len);

	/* send back a ip packet containing icmp*/
	sr_ip_hdr_t *ip_packet;
	ip_packet = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_packet->ip_id = htons(ip_id);
	ip_packet->ip_off = htons(IP_DF);
	ip_packet->ip_ttl = 255;
	ip_packet->ip_p = ip_protocol_icmp;ip_packet->ip_hl = 5;
	ip_packet->ip_tos = 0;
	ip_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_packet->ip_v = 4;
	ip_packet->ip_src = source_ip;
	ip_packet->ip_dst = dest_ip;
	ip_packet->ip_sum = 0;
	ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

	/* get an overall packet*/
	sr_ethernet_hdr_t *ether_packet;
	ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(ether_packet->ether_dhost, dest_mac, ETHER_ADDR_LEN);
	memcpy(ether_packet->ether_shost, source_mac, ETHER_ADDR_LEN);
	ether_packet->ether_type = htons(ethertype_ip);

	uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len);
	memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t), ip_packet, sizeof(sr_ip_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_reply_hdr, icmp_len);

	struct sr_rt * rt = longest_prefix(sr, dest_ip);
	sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len, rt->interface);
	free(icmp_reply_hdr);
	free(ip_packet);
	free(ether_packet);
	free(packet);
}

void send_icmp_error(struct sr_instance* sr,
		uint16_t ip_id,
		uint8_t *icmp_data,
		uint16_t icmp_len,
		int icmp_exeption_type,
		uint32_t dest_ip,
		uint8_t dest_mac[ETHER_ADDR_LEN])
{
	struct sr_rt *rt = longest_prefix(sr, dest_ip);
	struct sr_if *interface;
	interface = sr_get_interface(sr, rt->interface);

	sr_icmp_hdr_t *icmp_packet;
	icmp_packet = malloc(icmp_len);

	if (icmp_exeption_type == DEST_HOST_UNREACHABLE) {
			icmp_packet->icmp_type = 3;
			icmp_packet->icmp_code = 1;}
	else if (icmp_exeption_type == DEST_NET_UNREACHABLE) {
		icmp_packet->icmp_type = 3;
		icmp_packet->icmp_code = 0;
	}else if (icmp_exeption_type == TTL_EXCEEDED) {
		icmp_packet->icmp_type = 11;
		icmp_packet->icmp_code = 0;
	}else if (icmp_exeption_type == PORT_UNREACHABLE) {
		icmp_packet->icmp_type = 3;
		icmp_packet->icmp_code = 3;
	}

	memcpy((uint8_t*)icmp_packet + sizeof(sr_icmp_hdr_t), icmp_data, icmp_len - sizeof(sr_icmp_hdr_t));
	icmp_packet->unused = 0;
	icmp_packet->icmp_sum = 0;
	icmp_packet->icmp_sum = cksum(icmp_packet, icmp_len);

	sr_ip_hdr_t *ip_packet;
	ip_packet = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
	ip_packet->ip_tos = 0;
	ip_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_len);
	ip_packet->ip_id = htons(ip_id);
	ip_packet->ip_ttl = 255;
	ip_packet->ip_p = ip_protocol_icmp;
	ip_packet->ip_v = 4;
	ip_packet->ip_hl = 5;
	ip_packet->ip_off = htons(IP_DF);
	ip_packet->ip_dst = dest_ip;
	ip_packet->ip_src = interface->ip;
	ip_packet->ip_sum = 0;
	ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));

	/* pack them to ether packet, pack to ether does not work here, unsure why*/
	sr_ethernet_hdr_t *ether_packet;
	ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
	memcpy(ether_packet->ether_dhost, dest_mac, ETHER_ADDR_LEN);
	memcpy(ether_packet->ether_shost, interface->addr, ETHER_ADDR_LEN);
	ether_packet->ether_type = htons(ethertype_ip);

	uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len);
	memcpy(packet, ether_packet, sizeof(sr_ethernet_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t), ip_packet, sizeof(sr_ip_hdr_t));
	memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_packet, icmp_len);

	sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + icmp_len, rt->interface);

	free(icmp_packet);
	free(ip_packet);
	free(ether_packet);
	free(packet);
}

int forward(struct sr_instance *sr,
		uint8_t* pac,
		uint32_t len) {
	printf("Forwarding...\n");
	uint8_t *packet = malloc(len);
	memcpy(packet, pac, len);
	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	/* check a bunch of things*/
	struct sr_rt *rt = longest_prefix(sr, ip_hdr->ip_dst);
	if (rt == NULL){
		printf("Destination Net Unreachable\n");
		return DEST_NET_UNREACHABLE;}
	printf("requiring rt->metric\n");
	if (rt->metric > 15){
		printf("Destination Net Unreachable\n");
		return DEST_NET_UNREACHABLE;
	}
	printf("successfully required rt metric");
	if (ip_hdr->ip_ttl == 1){
		printf("TTL Exceed\n");
		return TTL_EXCEEDED;
	}
	/* check ip_dst or gw*/
		uint32_t target_dst;
		if(rt->metric > 0){
			target_dst = rt->gw.s_addr;
			rt = longest_prefix(sr, target_dst);
		}else{
			target_dst = ip_hdr-> ip_dst;
		}
	/* look up in the routing table*/
	struct sr_if* interface;
	struct sr_arpreq *temp;
	interface = sr_get_interface(sr, rt->interface);
	struct sr_arpentry* entry;

	entry = sr_arpcache_lookup(&sr->cache, target_dst);
	if (entry) {
		memcpy(ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
		memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
	} else {
		temp = sr_arpcache_queuereq(&sr->cache, target_dst, packet, len, rt->interface);
		time_t curr;
		time(&curr);
		printf("Put ARP request on queue\n");
		if (difftime(curr, temp->sent) >=1)	{
			if (temp->times_sent >= 5) {
				printf("Sending all exceptions!!!\n");
				fflush(stdout);
				send_all_exceptions(sr, temp->packets);
				sr_arpreq_destroy(&(sr->cache), temp);
			} else {
				printf("temp ip is %x\n", temp->ip);
				int res = send_arp_request(sr, temp->ip);
				if (res != 0) {
					struct sr_packet* packet;
					for (packet = temp->packets; packet != NULL; packet = packet->next) {
						sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)(packet->buf);
						sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet->buf + sizeof(sr_ethernet_hdr_t));
						send_icmp_error(sr, htons(ip_hdr->ip_id) + 1, sizeof(sr_ethernet_hdr_t)+packet->buf, htons(ip_hdr->ip_len), res, ip_hdr->ip_src, ether_hdr->ether_shost);
						}
					sr_arpreq_destroy(&(sr->cache), temp);
					}
				temp->sent = curr;
				temp->times_sent++;
				}}

		return 0;
	}

	/*update checksum and ttl*/
	ip_hdr->ip_ttl--;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	sr_send_packet(sr, packet, len, rt->interface);
	free(packet);
	return 0;
}


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet /* lent */,
        unsigned int len,
        char* interface /* lent */)
{
	printf("handling packet received from interface %s \n", interface);
	assert(sr);
	assert(packet);
	assert(interface);

	char* iface = interface;

	fflush(stdout);

	sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;

	unsigned int temp_len = len;
	/* first check size*/
	if (len < sizeof(sr_ethernet_hdr_t)) {
		return;
	}
	len -= sizeof(sr_ethernet_hdr_t);


	if (ether_hdr->ether_type == htons(ethertype_ip)) { /* IP */
		if (len < sizeof(sr_ip_hdr_t)) {
			return;
		}
		len -= sizeof(sr_ip_hdr_t);
		sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xFFFF) {
				return;
		}
		struct sr_if * interface;

		if(ip_hdr->ip_p == 17){ /*is udp package*/
			sr_udp_hdr_t *udp_hdr = (sr_udp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			if(udp_hdr-> port_src == 520 && udp_hdr -> port_dst==520){
				sr_rip_pkt_t *rip_hdr = (sr_rip_pkt_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_udp_hdr_t));
				printf("about to update\n");
				update_route_table(sr, ip_hdr, rip_hdr, iface);
				return;
			}
		}

		for (interface = sr->if_list; interface != NULL; interface = interface->next){
			if (interface->ip == ip_hdr->ip_dst) { /*sent to me*/
				printf("Send to me\n");
				struct sr_rt *rt = longest_prefix(sr, ip_hdr->ip_dst);
				if (rt == NULL){
					printf("Destination Net Unreachable\n");
					return;}
				printf("routing table entry for %s has metric %d\n", rt->interface, rt->metric);
				if (rt->metric > 15){
					send_icmp_error(sr, htons(ip_hdr->ip_id) + 1, ip_hdr, htons(ip_hdr->ip_len) + sizeof(sr_icmp_hdr_t), DEST_NET_UNREACHABLE, ip_hdr->ip_src, ether_hdr->ether_shost);
					return;
				}
				if (ip_hdr->ip_p == ip_protocol_icmp) {/* is icmp message */
						/*first check*/
					printf("Is icmp message\n");
						if(len<sizeof(sr_icmp_hdr_t)){
							printf("length too short \n");
							return;
						}
						sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
						if(cksum(icmp_hdr, len) != 0xFFFF){
							printf("checksum incorrect\n");
							return;
						}
						if (icmp_hdr->icmp_type != 8) {
							/* There is an error in the network*/
							printf("there is an error in the network\n");
							return;
						}
						send_icmp_reply(sr, htons(ip_hdr->ip_id) + 1, icmp_hdr->unused, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), htons(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t),
										ether_hdr->ether_dhost, ether_hdr->ether_shost, ip_hdr->ip_dst, ip_hdr->ip_src);
						printf("sent icmp reply\n");
				} else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
						/* is tcp or udp*/
						/* print unreachable */
						send_icmp_error(sr, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len) + sizeof(sr_icmp_hdr_t), PORT_UNREACHABLE, ip_hdr->ip_src, ether_hdr->ether_shost);
						printf("sent icmp error\n");
				}
				return;
			}
		}
		/* not sent to me*/
		int res = forward(sr, packet, temp_len);
		if (res != 0) {
			/* failed to send*/
			send_icmp_error(sr, htons(ip_hdr->ip_id) + 1, packet + sizeof(sr_ethernet_hdr_t), htons(ip_hdr->ip_len) + sizeof(sr_icmp_hdr_t), res, ip_hdr->ip_src, ether_hdr->ether_shost);
		}
	} else if (ether_hdr->ether_type == htons(ethertype_arp)) {
		/* check size*/
		if (len<sizeof(sr_arp_hdr_t)){
			return;
		}
		sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		struct sr_if * interface;
		for (interface = sr->if_list; interface != NULL; interface = interface->next){
			if (interface->ip == arp_hdr->ar_tip) {/* if it is sent to me*/
 				if (arp_hdr->ar_op == htons(arp_op_request)) {/* if it is a request*/
					send_arp_reply(sr, arp_hdr->ar_tip, arp_hdr->ar_sip, interface->addr, arp_hdr->ar_sha);
				} else {
					/* if it is a reply*/
					struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
					if (req != NULL) {
						send_all_pacs(sr, req->packets);
						sr_arpreq_destroy(&(sr->cache), req);
					}
				}
				return;
			}
		}
		/* it is not sent to me*/
		/* forward the package to its destination*/
		struct sr_rt *rt = longest_prefix(sr, arp_hdr->ar_tip);
		printf("forwarding to next hop\n");
		sr_send_packet(sr, packet, temp_len, rt->interface);
	}
		printf("*** -> Received packet of length %d \n",len);
}
