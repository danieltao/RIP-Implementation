/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_utils.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int sr_load_rt(struct sr_instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];    
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        sr_add_rt_entry(sr,dest_addr,gw_addr,mask_addr,(uint32_t)0,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- sr_load_rt -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/
int sr_build_rt(struct sr_instance* sr){
    struct sr_if* interface = sr->if_list;
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    while (interface){
        dest_addr.s_addr = (interface->ip & interface->mask);
        gw_addr.s_addr = 0;
        mask_addr.s_addr = interface->mask;
        strcpy(iface, interface->name);
        sr_add_rt_entry(sr, dest_addr, gw_addr, mask_addr, (uint32_t)0, iface);
        interface = interface->next;
    }
    return 0;
}

void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask, uint32_t metric, char* if_name)
{   
    struct sr_rt* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    pthread_mutex_lock(&(sr->rt_lock));
    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct sr_rt*)malloc(sizeof(struct sr_rt));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);
        sr->routing_table->metric = metric;
        time_t now;
        time(&now);
        sr->routing_table->updated_time = now;

        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct sr_rt*)malloc(sizeof(struct sr_rt));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);
    rt_walker->metric = metric;
    time_t now;
    time(&now);
    rt_walker->updated_time = now;
    
     pthread_mutex_unlock(&(sr->rt_lock));
} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_table(struct sr_instance* sr)
{
    pthread_mutex_lock(&(sr->rt_lock));
    struct sr_rt* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        pthread_mutex_unlock(&(sr->rt_lock));
        return;
    }
    printf("  <---------- Router Table ---------->\n");
    printf("Destination\tGateway\t\tMask\t\tIface\tMetric\tUpdate_Time\n");

    rt_walker = sr->routing_table;
    
    while(rt_walker){
        if (rt_walker->metric < INFINITY)
            sr_print_routing_entry(rt_walker);
        rt_walker = rt_walker->next;
    }
    printf("--------------------------------------finish printing------------------------------\n");
    pthread_mutex_unlock(&(sr->rt_lock));


} /* -- sr_print_routing_table -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void sr_print_routing_entry(struct sr_rt* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);
    
    char buff[20];
    struct tm* timenow = localtime(&(entry->updated_time));
    strftime(buff, sizeof(buff), "%H:%M:%S", timenow);
    printf("%s\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\t",entry->interface);
    printf("%d\t",entry->metric);
    printf("%s\n", buff);

} /* -- sr_print_routing_entry -- */

uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
 {/* src_addr and dest_addr refer to IP address, buff and len are whole packet*/
         const uint16_t *buf=buff;
         uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
         uint32_t sum;
         size_t length=len;
         sum = 0;
         while (len > 1)
         {
                 sum += *buf++;
                 if (sum & 0x80000000)
                         sum = (sum & 0xFFFF) + (sum >> 16);
                 len -= 2;
        }

        if ( len & 1 )
                 sum += *((uint8_t *)buf);
        sum += *(ip_src++);
         sum += *ip_src;

         sum += *(ip_dst++);
        sum += *ip_dst;

         sum += htons(IPPROTO_UDP);
         sum += htons(length);
         while (sum >> 16)
                 sum = (sum & 0xFFFF) + (sum >> 16);
         return ((uint16_t)(~sum));
}


void *sr_rip_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    while (1) {
        sleep(5);
        printf("-------------------Called rip timeout-----------------------\n");
        pthread_mutex_lock(&(sr->rt_lock));
        /*send the RIP response packets periodically. check the routing table and remove expired route entry. If a route entry is not updated in 20 seconds, we will think it is expired. */
        /* todo: garbage collection*/
        time_t now;
        time(&now);
        struct sr_rt* rt_walker = 0;
        struct sr_rt* rt_walker_prev = 0;
		if(sr->routing_table == 0){
			pthread_mutex_unlock(&(sr->rt_lock));
			continue;
		}

		int expiretime = 20;

		rt_walker_prev = sr->routing_table;
		while(rt_walker_prev->updated_time + expiretime < now){
			sr->routing_table = rt_walker_prev->next;
			free(rt_walker_prev);
			rt_walker_prev = sr->routing_table;
			if(!rt_walker_prev){
				printf("all entries discarded! \n");
				send_rip_update(sr);
				pthread_mutex_unlock(&(sr->rt_lock));
				continue;
			}
		}
		rt_walker = rt_walker_prev -> next;
		while(rt_walker){
			if (rt_walker->updated_time + expiretime < now){
				rt_walker_prev -> next = rt_walker->next;
				free(rt_walker);
			}
			rt_walker_prev = rt_walker_prev->next;
			if(!rt_walker_prev){
				send_rip_update(sr);
				pthread_mutex_unlock(&(sr->rt_lock));
				continue;
			}
			rt_walker = rt_walker_prev -> next;
		}
		printf("---------------------Finish rip timeout------------------------\n");

		send_rip_update(sr);
        pthread_mutex_unlock(&(sr->rt_lock));
    }
    return NULL;
}

void send_rip_request(struct sr_instance *sr){
    /* You should send RIP request packets using UDP broadcast here.
     * This function is called when the program started.
*/

    printf("---------------------Called rip request------------------------\n");
	struct sr_if * interface;
	interface = sr -> if_list;

	while(interface){ /* broadcast*/
		/* set up rip packet*/
		sr_rip_pkt_t * packet = (sr_rip_pkt_t *) malloc(sizeof(sr_rip_pkt_t));
		packet -> command = 1;
		packet -> version = 2;
		packet -> entries[0].afi = 0;
		packet -> entries[0].address = 0;
		packet -> entries[0].mask = 0;
		packet -> entries[0].metric = 16;
		packet -> entries[0].tag = 0;
		packet -> entries[0].next_hop = 0;

		/* config udp header */
		sr_udp_hdr_t *udp = (sr_udp_hdr_t *) malloc(sizeof(sr_udp_hdr_t));
		udp -> port_src = 520;
		udp -> port_dst = 520;
		udp -> udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
		udp -> udp_sum = 0;
		udp -> udp_sum = udp_checksum(udp, sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t), interface->ip, 0xe0000009 /*224.0.0.9*/);

		/* config IP header */
		sr_ip_hdr_t *ip_packet;
		ip_packet = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
		ip_packet->ip_tos = 0;
		ip_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + udp->udp_len);
		ip_packet->ip_id = 1;
		ip_packet->ip_ttl = 255;
		ip_packet->ip_p = 17 /*UDP*/;
		ip_packet->ip_v = 4;
		ip_packet->ip_hl = 5;
		ip_packet->ip_off = htons(IP_DF);
		ip_packet->ip_dst = 0xe0000009 /*224.0.0.9*/;
		ip_packet->ip_src = interface->ip;
		ip_packet->ip_sum = 0;
		ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));
		/* config ether header */
		struct sr_ethernet_hdr *ether_packet;
		ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
		memset(ether_packet->ether_dhost, 255, ETHER_ADDR_LEN);
		memcpy(ether_packet->ether_shost, sr_get_interface(sr, interface->name)->addr, ETHER_ADDR_LEN);
		ether_packet->ether_type = htons(ethertype_ip);

		/* combine everything together */
		uint8_t * msg = malloc(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		memcpy(msg, ether_packet, sizeof(sr_ethernet_hdr_t));
		msg += sizeof(sr_ethernet_hdr_t);
		memcpy(msg, ip_packet, sizeof(sr_ip_hdr_t));
		msg += sizeof(sr_ip_hdr_t);
		memcpy(msg, udp, sizeof(sr_udp_hdr_t));
		memcpy(msg + sizeof(sr_udp_hdr_t), packet, sizeof(sr_rip_pkt_t));

		sr_send_packet(sr, msg - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), interface->name);

		/* garbage collection*/
		free(msg- sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		free(ether_packet);
		free(ip_packet);
		free(udp);
		free(packet);
		interface = interface -> next;
	}
	printf("---------------------Finish rip request------------------------\n");

}



void send_rip_update(struct sr_instance *sr){
    pthread_mutex_lock(&(sr->rt_lock));
    /*You should call it when you receive a RIP request packet or in the sr_rip_timeout function. You should enable split horizon here to prevent count-to-infinity problem. */

    printf("----------------------Called rip update--------------------------------\n");
    /* broadcast */
    struct sr_if * bi;
    bi = sr -> if_list;
    while(bi){
		/* look at routing table*/
		struct sr_rt * rt = sr -> routing_table;
		int i = 0;

		/* set up rip packet*/
		sr_rip_pkt_t * packet = (sr_rip_pkt_t *) malloc(sizeof(sr_rip_pkt_t));
		packet -> command = 2;
		packet -> version = 2;
		while(rt){
			/* split horizon ----- double check*/
			if(strcmp(rt -> interface, bi -> name)==0){
				/* if next hop and destination is in the same subnet, and I am sending the package to the next hop router*/
				rt = rt->next;
				continue;
			}
			packet -> entries[i].afi = 2;
			packet -> entries[i].address = rt -> dest.s_addr;
			packet -> entries[i].mask = rt -> mask.s_addr;
			packet -> entries[i].metric = rt -> metric;
			packet -> entries[i].tag = 2;
			packet -> entries[i].next_hop = rt -> gw.s_addr;
		/*	printf("from interface %s     address:%x  mask:%x  metric:%d  next_hop:%x\n", bi -> name, rt -> dest.s_addr, rt -> mask.s_addr, rt -> metric, rt -> gw.s_addr);
		*/	i ++;
			rt = rt->next;
		}
		for(i; i<25;i++){
			packet -> entries[i].afi = 2;
			packet -> entries[i].address = 0;
			packet -> entries[i].mask = 0;
			packet -> entries[i].metric = 100;
			packet -> entries[i].tag = 0;
			packet -> entries[i].next_hop = 0;
		}
		/* config udp header */
		sr_udp_hdr_t *udp = (sr_udp_hdr_t *) malloc(sizeof(sr_udp_hdr_t));
		udp -> port_src = 520;
		udp -> port_dst = 520;
		udp -> udp_len = htons(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t));
		udp -> udp_sum = 0;
		udp -> udp_sum = udp_checksum(udp, sizeof(sr_udp_hdr_t)+sizeof(sr_rip_pkt_t), bi->ip, 0xe0000009 /*224.0.0.9*/);
		/* config IP header */
		sr_ip_hdr_t *ip_packet;
		ip_packet = (sr_ip_hdr_t*) malloc(sizeof(sr_ip_hdr_t));
		ip_packet->ip_tos = 0;
		ip_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + udp->udp_len);
		ip_packet->ip_id = 1;
		ip_packet->ip_ttl = 255;
		ip_packet->ip_p = 17 /*UDP*/;
		ip_packet->ip_v = 4;
		ip_packet->ip_hl = 5;
		ip_packet->ip_off = htons(IP_DF);
		ip_packet->ip_dst = 0xe0000009 /*224.0.0.9*/;
		ip_packet->ip_src = bi->ip;
		ip_packet->ip_sum = 0;
		ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));
		/* config ether header */
		struct sr_ethernet_hdr *ether_packet;
		ether_packet = (sr_ethernet_hdr_t*)malloc(sizeof(sr_ethernet_hdr_t));
		memset(ether_packet->ether_dhost, 255, ETHER_ADDR_LEN);
		memcpy(ether_packet->ether_shost, bi->addr, ETHER_ADDR_LEN);
		ether_packet->ether_type = htons(ethertype_ip);

		/* combine everything together */
		uint8_t * msg = malloc(sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		memcpy(msg, ether_packet, sizeof(sr_ethernet_hdr_t));
		msg += sizeof(sr_ethernet_hdr_t);
		memcpy(msg, ip_packet, sizeof(sr_ip_hdr_t));
		msg += sizeof(sr_ip_hdr_t);
		memcpy(msg, udp, sizeof(sr_udp_hdr_t));
		memcpy(msg + sizeof(sr_udp_hdr_t), packet, sizeof(sr_rip_pkt_t));

		sr_send_packet(sr, msg- sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t), sizeof(sr_udp_hdr_t) + sizeof(sr_rip_pkt_t)+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), bi -> name);
		printf("message sent from %s\n", bi->name);
		/* garbage collection*/
		free(msg- sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
		free(ether_packet);
		free(ip_packet);
		free(udp);
		free(packet);
		bi = bi -> next;
    }
	printf("---------------------Finish rip update------------------------\n");

	pthread_mutex_unlock(&(sr->rt_lock));
}


void update_route_table(struct sr_instance *sr, sr_ip_hdr_t* ip_packet ,sr_rip_pkt_t* rip_packet, char* iface){
	pthread_mutex_lock(&(sr->rt_lock));
    printf("-----------Called update route table---------------------------------\n");

    uint8_t cmd = rip_packet->command;

    uint32_t src_addr = ip_packet->ip_src;

	sr_print_routing_table(sr);
    int update = 0;

    if(cmd == 1){
    	send_rip_update(sr);
    	pthread_mutex_unlock(&(sr->rt_lock));
    	return;
    }

    int i;
    for(i = 0; i < MAX_NUM_ENTRIES; i++){
    	uint32_t new_dst = rip_packet->entries[i].address;    /*the dst*/
    	uint32_t new_metric = rip_packet->entries[i].metric;
    	uint32_t new_mask = rip_packet->entries[i].mask;
        /*use tag to see if the entries come to an end(empty entry)*/
        if(rip_packet -> entries[i].tag==0 | new_dst==0 | new_mask == 0 | new_metric >= 16)
        	continue;


        int hasRoute = 0; /*bool to check if current routing table has route to dest in rip entry*/

        struct sr_rt* rt_iter;

        for(rt_iter = sr->routing_table; rt_iter!=NULL; rt_iter = rt_iter->next){
        	uint32_t current_dst = rt_iter->dest.s_addr;
        	uint32_t current_gw = rt_iter->gw.s_addr;
        	uint32_t current_metric = rt_iter->metric;

        	if(new_dst == current_dst){

				hasRoute = 1; /* no need to add new entry*/
	/*			printf("Destination already in rt\n");
*/
        		uint32_t updated_metric = new_metric + 1;
        		if(updated_metric < current_metric && updated_metric < 16){ /*when equal, update??*/
        			update = 1;
        			struct in_addr updated_gw;
        			updated_gw.s_addr = src_addr;

        			rt_iter->gw = updated_gw;
        			rt_iter->metric = updated_metric;

        			time_t now;
        			time(&now);
        			rt_iter->updated_time = now;/* need to get current time*/

        			memcpy(rt_iter->interface, iface, 32);
        			/*rt_iter->interface = iface;*/
        		}
        	}
        }

        if(hasRoute == 0){
        	update = 1;
    /*    	printf("Destination not in rt yet\n");
      */  	struct in_addr add_dst;
        	add_dst.s_addr = new_dst;
        	struct in_addr add_gw;
        	add_gw.s_addr = src_addr;
        	struct in_addr add_mask;
        	add_mask.s_addr = new_mask;
        	/* the interface of the new entry should use iface?*/
        	/* which mask to use?*/
        	uint32_t add_metric = 1 + new_metric;
        	if(add_metric > 16)
        		add_metric = 16;

        	sr_add_rt_entry(sr, add_dst, add_gw, add_mask, add_metric, iface);
        }

   /*     printf("attributes received from %s: dest: %x, metric: %d, mask: %x\n", iface, new_dst, new_metric, new_mask);
    */}

    struct sr_rt* rt_iter;
    for(rt_iter = sr->routing_table; rt_iter!=NULL; rt_iter = rt_iter->next){
        	time_t now;
        	time(&now);
        	rt_iter->updated_time = now;
    }
	printf("---------------------Finish rip routing table------------------------\n");

    if(update==1){
    	send_rip_update(sr);
    }

    pthread_mutex_unlock(&(sr->rt_lock));
}
