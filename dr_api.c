/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 20

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */

/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */

/**
        Instantiates the routing table with the interface 0's entries.
        Returns NULL if there are no interfaces
*/
void dump_routing_table(route_t *rtable_head)
{
	route_t *curr = rtable_head;
	fprintf(stdout,"Subnet \t Next Hop IP \t Outgoing Interface \t Cost \t \n");
	while(curr!=NULL)
	{
		fprintf(stdout,"%d \t %d \t %d \t %d \t\n",curr->subnet,curr->next_hop_ip,curr->outgoing_intf,curr->cost);
		curr = curr->next;
	}
}

void init_directly_conn_networks(route_t *rtable_curr)
{
	int interface_iter;
	if(dr_interface_count() <=0)
		return ;
	else
	{
		for(interface_iter = 1;interface_iter<dr_interface_count();interface_iter++)
		{
			lvns_interface_t interface_curr = dr_get_interface(interface_iter);
			route_t * route_table_entry = (route_t*) malloc(sizeof(route_t));
			route_table_entry->subnet = interface_curr.ip & interface_curr.subnet_mask;
			route_table_entry->next_hop_ip = 0;
			route_table_entry->outgoing_intf = 0;
			route_table_entry->cost = interface_curr.cost;
			route_table_entry->is_garbage=0;
			route_table_entry->next=NULL;
			rtable_curr->next = route_table_entry;	
		}
	}
}
struct route_t * dr_routing_table_init()
{
        fprintf(stdout,"Performing routing table initialization\n");
        if (dr_interface_count() <=0)
                return NULL;
        else
        {
                lvns_interface_t interface_0 = dr_get_interface(0);
                route_t *route_table_head = (route_t*) malloc(sizeof(route_t));
		route_table_head->subnet = interface_0.ip & interface_0.subnet_mask;
		route_table_head->next_hop_ip = 0;
		route_table_head->outgoing_intf=0;
		route_table_head->cost = interface_0.cost;
		route_table_head->is_garbage = 0;
		route_table_head->next = NULL;
		return route_table_head;
        }
}


void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn");
        exit(1);
    }

    /* do initialization of your own data structures here */
    route_t *rtable_head = dr_routing_table_init();
    route_t *rtable_current = rtable_head;
    dump_routing_table(rtable_head);
    init_directly_conn_networks(rtable_current);
}

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;

    hop.interface = 0;
    hop.dst_ip = 0;

    /* determine the next hop in order to get to ip */

    return hop;
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* handle the dynamic routing payload in the buf buffer */
}

void safe_dr_handle_periodic() {
    /* handle periodic tasks for dynamic routing here */
}

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
}

/* definition of internal functions */
