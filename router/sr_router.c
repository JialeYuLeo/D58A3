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
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

 /*---------------------------------------------------------------------
 *
 * Local function declarations
 *
 *---------------------------------------------------------------------*/

void send_arp_reply(
  struct sr_instance* sr,
  uint32_t reply_sip,
  uint32_t reply_tip,
  uint8_t reply_saddr[ETHER_ADDR_LEN],
  uint8_t reply_daddr[ETHER_ADDR_LEN],
  const char* interface
);

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

void sr_handlepacket(
  struct sr_instance* sr,
  uint8_t* packet/* lent */,
  unsigned int len,
  char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  struct sr_if* interface_record = sr_get_interface(sr, interface);

  switch (ethertype(packet)) {
  case ethertype_arp: /* ARP Protocol */ {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
      printf("ERROR: The packet has ether_type set to ARP but it's too short to contain an ARP header.");
      return;
    }
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    switch (ntohs(arp_header->ar_op)) {
    case arp_op_request: {
      if (arp_header->ar_tip == interface_record->ip) {
        /* Send ARP Reply */
        send_arp_reply(
          sr,
          interface_record->ip,
          arp_header->ar_sip,
          interface_record->addr,
          arp_header->ar_sha,
          interface
        );
      }
      break;
    }
    case arp_op_reply:
      break;
    default:
      break;
    }
    break;
  }
  case ethertype_ip: /* IP Protocol */
    break;
  default:
    break;
  }
}/* end sr_ForwardPacket */


void send_arp_reply(
  struct sr_instance* sr,
  uint32_t reply_sip,
  uint32_t reply_tip,
  uint8_t reply_saddr[ETHER_ADDR_LEN],
  uint8_t reply_daddr[ETHER_ADDR_LEN],
  const char* interface
) {
  /* [Step 1]. Create ethernet header */
  sr_ethernet_hdr_t* ethernet_header = malloc(sizeof(sr_ethernet_hdr_t));

  memcpy(ethernet_header->ether_shost, reply_saddr, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_dhost, reply_daddr, ETHER_ADDR_LEN);
  ethernet_header->ether_type = htons(ethertype_arp);

  /* [Step 2]. Create ARP header */
  sr_arp_hdr_t* arp_header = malloc(sizeof(sr_arp_hdr_t));
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = ETHER_ADDR_LEN;
  arp_header->ar_pln = IP_ADDR_LEN;
  arp_header->ar_op = htons(arp_op_reply);
  memcpy(arp_header->ar_sha, reply_saddr, ETHER_ADDR_LEN);
  memcpy(arp_header->ar_tha, reply_daddr, ETHER_ADDR_LEN);
  arp_header->ar_sip = reply_sip;
  arp_header->ar_tip = reply_tip;

  /* [Step 3]. Wrap into an entire reply packet */
  int32_t reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* reply_packet = malloc(reply_packet_len);
  memcpy(reply_packet, ethernet_header, sizeof(sr_ethernet_hdr_t));
  memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), arp_header, sizeof(sr_arp_hdr_t));

  /* [Step 4]. Send the reply packet */
  sr_send_packet(sr, reply_packet, reply_packet_len, interface);
  fprintf(stderr, "ARP Reply sent\n");
  fprintf(stderr, "From: ");
  print_addr_ip_int(ntohl(arp_header->ar_sip));
  fprintf(stderr, "To: ");
  print_addr_ip_int(ntohl(arp_header->ar_tip));

  /* [Step 5]. Free the allocated memory */
  free(ethernet_header);
  free(arp_header);
  free(reply_packet);
}
