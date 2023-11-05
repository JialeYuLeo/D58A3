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
  const char* interface);

void set_icmp_type_and_code(
  sr_icmp_hdr_t* icmp_reply_packet,
  icmp_res_type_t icmp_res_type
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
  uint8_t* packet /* lent */,
  unsigned int len,
  char* interface /* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  struct sr_if* interface_record = sr_get_interface(sr, interface);

  switch (ethertype(packet))
  {
  case ethertype_arp: /* ARP Protocol */
  {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
      printf("** ERROR: The packet has ether_type set to ARP but it's too short to contain an ARP header.\n");
      return;
    }
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    switch (ntohs(arp_header->ar_op))
    {
    case arp_op_request:
    {
      printf("arp_op_request\n");
      if (arp_header->ar_tip == interface_record->ip)
      {
        /* ARP request received. */
        /* Send ARP Reply */
        send_arp_reply(
          sr,
          interface_record->ip,
          arp_header->ar_sip,
          interface_record->addr,
          arp_header->ar_sha,
          interface);
      }
      break;
    }
    case arp_op_reply:
      printf("arp_op_reply\n");
      if (arp_header->ar_tip == interface_record->ip)
      {
        /* ARP reply received. */
        /* [Step 1]. Update ARP cache */
        struct sr_arpreq* arp_req = sr_arpcache_insert(
          &sr->cache, arp_header->ar_sha, arp_header->ar_sip);

        /* [Step 2]. Send queued packets */
        struct sr_packet* packet_walker;
        for (
          packet_walker = arp_req->packets;
          packet_walker != NULL;
          packet_walker = packet_walker->next) {
          sr_send_packet(sr, packet_walker->buf, packet_walker->len, packet_walker->iface);
          printf("Queued packet sent. Length: %d\n", packet_walker->len);
        }
        /* [Step 3]. Destroy ARP Request */
        sr_arpreq_destroy(&sr->cache, arp_req);
      }
      break;
    default:
      printf("** ERROR: Unexpected ARP operation code: %d.\n", ntohs(arp_header->ar_op));
      break;
    }
    break;
  }
  case ethertype_ip: /* IP Protocol */
  {
    printf("ethertype_ip\n");
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* interface_walker;
    /* Check the destination */
    for (interface_walker = sr->if_list;
      interface_walker != NULL;
      interface_walker = interface_walker->next)
    {
      /* If the packet is sent to this router */
      if (interface_walker->ip == ip_header->ip_dst)
      {
        icmp_res_type_t icmp_res_type;
        switch (ip_header->ip_p)
        {
        case (ip_protocol_icmp):
        {
          icmp_res_type = echo_reply;
          break;
        }
        default: /* Assume TCP or UDP protocols */
          icmp_res_type = port_unreachable;
          break;
        }
        send_icmp_reply(
          sr,
          interface_walker,
          ether_header->ether_dhost,
          ether_header->ether_shost,
          ip_header->ip_dst,
          ip_header->ip_src,
          ip_header->ip_id,
          ip_header->ip_len,
          (uint8_t*)ip_header + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
          icmp_res_type);
        return;
      }
    }
    /* TODO: Forward packet */
    printf("Todo: Forward packet\n");

    /* TODO: If unreachable, send_icmp_reply(..., icmp_restype, ...)*/

    break;
  }
  default:
    break;
  }
} /* end sr_ForwardPacket */

void send_arp_reply(
  struct sr_instance* sr,
  uint32_t reply_sip,
  uint32_t reply_tip,
  uint8_t reply_saddr[ETHER_ADDR_LEN],
  uint8_t reply_daddr[ETHER_ADDR_LEN],
  const char* interface)
{
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

void send_icmp_reply(
  struct sr_instance* sr,
  struct sr_if* interface,
  uint8_t ether_mac_addr_src[ETHER_ADDR_LEN],
  uint8_t ether_mac_addr_dst[ETHER_ADDR_LEN],
  uint32_t ip_src,
  uint32_t ip_dst,
  uint16_t ip_id,
  uint16_t ip_len,
  uint8_t* icmp_payload,
  icmp_res_type_t icmp_res_type)
{
  /* [Step 1]. Create Ethernet header */
  sr_ethernet_hdr_t* ethernet_header = malloc(sizeof(sr_ethernet_hdr_t));

  ethernet_header->ether_type = htons(ethertype_ip);
  memcpy(ethernet_header->ether_dhost, ether_mac_addr_src, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, ether_mac_addr_dst, ETHER_ADDR_LEN);

  /* [Step 2]. Create IP header */
  sr_ip_hdr_t* ip_header = malloc(sizeof(sr_ip_hdr_t));
  ip_header->ip_src = ip_src;
  ip_header->ip_dst = ip_dst;
  ip_header->ip_v = 4;
  ip_header->ip_hl = 5;
  ip_header->ip_tos = 0;
  ip_header->ip_len = ip_len;
  ip_header->ip_id = htons(ip_id);
  ip_header->ip_off = htons(IP_DF);
  ip_header->ip_ttl = 64;
  ip_header->ip_p = ip_protocol_icmp;

  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* [Step 3]. Create ICMP header */
  uint16_t icmp_payload_len = ip_len - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
  sr_icmp_hdr_t* icmp_reply_packet = malloc(sizeof(sr_icmp_hdr_t) + icmp_payload_len);

  /* Set `icmp_reply_packet->icmp_type` and `icmp_reply_packet->icmp_code` */
  set_icmp_type_and_code(icmp_reply_packet, icmp_res_type);

  memcpy(icmp_reply_packet + sizeof(sr_icmp_hdr_t), icmp_payload, icmp_payload_len);

  icmp_reply_packet->icmp_sum = 0;
  icmp_reply_packet->icmp_sum = cksum(icmp_reply_packet, icmp_payload_len);

  /* [Step 4]. Wrap the final reply packet */
  uint32_t reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
    sizeof(sr_icmp_hdr_t) + icmp_payload_len;
  uint8_t* reply_packet = malloc(reply_packet_len);
  memcpy(reply_packet, ethernet_header, sizeof(sr_ethernet_hdr_t));
  memcpy(reply_packet + sizeof(sr_ethernet_hdr_t), ip_header, sizeof(sr_ip_hdr_t));
  memcpy(reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
    icmp_reply_packet, sizeof(sr_icmp_hdr_t) + icmp_payload_len);

  /* [Step 5]. Send the packet */
  sr_send_packet(sr, reply_packet, reply_packet_len, interface->name);

  fprintf(stderr, "ICMP Reply sent\n");
  fprintf(stderr, "From: ");
  print_addr_ip_int(ntohl(ip_header->ip_src));
  fprintf(stderr, "To: ");
  print_addr_ip_int(ntohl(ip_header->ip_dst));
}

void set_icmp_type_and_code(
  sr_icmp_hdr_t* icmp_reply_packet,
  icmp_res_type_t icmp_res_type)
{

  switch (icmp_res_type)
  {
  case (echo_reply):
  {
    icmp_reply_packet->icmp_type = 0;
    icmp_reply_packet->icmp_code = 0;
    break;
  }
  case (dest_net_unreachable):
  {
    icmp_reply_packet->icmp_type = 3;
    icmp_reply_packet->icmp_code = 0;
    break;
  }
  case (dest_host_unreachable):
  {
    icmp_reply_packet->icmp_type = 3;
    icmp_reply_packet->icmp_code = 1;
    break;
  }
  case (port_unreachable):
  {
    icmp_reply_packet->icmp_type = 3;
    icmp_reply_packet->icmp_code = 3;
    break;
  }
  case (time_exceeded):
  {
    icmp_reply_packet->icmp_type = 11;
    icmp_reply_packet->icmp_code = 0;
    break;
  }
  default:
  {
    break;
  }
  }
}

void forward_packet(struct sr_instance* sr,
  uint8_t* packet /* lent */,
  unsigned int len)
{

  /* REQUIRES */
  assert(sr);
  assert(packet);

  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)buf;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
}