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

  fprintf(stderr, "*** -> Received packet of length %d \n", len);


  struct sr_if* interface_record = sr_get_interface(sr, interface);

  switch (ethertype(packet))
  {
  case ethertype_arp: /* ARP Protocol */
  {
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
      fprintf(stderr, "** ERROR: The packet has ether_type set to ARP but it's too short to contain an ARP header.\n");
      return;
    }
    sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    switch (ntohs(arp_header->ar_op))
    {
    case arp_op_request:
    {
      fprintf(stderr, "arp_op_request\n");
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
      fprintf(stderr, "arp_op_reply\n");
      if (arp_header->ar_tip == interface_record->ip)
      {
        fprintf(stderr, "arp_op_reply: my ip \n");
        /* ARP reply received. */
        /* [Step 1]. Update ARP cache */
        struct sr_arpreq* arp_req = sr_arpcache_insert(
          &sr->cache, arp_header->ar_sha, ntohl(arp_header->ar_sip));
        if (arp_req) {
          fprintf(stderr, "arp_op_reply: inserted, arp_req->ip =");
          print_addr_ip_int(htonl(arp_req->ip));
          /* [Step 2]. Send queued packets */
          struct sr_packet* packet_walker;
          for (
            packet_walker = arp_req->packets;
            packet_walker != NULL;
            packet_walker = packet_walker->next)
          {

            fprintf(stderr, "arp_op_reply: interface=%s \n", packet_walker->iface);
            sr_send_packet(sr, packet_walker->buf, packet_walker->len, packet_walker->iface);
            fprintf(stderr, "Queued packet sent. Length: %d\n", packet_walker->len);
          }
          /* [Step 3]. Destroy ARP Request */
          sr_arpreq_destroy(&sr->cache, arp_req);
        }
      }
      break;
    default:
      fprintf(stderr, "** ERROR: Unexpected ARP operation code: %d.\n", ntohs(arp_header->ar_op));
      break;
    }
    break;
  }
  case ethertype_ip: /* IP Protocol */
  {
    fprintf(stderr, "ethertype_ip\n");
    sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet;
    sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));


    /* len and checksum validate */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    {
      fprintf(stderr, "** ERROR: The packet has ether_type set to IP but it's too short to contain an IP header.\n");
      return;
    }
    if (cksum(ip_header, sizeof(sr_ip_hdr_t)) != 0xffff) {
      fprintf(stderr, "** ERROR: The packet has ether_type set to IP but failed checksum test.\n");
      return;
    }

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
        sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        switch (ip_header->ip_p)
        {
        case (ip_protocol_icmp):
        {
          /* len and checksum validate */
          if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
          {
            fprintf(stderr, "** ERROR: The packet has ether_type set to ICMP but it's too short to contain an ICMP header.\n");
            return;
          }
          if (cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != 0xffff) {
            fprintf(stderr, "** ERROR: The packet has ether_type set to ICMP but failed checksum test.\n");
            return;
          }

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
    /* Forward packet */
    forward_packet(sr, packet, len);
    return;
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
  memcpy(ethernet_header->ether_dhost, ether_mac_addr_dst, ETHER_ADDR_LEN);
  memcpy(ethernet_header->ether_shost, ether_mac_addr_src, ETHER_ADDR_LEN);

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

  char* iface = sr_find_longest_prefix(sr, ip_dst)->interface;
  /* [Step 5]. Send the packet */
  sr_send_packet(sr, reply_packet, reply_packet_len, iface);
  print_hdr_eth((uint8_t*)reply_packet);
  print_hdr_ip((uint8_t*)reply_packet + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp((uint8_t*)reply_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
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
  uint8_t* packet,
  unsigned int len)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);

  uint8_t* packet_copy = malloc(len);
  memcpy(packet_copy, packet, len);

  /* [Step1]. Creat header*/
  sr_ethernet_hdr_t* ether_header = (sr_ethernet_hdr_t*)packet_copy;
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet_copy + sizeof(sr_ethernet_hdr_t));

  fprintf(stderr, "***->Forwarding packet to: ");
  print_addr_ip_int(ntohl(ip_header->ip_dst));
  print_hdr_eth((u_int8_t*)ether_header);
  print_hdr_ip((u_int8_t*)ip_header);
  icmp_res_type_t icmp_res_type;

  /* [Step2]. Check ttl*/
  if (ip_header->ip_ttl == 1)
  {
    icmp_res_type = time_exceeded;
  }

  /* [Step3]. Check Routing table*/
  struct sr_rt* rt;
  rt = sr_find_longest_prefix(sr, ip_header->ip_dst);

  if (!rt) {
    return;
    icmp_res_type = dest_net_unreachable;
    struct sr_if* interface = sr_get_interface(sr, rt->interface);
    send_icmp_reply(
      sr,
      interface,
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

  struct sr_if* interface = sr_get_interface(sr, rt->interface);

  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_header->ip_dst);
  if (entry) {
    memcpy(ether_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memcpy(ether_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    free(entry);
  }
  else {
    fprintf(stderr, "before queue req\n");
    print_hdr_eth((u_int8_t*)ether_header);
    print_hdr_ip((u_int8_t*)ip_header);
    struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, ip_header->ip_dst, packet_copy, len, rt->interface);
    handle_arpreq(sr, req);
    return;
  }

  fprintf(stderr, "ttl=%d\n", ip_header->ip_ttl);
  ip_header->ip_ttl--;
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  print_hdr_ip((uint8_t*)ip_header);
  fprintf(stderr, "ttl=%d\n", ip_header->ip_ttl);
  sr_send_packet(sr, packet_copy, len, interface->name);
  fprintf(stderr, "ttl=%d\n", ip_header->ip_ttl);
  free(packet_copy);
}