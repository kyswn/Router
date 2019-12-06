/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  ethernet_hdr *ehdr = (ethernet_hdr*)malloc(sizeof(ethernet_hdr));
  memcpy(ehdr, packet.data(), sizeof(ethernet_hdr));

  if (ntohs(ehdr->ether_type) == ethertype_arp) {

    arp_hdr *ahdr = (arp_hdr*)malloc(sizeof(arp_hdr));
    memcpy(ahdr, packet.data() + sizeof(ethernet_hdr), sizeof(arp_hdr));

    if (ntohs(ahdr->arp_op) == arp_op_request) {
      // Handle ARP request
      if (ahdr->arp_tip == iface->ip) {
        // Send ARP response
        ethernet_hdr *ehdr_res = (ethernet_hdr*)malloc(sizeof(ethernet_hdr));
        memcpy(ehdr_res->ether_dhost, ehdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(ehdr_res->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        ehdr_res->ether_type = htons(ethertype_arp);

        arp_hdr *ahdr_res = (arp_hdr*)malloc(sizeof(arp_hdr));
        ahdr_res->arp_hrd = htons(arp_hrd_ethernet);
        ahdr_res->arp_pro = htons(ethertype_ip);
        ahdr_res->arp_hln = ETHER_ADDR_LEN;
        ahdr_res->arp_pln = 4;
        ahdr_res->arp_op = htons(arp_op_reply);
        ahdr_res->arp_tip = ahdr->arp_sip;
        ahdr_res->arp_sip = iface->ip;
        memcpy(ahdr_res->arp_tha, ahdr->arp_sha, ETHER_ADDR_LEN);
        memcpy(ahdr_res->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);

        Buffer packet_res(packet.size());
        memcpy(packet_res.data(), ehdr_res, sizeof(ethernet_hdr));
        memcpy(packet_res.data() + sizeof(ethernet_hdr), ahdr_res, sizeof(arp_hdr));

        sendPacket(packet_res, inIface);
      }

    } else if (ntohs(ahdr->arp_op) == arp_op_reply) {

      // Handle ARP response
      if (ahdr->arp_tip == iface->ip) {

        Buffer sha_buf(ahdr->arp_sha, ahdr->arp_sha + ETHER_ADDR_LEN);
        std::shared_ptr<ArpRequest> req_ptr = m_arp.insertArpEntry(sha_buf, ahdr->arp_sip);

        if (req_ptr != nullptr) {

          ethernet_hdr *ehdr_res = (ethernet_hdr*)malloc(sizeof(ethernet_hdr));
          ehdr_res->ether_type = htons(ethertype_ip);
          memcpy(ehdr_res->ether_dhost, ahdr->arp_sha, ETHER_ADDR_LEN);
          memcpy(ehdr_res->ether_shost, ahdr->arp_tha, ETHER_ADDR_LEN);

          for (PendingPacket r : req_ptr->packets) {

            ip_hdr *iphdr_res = (ip_hdr*)malloc(sizeof(ip_hdr));
            memcpy(iphdr_res, r.packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
            iphdr_res->ip_ttl -= 1;
            iphdr_res->ip_sum = 0;
            iphdr_res->ip_sum = simple_router::cksum((const void*)iphdr_res, sizeof(ip_hdr));

            Buffer packet_res(r.packet.size());
            memcpy(packet_res.data(), r.packet.data(), r.packet.size());
            memcpy(packet_res.data(), ehdr_res, sizeof(ethernet_hdr));
            memcpy(packet_res.data() + sizeof(ethernet_hdr), iphdr_res, sizeof(ip_hdr));
            sendPacket(packet_res, inIface);
          }

          m_arp.removeRequest(req_ptr);
        }
      }
    }

  } else if (ntohs(ehdr->ether_type) == ethertype_ip) {
    // Handle IPv4/ICMP packet
    ip_hdr *iphdr = (ip_hdr*)malloc(sizeof(ip_hdr));
    memcpy(iphdr, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));

    uint16_t sum_buf = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = simple_router::cksum((const void*)iphdr, sizeof(ip_hdr));
    
    if (sum_buf != iphdr->ip_sum || iphdr->ip_ttl <= 0)
      return;

    iphdr->ip_ttl -= 1;
    iphdr->ip_sum = 0;
    iphdr->ip_sum = simple_router::cksum((const void *)iphdr, sizeof(ip_hdr));

    ip_hdr *iphdr_res = (ip_hdr*)malloc(sizeof(ip_hdr));
    memcpy(iphdr_res, iphdr, sizeof(ip_hdr));

    bool shouldForward = true;

    if (iphdr_res->ip_p == 1) {
      // Handle ICMP packet
      icmp_hdr *icmphdr = (icmp_hdr*)malloc(sizeof(icmp_hdr));
      memcpy(icmphdr, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), sizeof(icmp_hdr));

      if (icmphdr->icmp_type == 8 && findIfaceByIp(iphdr->ip_dst) != nullptr) {

        icmp_hdr *icmphdr_res = (icmp_hdr*)malloc(sizeof(icmp_hdr));
        memcpy(icmphdr_res, icmphdr, sizeof(icmp_hdr));
        icmphdr_res->icmp_type = 0;
        icmphdr_res->icmp_code = 0;
        icmphdr_res->icmp_sum = 0;
        icmphdr_res->icmp_sum = simple_router::cksum((const void*)icmphdr_res, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));

        iphdr_res->ip_len = htons(packet.size() - sizeof(ethernet_hdr));
        iphdr_res->ip_ttl = 64;
        iphdr_res->ip_p = 1;
        uint32_t ip_src_buf = iphdr_res->ip_src;
        iphdr_res->ip_src = iphdr_res->ip_dst;
        iphdr_res->ip_dst = ip_src_buf;
        iphdr_res->ip_sum = 0;
        iphdr_res->ip_sum = simple_router::cksum((const void*)iphdr_res, sizeof(ip_hdr));
      
        ethernet_hdr *ehdr_res = (ethernet_hdr*)malloc(sizeof(ethernet_hdr));
        memcpy(ehdr_res, ehdr, sizeof(ethernet_hdr));
        memcpy(ehdr_res->ether_dhost, ehdr_res->ether_shost, ETHER_ADDR_LEN);
        memcpy(ehdr_res->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

        Buffer packet_res(packet.size());
        memcpy(packet_res.data(), packet.data(), packet.size());
        memcpy(packet_res.data(), ehdr_res, sizeof(ethernet_hdr));
        memcpy(packet_res.data() + sizeof(ethernet_hdr), iphdr_res, sizeof(ip_hdr));
        memcpy(packet_res.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), icmphdr_res, sizeof(icmp_hdr));

        RoutingTableEntry rte = getRoutingTable().lookup(iphdr_res->ip_dst);
        std::shared_ptr<ArpEntry> arp_ptr = (iphdr_res->ip_dst & rte.mask) == (rte.dest & rte.mask) ?
          m_arp.lookup(iphdr_res->ip_dst) : m_arp.lookup(rte.gw);

        if (arp_ptr == nullptr)
          m_arp.queueRequest(iphdr_res->ip_dst, packet_res, inIface);
        else
          sendPacket(packet_res, inIface);

        shouldForward = false;
      }

    }
    
    if (shouldForward) {
      // Forward the packet
      if (iphdr_res->ip_dst == iface->ip)
        return;
      
      RoutingTableEntry rte = getRoutingTable().lookup(iphdr->ip_dst);
      std::shared_ptr<ArpEntry> arp_ptr = m_arp.lookup(iphdr->ip_dst);
      
      Buffer packet_res(packet.size());
      memcpy(packet_res.data(), packet.data(), packet.size());
      memcpy(packet_res.data() + sizeof(ethernet_hdr), iphdr_res, sizeof(ip_hdr));

      if (arp_ptr == nullptr) {
        m_arp.queueRequest(iphdr_res->ip_dst, packet_res, inIface);

      } else {
        ethernet_hdr *ehdr_res = (ethernet_hdr*)malloc(sizeof(ethernet_hdr));
        memcpy(ehdr_res, ehdr, sizeof(ethernet_hdr));
        memcpy(ehdr_res->ether_dhost, arp_ptr->mac.data(), ETHER_ADDR_LEN);
        memcpy(ehdr_res->ether_shost, findIfaceByName(rte.ifName)->addr.data(), ETHER_ADDR_LEN);
        memcpy(packet_res.data(), ehdr_res, sizeof(ethernet_hdr));
        sendPacket(packet_res, rte.ifName);
      }
    }

  }

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
