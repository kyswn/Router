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
#include <string>
using namespace std;

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const string& inIface)
{
  cerr << "Got packet of size " << packet.size() << " on interface " << inIface << endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    cerr << "Received packet, but interface is unknown, ignoring" << endl;
    return;
  }

  //cerr<<getRoutingTable()<<endl;


  // FILL THIS IN

  //get the ethernet frame header out 
  
  //print_hdrs(packet);
  struct ethernet_hdr e_header;
  memcpy(&e_header, packet.data(),sizeof(struct ethernet_hdr));
   

  uint16_t e_type = ntohs(e_header.ether_type);
  cerr<<e_type<<endl;
  if(e_type==ethertype_arp){
    cerr<<"its arp"<<endl;

    struct arp_hdr a_header;
    memcpy(&a_header,&(packet[sizeof(struct ethernet_hdr)]),sizeof(struct arp_hdr));
    unsigned short o_code=ntohs(a_header.arp_op);

    if(o_code==1){
      //arp request
      cerr<<"arp request"<<endl;
      string etmac=macToString(Buffer(e_header.ether_dhost,e_header.ether_dhost+ETHER_ADDR_LEN));
      cerr<<"the destinition mac address is"<<etmac<<endl;
      string broadcastMac="ff:ff:ff:ff:ff:ff";

      if(etmac==broadcastMac&&a_header.arp_tip==iface->ip){
        //broadcast and to this router interface

        //we should send response

        //construct an arp header for the response arp
        struct arp_hdr r_a_header;
        r_a_header.arp_hrd=a_header.arp_hrd;
        r_a_header.arp_pro=a_header.arp_pro;
        r_a_header.arp_hln=a_header.arp_hln;
        r_a_header.arp_pln=a_header.arp_pln;
        r_a_header.arp_op=htons(2);
        memcpy(r_a_header.arp_sha,iface->addr.data(),ETHER_ADDR_LEN);
        r_a_header.arp_sip=iface->ip;
        memcpy(r_a_header.arp_tha,a_header.arp_sha,ETHER_ADDR_LEN);
        r_a_header.arp_tip=a_header.arp_sip;

        //construc a ethernet header for to send
        struct ethernet_hdr r_e_header;
        memcpy(r_e_header.ether_dhost,e_header.ether_shost,ETHER_ADDR_LEN);
        memcpy(r_e_header.ether_shost,iface->addr.data(),ETHER_ADDR_LEN);
        r_e_header.ether_type=e_header.ether_type;

        //construct the packet to reply
        Buffer r_packet(packet.size());
        memcpy(r_packet.data(),&r_e_header,sizeof(ethernet_hdr));
        memcpy(r_packet.data()+sizeof(ethernet_hdr), &r_a_header, sizeof(arp_hdr));
        cerr<<"responding to arp"<<endl;
        //print_hdrs(r_packet);
        sendPacket(r_packet,inIface);
        cerr<<inIface<<endl;
        cerr<<"finished sending"<<endl;
        return;
      }
      else{
        //ignore
        cerr<<"not broadcast or ip target is not this interface"<<endl;
        return;
      }


    }
    else if(o_code==2){
      //arp reply
      cerr<<"arp reply"<<endl;
      if(a_header.arp_tip==iface->ip){
        Buffer mac(a_header.arp_sha, a_header.arp_sha + ETHER_ADDR_LEN);
        //cerr<<"intsert arp entry"<<mac<<" "<<a_header.arp_sip<<endl;
        shared_ptr<ArpRequest> arpRequest = m_arp.insertArpEntry(mac, a_header.arp_sip);
        if (arpRequest != nullptr) { 
          //send those packages out
          while(arpRequest->packets.size()>0){
            //contruct an etherenet frame to send
            cerr<<"start preparing for package<<endl";
            struct ethernet_hdr s_e_header;
            s_e_header.ether_type=htons(0x0800);
            memcpy(s_e_header.ether_dhost,a_header.arp_sha,ETHER_ADDR_LEN);
            memcpy(s_e_header.ether_shost,a_header.arp_tha,ETHER_ADDR_LEN);
            

            int packet_size=arpRequest->packets.front().packet.size();
            Buffer r_packet(packet_size);
            memcpy(r_packet.data(),arpRequest->packets.front().packet.data(),packet_size);
            memcpy(r_packet.data(), &s_e_header, sizeof(struct ethernet_hdr));
            //uint8_t* sendPack = (uint8_t*)r_packet.data();
            //update the tll and checksum
            ip_hdr *ip_header = (ip_hdr*)malloc(sizeof(ip_hdr));
            memcpy(ip_header, arpRequest->packets.front().packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
            ip_header->ip_ttl -= 1;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum((const void*)ip_header, sizeof(ip_hdr));
            memcpy(r_packet.data()+sizeof(ethernet_hdr),ip_header,sizeof(ip_hdr));


            cerr<<"sending ipv4 packet"<<endl;
            sendPacket(r_packet,inIface);
            cerr<<inIface<<endl;
            cerr<<"fnished sending ipv4 packet with the following header"<<endl;
            //print_hdrs(r_packet);
            arpRequest->packets.pop_front();
            //////todo: is pop front right?







          }
          m_arp.removeRequest(arpRequest);
          return;

        }

      }
      else {
        cerr<<"not to this interface"<<endl;
        return;
      }


    }
    else {
      cerr<<"the arp_op is wrong"<<endl;
      return;
    }

        


  }
  else if(e_type==ethertype_ip){
    cerr << "It's ipv4" << endl;
    

    struct ip_hdr ip_header;
    memcpy(&ip_header, &(packet[sizeof(ethernet_hdr)]), sizeof(struct ip_hdr));
    //check the checksum
    uint16_t the_checksum = ip_header.ip_sum;
    ip_header.ip_sum = 0;
    uint16_t actual_checksum = cksum((const void *)&ip_header, sizeof(struct ip_hdr));
    if(the_checksum==actual_checksum){
      cerr<<"checksum test passed"<<endl;
      ip_header.ip_sum=actual_checksum;
    }
    else{
      cerr<<"chekcsum failed"<<endl;
      return;
    }

    //check pacakge length
    if (ip_header.ip_len < 20) {
      cerr << "Packet length smaller than min length" << endl;
      return;
    }


    //check TTL

    uint8_t ipTTL = ip_header.ip_ttl;
    if (ipTTL <= 0) {
        cerr << "Packet TTL Expired" << endl;
        return;
    }
    
    const Interface* ipDest = findIfaceByIp(ip_header.ip_dst);
    if (ipDest != nullptr) {
    //to this router, deal with it
      if(ip_header.ip_p == 1){
        //icmp
        cerr<<"its icmp"<<endl;
        struct icmp_hdr ic_header;
        memcpy(&ic_header, &(packet[sizeof(ethernet_hdr)+sizeof(ip_hdr)]), sizeof(icmp_hdr));
        if (ic_header.icmp_type == 8 ) {
          //icmp echo,need to reply
          cerr<<"icmp echo"<<endl;   
          Buffer s_packet(packet.size());
          memcpy(s_packet.data(), packet.data(), packet.size());
          struct icmp_hdr r_ic_header;
          memcpy(&r_ic_header, &(packet[sizeof(struct ethernet_hdr)+sizeof(struct ip_hdr)]), sizeof(struct icmp_hdr));
          r_ic_header.icmp_type = 0;
          r_ic_header.icmp_code = 0;
          r_ic_header.icmp_sum = 0;
          r_ic_header.icmp_sum = simple_router::cksum((const void *)&r_ic_header, packet.size()-(sizeof(struct ethernet_hdr))-(sizeof(struct ip_hdr)));
          
          //construct the ip header
          ip_header.ip_len = htons(packet.size()-(sizeof(struct ethernet_hdr)));
          ip_header.ip_ttl = 64;
          ip_header.ip_p = 1;
          uint32_t temp = ip_header.ip_dst;
          ip_header.ip_dst = ip_header.ip_src;
          ip_header.ip_src = temp;
          ip_header.ip_sum = 0;
          ip_header.ip_sum = simple_router::cksum((const void *)&ip_header, sizeof(ip_hdr));
          //construct the ethernet header
          memcpy(e_header.ether_dhost, e_header.ether_shost, ETHER_ADDR_LEN);
          memcpy(e_header.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
          memcpy(s_packet.data(), &e_header, sizeof(ethernet_hdr));
          memcpy(&(s_packet[sizeof(ethernet_hdr)]), &ip_header, sizeof(struct ip_hdr));
          memcpy(&(s_packet[sizeof(ethernet_hdr)+sizeof(ip_hdr)]), &r_ic_header, sizeof(icmp_hdr));
                    
          struct RoutingTableEntry nexthop;         
          nexthop = getRoutingTable().lookup(ip_header.ip_dst);
          shared_ptr<ArpEntry> ptr;
          if ((ip_header.ip_dst&nexthop.mask) == (nexthop.dest&nexthop.mask)) {
              ptr = m_arp.lookup(ip_header.ip_dst);
          }
          else {
              ptr = m_arp.lookup(nexthop.gw);
          }
          if (ptr == nullptr) {
              m_arp.queueRequest(ip_header.ip_dst, s_packet, inIface);
          }
          else {
              sendPacket(s_packet, inIface);
              cerr<<inIface<<endl;
              cerr << "Sending Echo Reply" << endl;
              //print_hdrs(s_packet);
          }
          return;
        }
        else {
          cerr<<"icmp echo reply"<<endl;
          //forward ICMP packetsap_
          RoutingTableEntry rtEntry = getRoutingTable().lookup(ip_header.ip_dst); 
          // Check ARP cache entry for the IP-MAC pair
          shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ip_header.ip_dst);
          if (arpEntry != nullptr) { 
            //in the arp cache

            // create and send ip packet 
      
            Buffer s_packet(packet.size());
            memcpy(s_packet.data(), packet.data(), packet.size());
            uint8_t* sendPack = (uint8_t*)s_packet.data();
            ethernet_hdr* e_header = (ethernet_hdr*)sendPack;
            ip_hdr* ip_header = (ip_hdr*)(sendPack + sizeof(ethernet_hdr));

            //construct the ethernet header and the ip header
            const Interface* the_iface = findIfaceByName(rtEntry.ifName);
            memcpy(e_header->ether_shost, the_iface->addr.data(), ETHER_ADDR_LEN);
            memcpy(e_header->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
            e_header->ether_type = htons(ethertype_ip);
                
            ip_header->ip_ttl -= 1;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum((const void*)ip_header, sizeof(ip_hdr));
                
            // Forward it
            cerr << "ready to forward icmp packet" << endl;
            sendPacket(s_packet, rtEntry.ifName);
            cerr<<rtEntry.ifName<<endl;

            cerr<<"finihsed sending icmp packet"<<endl;

            //print_hdrs(s_packet);

            return;
          }
          else { 
            //not in arp cache, need to queue message 
            Buffer q_packet(packet.size());
            memcpy(q_packet.data(), packet.data(), packet.size());
            //uint8_t* queuePacket = (uint8_t*)q_packet.data();
            //ip_hdr* ip_header = (ip_hdr*)(queuePacket + sizeof(ethernet_hdr));
           // ip_header->ip_ttl -= 1; 
            //ip_header->ip_sum = 0;
            //ip_header->ip_sum = cksum((const void*)ip_header, sizeof(ip_header)); 
            shared_ptr<ArpRequest> arpRequest = m_arp.queueRequest(ip_header.ip_dst, q_packet, inIface);
            return;
          }
        }
      }
      else{
        //error
        cerr<<"to this router but no icmp, so drop it"<<endl;
        return;
      }
    }

      

    else{
      //not to this router,forward it

      RoutingTableEntry rtEntry = getRoutingTable().lookup(ip_header.ip_dst); 
      // Check ARP cache entry for the IP-MAC pair
      shared_ptr<ArpEntry> arpEntry = m_arp.lookup(ip_header.ip_dst);
      if (arpEntry != nullptr) { 
        //in the arp cache

        // create and send ip packet 
  
        Buffer s_packet(packet.size());
        memcpy(s_packet.data(), packet.data(), packet.size());
        uint8_t* sendPack = (uint8_t*)s_packet.data();
        ethernet_hdr* e_header = (ethernet_hdr*)sendPack;
        ip_hdr* ip_header = (ip_hdr*)(sendPack + sizeof(ethernet_hdr));

        //construct the ethernet header and the ip header
        const Interface* the_iface = findIfaceByName(rtEntry.ifName);
        memcpy(e_header->ether_shost, the_iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(e_header->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
        e_header->ether_type = htons(ethertype_ip);
            
        ip_header->ip_ttl -= 1;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum((const void*)ip_header, sizeof(ip_hdr));
            
       // memcpy(&(s_packet[0]), &e_header, sizeof(struct ethernet_hdr));
        //memcpy(&(s_packet[sizeof(struct ethernet_hdr)]), &ip_header, sizeof(struct ip_hdr));
        // Forward it
        cerr << "ready to forward ip packets" << endl;
        sendPacket(s_packet, rtEntry.ifName);
        cerr<<rtEntry.ifName;
        cerr<<"finished sending ip packets"<<endl;

        print_hdrs(s_packet);
      }
      else { 
        //not in arp cache, need to queue message 
        Buffer q_packet(packet.size());
        memcpy(q_packet.data(), packet.data(), packet.size());
        //uint8_t* queuePacket = (uint8_t*)q_packet.data();
        //ip_hdr* ip_header = (ip_hdr*)(queuePacket + sizeof(ethernet_hdr));
        //ip_header->ip_ttl -= 1; 
        //ip_header->ip_sum = 0;
        //ip_header->ip_sum = cksum((const void*)ip_header, sizeof(ip_header)); 
        cerr<<"queuing the request"<<endl;
        shared_ptr<ArpRequest> arpRequest = m_arp.queueRequest(ip_header.ip_dst, q_packet, inIface);

      }

    }
  }
  else{
    //ignnore
    cerr<<"not arp or ipv4"<<endl;
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
SimpleRouter::sendPacket(const Buffer& packet, const string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const string& ifconfig)
{
  ifstream iff(ifconfig.c_str());
  string line;
  while (getline(iff, line)) {
    istringstream ifLine(line);
    string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << endl;
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
  auto iface = find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
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
  auto iface = find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
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
  cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const string& name) const
{
  auto iface = find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
