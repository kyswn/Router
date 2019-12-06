/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

/**
   * IMPLEMENT THIS METHOD
   *
   * This method gets called every second. For each request sent out,
   * you should keep checking whether to resend a request or remove it.
   *
   * Your implementation should follow the following logic
   *
   *     for each request in queued requests:
   *         handleRequest(request)
   *
   *     for each cache entry in entries:
   *         if not entry->isValid
   *             record entry for removal
   *     remove all entries marked for removal
   */

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

//TODO: implement handleRequest
void
ArpCache::handleRequest(std::shared_ptr<ArpRequest> req)
{
    if (req == nullptr) {
        return;
    }

  auto now = steady_clock::now();
  if (std::chrono::duration_cast<seconds>(now - req->timeSent) >= seconds(1)) {
    if (req -> nTimesSent >= 5) {
      //over 5 times, remove it
      std::list<PendingPacket>::iterator packetIterator;
      m_arpRequests.remove(req);
      return;
    }
    else {
      //send arp request
      Buffer packet(sizeof(arp_hdr) + sizeof (ethernet_hdr));
      struct RoutingTableEntry Rentry = m_router.getRoutingTable().lookup(req->ip);
      const Interface *IF_PTR = m_router.findIfaceByName(Rentry.ifName);

      struct ethernet_hdr ehdr;

      int i=0;
      while(i<ETHER_ADDR_LEN){
        ehdr.ether_dhost[i]=0xFF;
        i++;
      }

      ehdr.ether_type = htons(ethertype_arp);
      memcpy(&(ehdr.ether_shost), IF_PTR->addr.data(),ETHER_ADDR_LEN);

      struct arp_hdr arphdr;
      arphdr.arp_hrd = htons(arp_hrd_ethernet);
      arphdr.arp_hln = ETHER_ADDR_LEN;
      arphdr.arp_pro = htons(ethertype_ip);
      arphdr.arp_pln = 4;
      arphdr.arp_op = htons(arp_op_request);
      arphdr.arp_tip = req->ip;
      arphdr.arp_sip = IF_PTR->ip;
      i=0;
      while(i<ETHER_ADDR_LEN){
        arphdr.arp_tha[i] = 0x00;
        i++;
      }
      memcpy(arphdr.arp_sha, IF_PTR->addr.data(), ETHER_ADDR_LEN);


      memcpy(&packet[0], &ehdr, sizeof(ehdr));
      memcpy(&packet[sizeof(ehdr)], &arphdr, sizeof(arphdr));
      std::cerr << "Sending ARP Request" << std::endl;
      //print_hdrs(packet);
      m_router.sendPacket(packet, IF_PTR->name);
      std::cerr<<"finished sending arp request"<<std::endl;

      req->timeSent = steady_clock::now();
      req->nTimesSent++;
      std::cerr << "!!!nTimesSent = " << req->nTimesSent << std::endl;
    }
  }
}

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  //handle the arp rquest table
  std::list<std::shared_ptr<ArpRequest>>::iterator req_iter1=m_arpRequests.begin();
  std::list<std::shared_ptr<ArpRequest>>::iterator req_iter2;
  while(req_iter1!=m_arpRequests.end()){
    req_iter2=req_iter1;
    req_iter2++;
    handleRequest(*req_iter1);
    req_iter1=req_iter2;
  }

  //handle the arp entry table

  std::list<std::shared_ptr<ArpEntry>>::iterator arp_iter=m_cacheEntries.begin();
  while(arp_iter!=m_cacheEntries.end()){
    if(!(*arp_iter)->isValid)
      arp_iter=m_cacheEntries.erase(arp_iter);
    else arp_iter++;
  }


}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
