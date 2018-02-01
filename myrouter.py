#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        self.ip_eth_map={}
        self.interfaces = net.interfaces()
        self.forwarding_table = []
        self.build_forwarding_table()
        self.queue = {}
        # other initialization stuff here

    
    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            self.check_queue()
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                print("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                print("Got shutdown signal")
                break

            if gotpkt:
                print("Got a packet: {}".format(str(pkt)))
                if pkt.has_header(Arp):
                   arp = pkt.get_header(Arp)
                   print ("ARP HEADER")
                   if arp.operation == ArpOperation.Request: # checking if the incoming request is Arp.Request
                      ip_eth_tuple = {arp.senderprotoaddr : arp.senderhwaddr}
                      self.ip_eth_map.update(ip_eth_tuple)
                      match_found = False
                      for intf in self.interfaces: # First checking in the local interfaces
                         if arp.targetprotoaddr == intf.ipaddr:
                            print ("Send arp reply to eth address " + str(arp.senderhwaddr) + " having ip " + str(arp.senderprotoaddr))
                            arp_reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                            match_found = True
                            print ("sending arp reply on inf " + str(dev))
                            self.net.send_packet(dev,arp_reply)
                            break

                      log_info(self.ip_eth_map)
                      log_info("Boolean " + str(match_found))
                      
                      # If not found in local interface, search the ip_eth cache for match
                      if match_found == False and self.is_present(self.ip_eth_map, arp.targetprotoaddr) is True:
                         mac_addr = self.ip_eth_map.get(arp.targetprotoaddr)
                         log_info("MAC FOUND " + str(mac_addr))
                         arp_reply = create_ip_arp_reply(mac_addr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                         self.net.send_packet(dev,arp_reply)
                      log_info("clear queue for self eth")

                   else:
                      # arp response, modify ip_eth_map and check for the items in queue
                      log_info("ARP Response received")
                      ip_eth_tuple = {arp.senderprotoaddr : arp.senderhwaddr}
                      self.ip_eth_map.update(ip_eth_tuple)
                      self.clear_queue(arp)
                         
                elif pkt.has_header(IPv4):
                   log_info("Received IPV4 packet")
                   local_interface = False
                   destination = pkt[IPv4].dst
                   # checking if the packet is intended for the router
                   for intf in self.interfaces:
                      if intf.ipaddr == pkt[IPv4].dst:
                         local_interface= True
                         if pkt.has_header(ICMP):
                            log_info("ICMP header caught switching src and dst address")
                            destination = pkt[IPv4].src
                         break
                   
                   # search the forwarding table for the next hop
                   forward_tuple = self.find_next_hop_in_forward_table(destination)
                   log_info("Forward Tuple is " + str(forward_tuple))
                   next_hop = forward_tuple[0]
                   out_inf = forward_tuple[1]

                   log_info("Next hop " + str(next_hop))

                   if next_hop is 'None': #match in myInterface set the next_hop as the destination.
                      next_hop = destination

                   
                   if next_hop == "": #match not found
                      # drop the packet and send the ICMP destination network unreachable msg
                      if not pkt.get_header(ICMP):
                         pkt+= ICMP()
                      pkt = self.make_icmp_packet(pkt, ICMPType.DestinationUnreachable, out_inf)
                      pkt.get_header(ICMP).icmpcode = 0 # Network Unreachable
                      next_hop = pkt[IPv4].dst
                      self.process_packet(pkt, next_hop, out_inf)
                      continue
                   
                   if local_interface is True:
                      if pkt.has_header(ICMP):
                         icmp_hdr = pkt.get_header(ICMP)
                         log_info("ICMP Type : " + str(icmp_hdr.icmptype))
                         if icmp_hdr.icmptype == ICMPType.EchoRequest: #if the ICMP Type is Echo Request
                            pkt = self.make_icmp_packet(pkt, ICMPType.EchoReply, out_inf) # Send the Echo reply and do forwarding process
                            self.process_packet(pkt, next_hop, out_inf)
                            continue
                         else:
                            # if packet has some other ICMPType send back the destinationUnreachable as per 
                            #specification point 4 (Task 2: Generating ICMP error messages)
                            pkt = self.make_icmp_packet(pkt, ICMPType.DestinationUnreachable, out_inf)
                            pkt.get_header(ICMP).icmpcode = 3 # port unreachable
                            self.process_packet(pkt, next_hop, out_inf)
                            continue
                      continue # As per FAQ, if the packet is intended for router drop it, if no icmp found.
                   
                   # TTL handling
                   pkt.get_header(IPv4).ttl = pkt.get_header(IPv4).ttl-1
                   if pkt.get_header(IPv4).ttl == 0:
                      # TTL is 0 send ICMP error msg
                      log_info("TTL is zero")
                      if not pkt.get_header(ICMP):
                         pkt+= ICMP()
                      pkt = self.make_icmp_packet(pkt, ICMPType.TimeExceeded, out_inf)
                      pkt.get_header(ICMP).icmpcode = 0 # TTL Expired
                      next_hop = pkt[IPv4].dst
                      self.process_packet(pkt, next_hop, out_inf)
                      continue
                   
                   self.process_packet(pkt, next_hop, out_inf)
                   
                   
                   
        
    # Does look up in forwarding table and returns the next_hop and output interface
    def find_next_hop_in_forward_table(self, destination):
       max_match_len = 0
       curr_match_len = 0
       out_inf = ""
       next_hop = ""
       log_info("Looking for destination " + str(destination) +  " In table")
       for tuple in self.forwarding_table:
          prefix = IPv4Address(tuple[0])
          first = int(prefix) & int(IPv4Address(tuple[1]))
          second = int(destination) & int(IPv4Address(tuple[1]))
          matches = (first == second)
          if matches is True:
             netaddr = IPv4Network(str(tuple[0]) + '/' + str(tuple[1]))
             curr_match_len = netaddr.prefixlen
          if curr_match_len > max_match_len:
             max_match_len = curr_match_len
             if tuple[2] == 'None':
                next_hop = 'None'  
             else:
                next_hop = IPv4Address(tuple[2])
             out_inf = tuple[3]
       return [next_hop, out_inf]
       
                                  
    def process_packet(self, pkt, next_hop, out_inf):

       log_info ("Next _ hop " + str(next_hop))
       log_info ("Map " + str(self.ip_eth_map))

       # No need for ARP, send the packet directly
       if self.is_present(self.ip_eth_map, next_hop) is True:
          if not pkt.get_header(Ethernet):
             pkt+= Ethernet()
          pkt[Ethernet].src = self.net.interface_by_name(out_inf).ethaddr
          log_info("Match_Found")
          pkt[Ethernet].dst = self.ip_eth_map[next_hop]
          log_info("Sending packet on " + out_inf + " self.net " + str(self.net))
          self.net.send_packet(out_inf,pkt)
          log_info("Below Sending packet")
       else:
          # checking if there is outstanding ARP request for this IP
          if self.is_present(self.queue, next_hop) is True:
             # append to queue, dont send again
             self.queue[next_hop][0].append(pkt)
             log_info("Added to queue")
          else:
             log_info("Sent Arp request " + out_inf + " for ip " + str(next_hop))
             senderhwaddr= self.net.interface_by_name(out_inf).ethaddr
             senderprotoaddr= self.net.interface_by_name(out_inf).ipaddr
             log_info("senderhwaddr " + str(senderhwaddr) + " senderprotoaddr " + str(senderprotoaddr) + " targetIP " + str(next_hop))
             req_packet = create_ip_arp_request(senderhwaddr,senderprotoaddr,next_hop)
             self.net.send_packet(out_inf,req_packet)
             self.queue[next_hop] = [[pkt], time.time(), 1.0, out_inf]
             log_info("Packet Added to queue")
          

    def is_present(self,maps, to_match):
       log_info("Inside is_present")
       for key in maps.keys():
          if str(to_match) ==  str(key):
             log_info("Match Returning True")
             return True
       return False  

    # builds forwarding table from forwarding_table.txt file and local interfaces
    def build_forwarding_table(self):
        contents = open("forwarding_table.txt","r")

        for line in contents.readlines():
           value = line.split()
           self.forwarding_table.append(value)

        for inf in self.interfaces:
            log_info("Local Interface ip " + str(inf.ipaddr))
            networkid = IPv4Address(int(inf.ipaddr) & int(inf.netmask))
            line =  [(format(str(networkid))), format(str(inf.netmask)), 'None', inf.name]
            self.forwarding_table.append(line)

        for each_tuple in self.forwarding_table:
            print(each_tuple)   

    # keeps the queue consistent, by checking for elimination criteria like retryCount and 
    # resending Arp queries
    def check_queue(self):
       # IP : [[pkt], time, count, interface]
       log_info("Inside Check Queue")
       max_count_reached = []
       for key in self.queue.keys():
          if time.time()-self.queue[key][1] >= 1.0:
             if self.queue[key][2] >= 5:
                max_count_reached.append(key)
                continue
             senderhwaddr= self.net.interface_by_name(self.queue[key][3]).ethaddr
             senderprotoaddr= self.net.interface_by_name(self.queue[key][3]).ipaddr
             req_packet = create_ip_arp_request(senderhwaddr,senderprotoaddr,key)
             self.net.send_packet(self.queue[key][3],req_packet)
             self.queue[key][1] = time.time()
             self.queue[key][2] = self.queue[key][2]+1 

       for key in max_count_reached:
          out_inf = self.queue[key][3]
          for pkt in self.queue[key][0]:
             self.send_arp_failure(pkt, out_inf)
          del self.queue[key]

    # Send Arp failure message # Invoked after 5 retries
    def send_arp_failure(self, pkt, out_inf):
       log_info("Sending Arp failures")
       pkt = self.make_icmp_packet(pkt, ICMPType.DestinationUnreachable, out_inf)
       pkt.get_header(ICMP).icmpcode = 1 # arp failure
       destination = pkt[IPv4].dst
       # Not directly sending it, as per specification first doing the look up and then 
       # normal forwarding process consisting of Arp checking
       forward_tuple = self.find_next_hop_in_forward_table(destination)
       next_hop = forward_tuple[0]
       out_inf = forward_tuple[1]
       self.process_packet(pkt, next_hop, out_inf)
       

	 # removes corresponding packets after successful Arp Response
    def clear_queue(self, arp):
       in_queue = False
       log_info("Inside clear queue Checking " + str(arp.senderprotoaddr))

       if self.is_present(self.queue, arp.senderprotoaddr) is True:
          out_inf = self.queue[arp.senderprotoaddr][3]
          log_info("Sending packets to " + str(arp.senderprotoaddr) + " from the queue ")
          for pkt in self.queue[arp.senderprotoaddr][0]:
             if not pkt.get_header(Ethernet):
                pkt+= Ethernet()
             pkt[Ethernet].src = self.net.interface_by_name(out_inf).ethaddr
             pkt[Ethernet].dst = arp.senderhwaddr
             self.net.send_packet(out_inf,pkt)
          del self.queue[arp.senderprotoaddr]

    # Makes and returns packet based on the input ICMP error_type
    def make_icmp_packet(self, pkt, error_type, out_inf):
       log_info("Inside Make Pkt  Received Pkt" + str(pkt))
       log_info("Error Type " + str(error_type))
       icmp_hdr = pkt.get_header(ICMP)
       log_info("Before Data " + str(icmp_hdr.icmpdata.data))
       log_info("ICMP Type : " + str(icmp_hdr.icmptype))
       data = icmp_hdr.icmpdata.data
       pkt.get_header(ICMP).icmptype = error_type
       pkt.get_header(ICMP).icmpdata.data = data

       tmp = pkt[IPv4].src
       pkt[IPv4].src = pkt[IPv4].dst
       pkt[IPv4].dst = tmp
       log_info("Final pkt " + str(pkt))

       return pkt
        
       
def main(net):
 
    '''Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
