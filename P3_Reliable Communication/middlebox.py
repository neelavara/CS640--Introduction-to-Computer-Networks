#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import *
import time


param_file_name = "middlebox_params.txt"

BLASTER_IP = "192.168.100.1"
BLASTER_MAC = "10:00:00:00:00:01"

MIDDLEBOX_BLASTER_IP = "192.168.100.2"
MIDDLEBOX_BLASTER_MAC = "40:00:00:00:00:01"

MIDDLEBOX_BLASTEE_IP = "192.168.200.2"
MIDDLEBOX_BLASTEE_MAC = "40:00:00:00:00:02"

BLASTEE_IP = "192.168.200.1"
BLASTEE_MAC = "20:00:00:00:00:01"

drop_rate = 0

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    read_parameters()

    while True:
        gotpkt = True
        try:
            recv_data = net.recv_packet()
            dev = recv_data.input_port
            pkt = recv_data.packet
            log_info("Device is {}".format(dev))
        except NoPackets:
            log_info("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_info("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if drop_this_pkt() == False :
               pkt = get_modified_packet(pkt,net,"middlebox-eth1",BLASTEE_MAC)
               net.send_packet("middlebox-eth1", pkt)
            else :
               log_info("Dropping packet")
        elif dev == "middlebox-eth1":
            log_info("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            '''
            pkt = get_modified_packet(pkt,net,"middlebox-eth0",BLASTER_MAC)
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()

def drop_this_pkt():
   drop_prob = uniform(0.0,1.0)
   log_info("Caculated drop prob " + str(drop_prob))
   if drop_prob < drop_rate : # drop packet
      return True
   else:
      return False


def get_modified_packet(pkt,net,interface,destination_eth):
   log_info("Inside get_modified_packet")
   if not pkt.get_header(Ethernet):
      pkt+= Ethernet()
   pkt[Ethernet].src = net.interface_by_name(interface).ethaddr
   pkt[Ethernet].dst = destination_eth
   log_info("Exit get_modified_packet")
   return pkt


def read_parameters():
   log_info("reading parameters from file " + str(param_file_name))
   global drop_rate
   contents = open(param_file_name,"r")

   for line in contents.readlines():
      value = line.split()
      drop_rate = float(value[1])
      log_info("drop_rate : " + str(drop_rate))
