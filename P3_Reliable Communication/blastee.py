#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

param_file_name = "blastee_params.txt"

BLASTER_IP = "192.168.100.1"
BLASTER_MAC = "10:00:00:00:00:01"

MIDDLEBOX_BLASTER_IP = "192.168.100.2"
MIDDLEBOX_BLASTER_MAC = "40:00:00:00:00:01"

MIDDLEBOX_BLASTEE_IP = "192.168.200.2"
MIDDLEBOX_BLASTEE_MAC = "40:00:00:00:00:02"

BLASTEE_IP = "192.168.200.1"
BLASTEE_MAC = "20:00:00:00:00:01"

blaster_ip = ""
no_pkts_by_blaster = 0

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    read_parameters()
    count = 0

    while True:
        gotpkt = True
        try:
            recv_data = net.recv_packet()
            dev = recv_data.input_port
            pkt = recv_data.packet
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            
            # Only Processing the packet if it is coming from blaster
            comingFromBlaster = isComingFromBlaster(pkt)
            if comingFromBlaster == True :
               count = count+1
               ack_pkt = create_ack_pkt(pkt)
               out_inf = net.interface_by_ipaddr(BLASTEE_IP)
               log_info("Sending packet from blastee ")
               net.send_packet(out_inf,ack_pkt)

    net.shutdown()



def isComingFromBlaster(pkt):
   if pkt.has_header(IPv4):
      if str(pkt[IPv4].src) == BLASTER_IP:
         return True
   return False
   

def create_ack_pkt(pkt):
   log_info("Inside create_ack_pkt Pkt: ")
   packet = pkt

   # Modifying Ethernet src and dst address
   if not packet.has_header(Ethernet) :
      packet += Ethernet()
   packet[Ethernet].src = BLASTEE_MAC
   packet[Ethernet].dst = MIDDLEBOX_BLASTEE_MAC

   # Modifying Ip src and dst address
   if not packet.has_header(IPv4) :
      packet += IPv4()
   packet[IPv4].src = BLASTEE_IP
   packet[IPv4].dst = BLASTER_IP

   if not packet.has_header(UDP) :
      packet += UDP()
   packet[UDP].src = 4444 
   packet[UDP].dst = 5555

   received_tuple = get_sequence_num_and_payload(pkt)
   sequence_num = received_tuple[0]
   payload = received_tuple[1]
  
   del packet[RawPacketContents] 
   packet += sequence_num
   packet += payload
   
   return packet
   

def get_sequence_num_and_payload(pkt):
   log_info("Inside Get Sequence Number")
   raw = pkt[RawPacketContents].data
   sequence_num = raw[0:32]
   log_info("Sequence Number " + str(sequence_num))
   
   payload = raw[48:]
   log_info("Payload " + str(payload))
   
   if len(payload) < 64:
      #do padding
      padding_len = (64-len(payload))

      data = get_data()
      log_info("Putting extra payload")
      intermediate_data = convert_to_binary(data,padding_len)
      encoded_data = get_encoded_data(intermediate_data)
  
      log_debug("Extra Payload after encoding ")

      payload = payload + encoded_data
   else:
      payload = payload[0:64]

   return [sequence_num,payload]


def get_encoded_data(data_to_encode):
   data_bytes = bytes(data_to_encode, 'ascii')
   converter = struct.Struct('>' + str(len(data_bytes)) + 'B')
   return converter.pack(*data_bytes)

def convert_to_binary(data, total_length):
   return bin(data)[2:].zfill(total_length)

def get_data():
   data = 8
   return data

def read_parameters():
   log_info("reading parameters from file " + str(param_file_name))
   global blaster_ip
   global no_pkts_by_blaster
   contents = open(param_file_name,"r")

   for line in contents.readlines():
      value = line.split()
      blaster_ip = value[1]
      no_pkts_by_blaster = int(value[3])
      log_info("Blaster Ip : " + str(blaster_ip) + " No of packets : " + str(no_pkts_by_blaster))

