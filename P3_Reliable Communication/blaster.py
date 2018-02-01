#!/usr/bin/env python3
from __future__ import division
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import collections
import time

param_file_name = "blaster_params.txt"

BLASTER_IP = "192.168.100.1"
BLASTER_MAC = "10:00:00:00:00:01"

MIDDLEBOX_BLASTER_IP = "192.168.100.2"
MIDDLEBOX_BLASTER_MAC = "40:00:00:00:00:01"

MIDDLEBOX_BLASTEE_IP = "192.168.200.2"
MIDDLEBOX_BLASTEE_MAC = "40:00:00:00:00:02"

BLASTEE_IP = "192.168.200.1"
BLASTEE_MAC = "20:00:00:00:00:01"


blastee_ip = ""
no_pkts_by_blaster = 0
variable_payload_len_bytes = 0
sender_window_size_in_packets = 0
coarse_timeout_ms = 0
recv_timeout_ms = 0

seq_num = 0
lhs = 1 # since sequence number is starting from 1, make its default value same as that of seq_num
rhs = 0

window = collections.OrderedDict() # seq_num : [pkt, ack_received(boolean), transmission_state] 

curr_time = time.time()

lhs_update_time = curr_time

reset_time_out = curr_time

local_re_count = 0

net_object  = None

# Statistics Variables
start_time = 0
end_time = 0
no_success_ack_recv = 0
no_of_retransmissions = 0
no_of_coarse_to = 0
total_send_pkt_calls = 0


def switchy_main(net):
    global net_object
    global no_of_coarse_to
    global reset_time_out
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    read_parameters()
    net_object = net

    while True:
        gotpkt = True
        update_lhs_window()
        
        # blaster processing done print the statistics
        if no_success_ack_recv >= no_pkts_by_blaster:
           print_statistics()
           break

        if is_lhs_timeout() == True:
           if(is_transmission_timeout() == True):
              if(all_retransmit_done() == True or local_re_count == 0): 
                 log_info("Updating reset time")
                 reset_window()
                 reset_time_out = time.time()
                 no_of_coarse_to = no_of_coarse_to+1
           retransmit_packets_with_timeout()
           
        try:
            #Timeout value will be parameterized!
            recv_data = net.recv_packet(timeout=(recv_timeout_ms/1000))
            dev = recv_data.input_port
            pkt = recv_data.packet
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet " + str(pkt))
            comingFromBlastee = isComingFromBlastee(pkt)
            #log_info("Coming From Blastee " + str(comingFromBlastee))
            if comingFromBlastee == True :
               received_seq_num = get_sequence_num(pkt)
               update_ack_status(received_seq_num)
            
        else:
            log_info("Didn't receive anything")
            log_info("RHS " + str(rhs) + " LHS " + str(lhs))

            if rhs-lhs+1 >= sender_window_size_in_packets :
               log_info("Sender window is full")
               continue # cannot send more since window is full

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[1].protocol = IPProtocol.UDP

            '''
            Do other things here and send packet
            '''
            
            pkt = modify_ethernet_layer(pkt)
            pkt = modify_ip_layer(pkt)
            pkt = modify_transport_layer(pkt)

            pkt = add_seq_number(pkt)
            pkt = add_length(pkt)
            pkt = add_payload(pkt)
            
            #add pkt to sender_window
            add_pkt_to_window(pkt)

            # Send the modified packet
            log_info("Sending seq num " + str(seq_num))
            send_packet(pkt)

    net.shutdown()

def isComingFromBlastee(pkt):
   if pkt.has_header(IPv4):
      #log_info("Src IP : " + str(pkt[IPv4].src) + " Blastee IP " + BLASTEE_IP)
      if str(pkt[IPv4].src) == BLASTEE_IP:
         return True
   return False


def print_statistics():
   total_tx_time = (end_time - start_time)
   throughput = (total_send_pkt_calls * variable_payload_len_bytes)/total_tx_time # Bps
   good_count = total_send_pkt_calls - no_of_retransmissions
   goodput = (good_count * variable_payload_len_bytes)/total_tx_time # Bps
   print ("Total TX Time (in seconds) " + str(total_tx_time))
   print ("Number of reTX : " + str(no_of_retransmissions))
   print ("Number of coarse TOs : " + str(no_of_coarse_to))
   print ("Throughput(Bps) : " + str(throughput))
   print ("Goodput(Bps) : " + str(goodput))
   


def retransmit_packets():
   log_info("Inside retransmit_packets")
   global no_of_retransmissions
   for key, value in window.items():
      if value[1] ==  False: # ack is not received
         # resend the packet
         #log_info("Retransmission sending for seq_num " + str(key))
         send_packet(value[0])
         no_of_retransmissions = no_of_retransmissions+1
      else:
        log_info("Ack Already There so not sending ")

def retransmit_packets_with_timeout():
   log_info("Inside retransmit_packets with_timeout")
   global no_of_retransmissions
   global reset_time_out
   global local_re_count
   for key, value in window.items():
      if value[1] ==  False and value[2] == False: # ack is not received and transmission not sent
         # resend the packet
         #log_info("Retransmission sending for seq_num " + str(key))
         send_packet(value[0])
         value[2] = True # Retrasmission done so dont send again
         no_of_retransmissions = no_of_retransmissions+1
         local_re_count += 1
         break
      else:
         log_info("Ack Already There or transmission sent so not sending ")

def all_retransmit_done():
   for key, value in window.items():
      if value[1] == False and value[2] == False:
         return False
   return True

def reset_window():
   log_info("Resetting window tramission state")
   global local_re_count
   local_re_count = 0
   for key, value in window.items():
      if value[1] == False: # Ack not present then only reset transmission
         value[2] = False
      

def is_lhs_timeout():
   log_info("Inside is_lhs_timeout")
   time_diff = (time.time() - lhs_update_time)*1000
   log_info("Time Diff " + str(time_diff))
   if time_diff >= coarse_timeout_ms:
      return True
   return False 

def is_transmission_timeout():
   log_info("Inside is_transmission_timeout")
   time_diff = (time.time() - reset_time_out)*1000
   log_info("Time Diff " + str(time_diff))
   if time_diff >= coarse_timeout_ms:
      return True
   return False 


# move the lhs forward if possible and delete all the processed packets
def update_lhs_window():
   global window
   global lhs
   global rhs
   global lhs_update_time
   global reset_time_out
   global no_success_ack_recv
   global end_time
   keys_to_delete = []
   
   for key, value in window.items():
      if value[1] ==  True: # ack is received
         if key == lhs: # if this packet seq_num same as lhs, left most packet
            lhs = lhs+1
            local_time = time.time()
            lhs_update_time = local_time
            reset_time_out = local_time
            reset_window()
            no_success_ack_recv = no_success_ack_recv+1
            keys_to_delete.append(key)
      else:
         break # if ack is false no need to check full window
   
   for key in keys_to_delete:
      del window[key]
   
	# Ack received for the last packet
   if no_success_ack_recv >= no_pkts_by_blaster:
      end_time = time.time()


def update_ack_status(received_seq_num):
   global window
   if is_present(window, received_seq_num) is True:
      # change the ack state of the packet to true
      window[received_seq_num][1] = True
      window[received_seq_num][2] = True # Since ack is received will not retransmit this ever
      #log_info("Ack state changed to true for seq_num " + str(received_seq_num))
   else:
      log_info("Unknown seq_num received ")



def get_sequence_num(pkt):
   #log_info("Inside get_sequence_num")
   raw = pkt[RawPacketContents].data
   sequence_num = raw[0:32] 
   #log_info("Sequence Number before decode " + str(sequence_num))
   # 4bytes 32 bits
   # decode this before sending
   sequence_num = get_decoded_data(sequence_num)
   log_info("sequence number after decode ")
   return to_int(sequence_num)

def add_pkt_to_window(pkt):
   global window
   global rhs
   curr_seq_num = seq_num
   window[curr_seq_num] = [pkt, False, False]
   rhs = curr_seq_num 


def is_present(maps, to_match):
   log_info("Inside is_present")
   for key, value in maps.items():
      if str(to_match) ==  str(key):
         log_info("Match Returning True")
         return True
   return False

def modify_ethernet_layer(pkt):
   pkt[Ethernet].src = BLASTER_MAC
   pkt[Ethernet].dst = MIDDLEBOX_BLASTER_MAC
   return pkt

def modify_ip_layer(pkt):
   pkt[IPv4].src = BLASTER_IP
   pkt[IPv4].dst = BLASTEE_IP
   return pkt

def modify_transport_layer(pkt):
   # Setting random values
   pkt[UDP].src = 4444 
   pkt[UDP].dst = 5555
   return pkt

def add_seq_number(pkt):
  log_info("Inside add_seq_number")
  global seq_num
  seq_num = seq_num + 1 
  #string = to_string(seq_num)
  #log_info("Putting sequence number " + str(seq_num))
  intermediate_data = convert_to_binary(seq_num,32) # will convert seq number to 32 bit
  encoded_data = get_encoded_data(intermediate_data)
  #log_info("Data after encoding " + str(encoded_data))
  pkt += encoded_data
  return pkt


def add_length(pkt):
  log_info("Inside add_length")
  length = variable_payload_len_bytes
  #string = to_string(length)
  #log_info("Putting length " + str(length))
  intermediate_data = convert_to_binary(length,16) # will convert length to 16 bit
  encoded_data = get_encoded_data(intermediate_data)
  #log_info("length after encoding " + str(encoded_data))

  pkt += encoded_data
  return pkt

def add_payload(pkt):
   log_info("Inside add_payload")
   length = variable_payload_len_bytes
   #length = length/2 # Doing because of UTF-16
   #data = get_data_of_given_length(length)
   data = get_data()
   #log_info("Putting payload " + str(data))
   intermediate_data = convert_to_binary(data,length) # will convert payload to length
   encoded_data = get_encoded_data(intermediate_data)
  
   #log_info("Payload after encoding " + str(encoded_data))
   pkt += encoded_data
   return pkt

def get_data_of_given_length(length):
   data = 8 
   #for i in range(length):
   #   string = string+"a"
   return data

def get_data():
   data = 8
   return data


def get_encoded_data(data_to_encode):
   data_bytes = bytes(data_to_encode, 'ascii')
   converter = struct.Struct('>' + str(len(data_bytes)) + 'B')
   
   return converter.pack(*data_bytes)

def get_decoded_data(data_to_decode):
   decoded_data = int(data_to_decode,2)
   return decoded_data

def convert_to_binary(data, total_length):
   return bin(data)[2:].zfill(total_length)

def to_int(ip_string):
   return int(ip_string)

def to_string(ip_int):
   return str(ip_int)

def send_packet(pkt):
  log_info("sending packet " + str(pkt))
  global start_time
  global total_send_pkt_calls
  total_send_pkt_calls = total_send_pkt_calls+1
  out_inf = net_object.interface_by_ipaddr(BLASTER_IP)
  if start_time == 0: # will be set only one time, on sending first packet
     start_time = time.time()
  net_object.send_packet(out_inf,pkt)

def read_parameters():
   log_info("reading parameters from file " + str(param_file_name))
   global blastee_ip
   global no_pkts_by_blaster
   global variable_payload_len_bytes
   global sender_window_size_in_packets
   global coarse_timeout_ms
   global recv_timeout_ms

   contents = open(param_file_name,"r")

   for line in contents.readlines():
      value = line.split()
      blastee_ip = value[1]
      no_pkts_by_blaster = int(value[3])
      variable_payload_len_bytes = int(value[5])
      sender_window_size_in_packets = int(value[7])
      coarse_timeout_ms = float(value[9])
      recv_timeout_ms = float(value[11])
      log_info("Blastee Ip : " + str(blastee_ip) + " No of packets : " + str(no_pkts_by_blaster) + " payload_len " + str(variable_payload_len_bytes))
      log_info("sender_window_size : " + str(sender_window_size_in_packets) + " coarse_timeout_ms : " + str(coarse_timeout_ms) + " recv_timeout_ms " + str(recv_timeout_ms))
