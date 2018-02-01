from switchyard.lib.userlib import *
import time


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forwarding_table = {}
    time_table = {}

    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        packet_header = packet[0];

        if (packet_header.src in forwarding_table):
            pass
        else:
            sorted_keys = sorted(time_table, key=time_table.get)
            if (len(sorted_keys) < 5):
                pass
            else:
                key_to_remove = sorted_keys[0]
                del time_table[key_to_remove]
                del forwarding_table[key_to_remove]

        if (packet_header.src not in forwarding_table):
            time_table_tuple = {packet_header.src: time.time()}
            time_table.update(time_table_tuple)

        corresponsing_forwarding_tuple = {packet_header.src: input_port}
        forwarding_table.update(corresponsing_forwarding_tuple)

        destination_address = packet_header.dst
        destination_port_from_table = forwarding_table.get(destination_address)

        if destination_address in mymacs:
            log_debug("Packet intended for me")
        elif destination_port_from_table is not None:
            net.send_packet(destination_port_from_table, packet)
            time_table_tuple = {destination_address: time.time()}
            time_table.update(time_table_tuple)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
