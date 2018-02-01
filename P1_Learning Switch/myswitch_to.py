from switchyard.lib.userlib import *
import time


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forwarding_table = {}
    time_table = {}
    timeout = 10
    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        packet_header = packet[0];

        keys = time_table.keys()
        items_to_delete = []
        for item in keys:
            if time.time() - time_table.get(item) >= timeout:
                items_to_delete.append(item)

        for item in items_to_delete:
            del forwarding_table[item]
            del time_table[item]

        corresponsing_forwarding_tuple = {packet_header.src: input_port}
        forwarding_table.update(corresponsing_forwarding_tuple)

        time_tuple = {packet_header.src: time.time()}
        time_table.update(time_tuple)

        destination_address = packet_header.dst
        destination_port_from_table = forwarding_table.get(destination_address)

        if destination_address in mymacs:
            log_debug("Packet intended for me")
        elif destination_port_from_table is not None:
            net.send_packet(destination_port_from_table, packet)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
