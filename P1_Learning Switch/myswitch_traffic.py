from switchyard.lib.userlib import *


def main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forwarding_table = {}
    traffic_table = {}
    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        packet_header = packet[0]

        if packet_header.src in forwarding_table:
            pass
        else:
            length = len(forwarding_table)
            if length < 5:
                pass
            else:
                sorted_keys = sorted(traffic_table, key=traffic_table.get)
                key_evict = sorted_keys[0]
                del forwarding_table[key_evict]
                del traffic_table[key_evict]

        if (packet_header.src not in forwarding_table):
            traffic_tuple = {packet_header.src: 0}
            traffic_table.update(traffic_tuple)

        corresponsing_forwarding_tuple = {packet_header.src: input_port}
        forwarding_table.update(corresponsing_forwarding_tuple)

        destination_address = packet_header.dst
        destination_port_from_table = forwarding_table.get(destination_address)

        if destination_address in mymacs:
            log_debug("Packet intended for me")
        elif destination_port_from_table is not None:
            traffic = traffic_table.get(destination_address) + 1
            traffic_tuple = {destination_address: traffic}
            traffic_table.update(traffic_tuple)
            net.send_packet(destination_port_from_table, packet)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()