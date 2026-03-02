import scapy.all as scapy


class FW:
    def __init__(self, bad_src_mac=None, bad_dst_mac=None, bad_src_ip=None,\
        bad_dst_ip=None, bad_src_port=None, bad_dst_port=None, bad_udp=False, bad_tcp=False):
        self.bad_src_mac = bad_src_mac
        self.bad_dst_mac = bad_dst_mac
        self.bad_src_ip = bad_src_ip
        self.bad_dst_ip = bad_dst_ip
        self.bad_src_port = bad_src_port
        self.bad_dst_port = bad_dst_port
        self.bad_udp = bad_udp
        self.bad_tcp = bad_tcp

    def _bad_layer_2(self, packet):
        if not scapy.Ether in packet:
            return False
        elif packet.src == self.bad_src_mac or packet.dst == self.bad_dst_mac:
            return True
        else:
            return False

    def _bad_layer_3(self, packet):
        if not scapy.IP in packet:
            return False
        elif packet['IP'].src == self.bad_src_ip or packet['IP'].dst == self.bad_dst_ip:
            return True
        else:
            return False

    def _bad_layer_4(self, packet):
        if not scapy.TCP in packet and not scapy.UDP in packet:
            return False
        elif packet.sport == self.bad_src_port or packet.dst == self.bad_dst_port:
            return True
        else:
            return False

    def _bad_protocol(self, packet):
        if (self.bad_tcp and scapy.TCP in packet) or (self.bad_udp and scapy.UDP in packet):
            return True
        else:
            return False
        
    def should_drop_packet(self, packet):
        if self._bad_layer_2(packet) \
            or self._bad_layer_3(packet) \
            or self._bad_layer_4(packet) \
            or self._bad_protocol(packet):
            print("Firewall dropped the packet")
            return True
        else:
            return False

