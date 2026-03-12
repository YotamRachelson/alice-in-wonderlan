import scapy.all as scapy


LEG_1 = "enp0s8"
LEG_2 = "enp0s9"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class Router:
    def __init__(self, ifaces, netmask=24):
        self.ifaces = [scapy.conf.ifaces[iface] for iface in ifaces]
        self.netmask = netmask

    def route(self, packet):
        other_ifaces = [iface for iface in self.ifaces if packet.sniffed_on != iface.name]
        for iface in other_ifaces:
            subnet = scapy.Net(f"{iface.ip}/{self.netmask}")
            # route the packet only if destined to the subnet of another router leg
            if packet['IP'].dst in subnet:
                packet.ttl -= 1
                packet.src = iface.mac
                # if mac address could be resolved and packet was not destined to the router itself- resolve, otherwise drop packet
                dst_mac = scapy.getmacbyip(packet['IP'].dst)
                # dst_mac == BROADCAST_MAC if the packet dst ip was of one of the router interfaces - we dont want it to be forwarded in this case
                if dst_mac == BROADCAST_MAC or dst_mac is None:
                    print("dropped packet - couldn't resolve mac address properly")
                    return
                else:
                    packet.dst = dst_mac
                scapy.sendp(packet, iface=iface.name, verbose=False)
                print(f"routed \'{packet}\' to {subnet}/{subnet.mask}")


def main():
    ifaces = [LEG_1, LEG_2]
    router = Router(ifaces)
    scapy.sniff(iface=ifaces, prn=router.route, filter="ip")


if __name__ == "__main__":
    main()
