import scapy.all as scapy


LEG_1 = "enp0s8"
LEG_2 = "enp0s9"


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
                scapy.sendp(packet, iface=iface.name, verbose=False)
                print(f"routed \'{packet}\' to {subnet}/{subnet.mask}")


def main():
    ifaces = [LEG_1, LEG_2]
    router = Router(ifaces)
    scapy.sniff(iface=ifaces, prn=router.route, filter="ip")


if __name__ == "__main__":
    main()
