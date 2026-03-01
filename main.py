import scapy.all as scapy


PRIVATE_LEG = "enp0s8"
NAT_LEG = "enp0s9"
PRIVATE_LEG_IP = "192.168.57.3"
NAT_LEG_IP = "192.168.131.4"
MIN_PORT = 10000
MAX_PORT = 65535


class Session:
    sessions = []
    def __init__(self, src_ip, dst_ip, src_port=None, dst_port=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        Session.sessions.append(self)

    def __repr__(self):
        return "hi"

    def __eq__(self, other):
        pass

def main():
    pkt = scapy.sniff(iface=[PRIVATE_LEG, PROXY_LEG], prn=proxy_logic, filter="ip")


def nat_logic(pkt):
    
    if pkt.sniffed_on == PRIVATE_LEG and pkt[0]['IP'].src == PRIVATE_LEG_IP:
        print(f"Instead of {pkt.summary()}")
        pkt[0]['IP'].src = PROXY_LEG_IP
        print(f"Sending {pkt.summary()}")
        scapy.sendp(pkt, iface=PROXY_LEG, verbose=0)
    elif pkt.sniffed_on == PROXY_LEG and pkt[0]['IP'].dst == PROXY_LEG_IP:
        print(f"Instead of {pkt.summary()}")
        pkt[0]['IP'].dst = PRIVATE_LEG_IP
        print(f"Receiving {pkt.summary()}")
        scapy.sendp(pkt, iface=PRIVATE_LEG, verbose=0)


if __name__ == "__main__":
    main()

