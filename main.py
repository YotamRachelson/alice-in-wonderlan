import scapy.all as scapy


PRIVATE_LEG = "enp0s8"
PROXY_LEG = "enp0s9"
PRIVATE_LEG_IP = "192.168.57.3"
PROXY_LEG_IP = "192.168.131.4"


def main():
    pkt = scapy.sniff(iface=[PRIVATE_LEG, PROXY_LEG], prn=proxy_logic, filter = "ip")


def proxy_logic(pkt):
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
