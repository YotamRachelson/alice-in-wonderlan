import scapy.all as scapy


SNIFFED_LEG = "enp0s8"
DESTINATION_LEG = "enp0s9"


def main():
    scapy.sniff(iface=SNIFFED_LEG, prn=lambda pkt: scapy.sendp(pkt, iface=DESTINATION_LEG, verbose=1))


if __name__ == "__main__":
    main()
