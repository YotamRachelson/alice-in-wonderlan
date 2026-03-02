import scapy.all as scapy
import random


PRIVATE_LEG = "enp0s8"
NAT_LEG = "enp0s9"
PRIVATE_LEG_IP = "192.168.57.3"
NAT_LEG_IP = "192.168.131.4"
MIN_PORT = 1024
MAX_PORT = 65535


class Session:
    sessions = []

    def __init__(self, packet):
        if packet['IP'].src != PRIVATE_LEG_IP:
            return
        self.src_ip = packet['IP'].src
        self.dst_ip = packet['IP'].dst
        if scapy.TCP in packet or scapy.UDP in packet:
            self.src_port = packet.sport
            self.generated_src_port = random.randrange(MIN_PORT, MAX_PORT + 1)
            self.dst_port = packet.dport
        elif scapy.ICMP in packet:
            self.icmp_seq = packet['ICMP'].seq

    def __repr__(self):
        return f"{self.src_ip} -> {self.dst_ip}"

    def __eq__(self, other):
        if self.dst_ip == other.dst_ip and self.src_ip == other.src_ip:
            if self.src_port is not None \ 
            and self.src_port == other.src_port \
            and self.dst_port == other.dst_port:
                return True
            elif self.icmp_seq is not None and self.icmp_seq == other.icmp_seq:
                return True
            else:
                return False
        else:
            return False

    def is_new_session(self):
        is_new_session = True
        for existing_session in Session.sessions:
            if self == existing_session:
                is_new_session = False
                # changing the generated src prt to the existing one
                self.generated_src_port = existing_session.generated_src_port
        return is_new_session

    @classmethod
    def get_session_src(cls, packet):
        for session is cls.sessions:
            if packet['IP'].src == session.dst_ip \
                and packet.sport == session.dst_port \
                and packet.dport == session.generated_src_port:
                    return (session.src_ip, session.src_port)
        

def main():
    scapy.sniff(iface=[PRIVATE_LEG, PROXY_LEG], prn=nat_logic, filter="ip")


def nat_logic(packet):
    packet = packet[0]
    if packet.sniffed_on == PRIVATE_LEG and packet['IP'].src == PRIVATE_LEG_IP:
        session = Session(packet)
        if session.is_new_session():
            Session.sessions.append(session)
        print(f"Instead of {packet.summary()}")
        packet['IP'].src = NAT_LEG_IP
        packet.sport = session.generated_src_port
        print(f"Sending {packet.summary()}")
        scapy.sendp(packet, iface=PROXY_LEG, verbose=0)
    elif packet.sniffed_on == NAT_LEG and packet['IP'].dst == NAT_LEG_IP:
        print(f"Instead of {packet.summary()}")
        packet['IP'].dst, packet.dport = Session.get_session_src(packet)
        print(f"Receiving {packet.summary()}")
        scapy.sendp(pkt, iface=PRIVATE_LEG, verbose=0)


if __name__ == "__main__":
    main()
