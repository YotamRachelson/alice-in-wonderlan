import scapy.all as scapy
import random


PRIVATE_LEG = "enp0s8"
NAT_LEG = "enp0s9"
PRIVATE_LEG_IP = "192.168.57.3"
NAT_LEG_IP = "192.168.131.4"
LOCALHOST = "127.0.0.1"
MIN_PORT = 1024
MAX_PORT = 65535


class Session:
    sessions = []
    count = 0

    def __init__(self, packet):
        if packet['IP'].src != PRIVATE_LEG_IP:
            return
        self.id = None
        self.src_ip = packet['IP'].src
        self.dst_ip = packet['IP'].dst
        self.src_port = None
        self.dst_port = None
        self.icmp_seq = None
        if scapy.TCP in packet or scapy.UDP in packet:
            self.src_port = packet.sport
            self.generated_src_port = random.randrange(MIN_PORT, MAX_PORT + 1)
            self.dst_port = packet.dport
        elif scapy.ICMP in packet:
            self.icmp_seq = packet['ICMP'].seq

    def __repr__(self):
        return f"session {self.id} - {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"

    def __eq__(self, other):
        if self.dst_ip == other.dst_ip and self.src_ip == other.src_ip:
            if self.src_port is not None \
            and self.src_port == other.src_port \
            and self.dst_port == other.dst_port:
                return True
            elif self.icmp_seq is not None and self.icmp_seq == other.icmp_seq + 1:
                return True
            else:
                return False
        else:
            return False

    def is_new_session(self):
        for existing_session in Session.sessions:
            if self == existing_session:
                # changing the generated src prt to the existing one
                if self.src_port is not None:
                    self.generated_src_port = existing_session.generated_src_port
                elif existing_session.icmp_seq is not None:
                    existing_session.icmp_seq += 1
                return False
        self.id = Session.count + 1
        Session.count += 1
        return True


    @classmethod
    def get_session_src(cls, packet):
        for session in cls.sessions:
            if packet['IP'].src == session.dst_ip:
                if (scapy.TCP in packet or scapy.UDP in packet) \
                    and packet.sport == session.dst_port \
                    and packet.dport == session.generated_src_port:
                        return (session.src_ip, session.src_port)
                else:
                    return (session.src_ip, None)
        return (None, None)


def nat_logic(packet):
    packet = packet[0]
    # for sending packets on the private leg - convert and send on the NAT leg
    if packet.sniffed_on == PRIVATE_LEG and packet['IP'].src == PRIVATE_LEG_IP:
        session = Session(packet)
        if session.is_new_session():
            Session.sessions.append(session)
            print(f"added {session}")
        print(f"Instead of {packet.summary()}")
        packet['IP'].src = NAT_LEG_IP
        if scapy.TCP in packet or scapy.UDP in packet:
            packet.sport = session.generated_src_port
        print(f"Sending {packet.summary()}")
        scapy.sendp(packet, iface=NAT_LEG, verbose=0)
    # for receiving packets on the NAT leg - convert and send on the private leg
    elif packet.sniffed_on == NAT_LEG and packet['IP'].dst == NAT_LEG_IP:
        dst_ip, dst_port = Session.get_session_src(packet)
        if dst_ip is None:
            return
        print(f"Instead of {packet.summary()}")
        packet['IP'].dst = dst_ip
        if scapy.TCP in packet or scapy.UDP in packet:
            packet['IP'].dport = dst_port
        print(f"Receiving {packet.summary()}")
        scapy.sendp(packet, iface=PRIVATE_LEG, verbose=0)


def main():
    scapy.sniff(iface=[PRIVATE_LEG, NAT_LEG], prn=nat_logic, filter="ip")


if __name__ == "__main__":
    main()
