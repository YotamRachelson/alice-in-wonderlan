from abc import ABC, abstractmethod
from typing import Tuple, Any
import scapy.all as scapy
import re


class Rule(ABC):
    RULE_DICT = {}
    EXISTENT_VALUE = "True"
    NON_EXISTENT_VALUE = "False"


    def __init_subclass__(cls, fields=None, **kwargs):
        super().__init_subclass__(**kwargs)
        if fields is not None:
            # Register the class for each field
            for field in fields:
                Rule.RULE_DICT[field] = cls

    def __new__(cls, config_line, *args, **kwargs):
        rule_parts = re.split('=|,', config_line.strip())
        field, values = rule_parts[0], {value for value in rule_parts[1:]}

        rule_cls = cls.RULE_DICT.get(field)
        if rule_cls is None:
            raise ValueError(f"Unknown rule field: {field}")

        obj = super().__new__(rule_cls)
        obj.field = field
        obj.values = values
        return obj

    @abstractmethod
    def check(self, packet, invalid_fields) -> Tuple[bool, Any]:
        pass


class L2Rule(Rule, fields=["src_mac", "dst_mac"]):
    def check(self, packet):
        if not scapy.Ether in packet:
            return False, None
        HEADERS = {"src_mac": packet.src, "dst_mac": packet.dst}
        return HEADERS[self.field] in self.values, HEADERS[self.field]


class L3Rule(Rule, fields=["src_ip", "dst_ip"]):
    def check(self, packet):
        if not scapy.IP in packet:
            return False, None
        HEADERS = {"src_ip": packet['IP'].src, "dst_ip": packet['IP'].dst}
        return HEADERS[self.field] in self.values, HEADERS[self.field]


class L4Rule(Rule, fields=["src_port", "dst_port"]):
    def check(self, packet):
        if not scapy.TCP in packet and not scapy.UDP in packet:
            return False, None
        HEADERS = {"src_port": packet.sport, "dst_port": packet.dport}
        return str(HEADERS[self.field]) in self.values, HEADERS[self.field]

 
class ProtocolRule(Rule, fields=["ethernet", "ip", "udp", "tcp"]):
    # returns whether the user rule takes place and whether the protocol exists
    def check(self, packet):
        HEADERS = {"udp": scapy.UDP, "tcp": scapy.TCP, "ip": scapy.IP, "ethernet": scapy.Ether}
        protocol_exists = HEADERS[self.field] in self.values
        # if user wants the protocol to exist - (True, True) / (False, False)
        if self.EXISTENT_VALUE in self.values:
            return protocol_exists, protocol_exists
        # if user wants the protocol to exist - (True, False) / (False, True)
        else:
            return not protocol_exists, protocol_exists