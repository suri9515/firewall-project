from scapy.all import sniff, IP, TCP, UDP, ICMP
import json
from logger import log_packet
from utils import apply_iptables_rule

class Firewall:
    def __init__(self, rule_file="rules.json"):
        with open(rule_file, 'r') as f:
            self.rules = json.load(f)
    
    def match_rule(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto

            if 'block_ips' in self.rules and (src_ip in self.rules['block_ips'] or dst_ip in self.rules['block_ips']):
                log_packet(packet, "Blocked IP")
                return False

            if proto == 6 and 'block_ports' in self.rules:  # TCP
                if TCP in packet and (packet[TCP].sport in self.rules['block_ports'] or packet[TCP].dport in self.rules['block_ports']):
                    log_packet(packet, "Blocked TCP port")
                    return False
            elif proto == 17 and 'block_ports' in self.rules:  # UDP
                if UDP in packet and (packet[UDP].sport in self.rules['block_ports'] or packet[UDP].dport in self.rules['block_ports']):
                    log_packet(packet, "Blocked UDP port")
                    return False
            elif proto == 1 and 'block_protocols' in self.rules and "ICMP" in self.rules['block_protocols']:  # ICMP
                log_packet(packet, "Blocked ICMP protocol")
                return False
        return True

    def start(self):
        sniff(prn=self.process_packet, store=0)

    def process_packet(self, packet):
        if not self.match_rule(packet):
            return
        print(packet.summary())
