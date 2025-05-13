
from collections import defaultdict
from scapy.all import IP, TCP

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            key = (packet[IP].src, packet[IP].dst,
                   packet[TCP].sport, packet[TCP].dport)
            stats = self.flow_stats[key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time
            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            duration = stats['last_time'] - stats['start_time']
            return {
                'packet_size': len(packet),
                'flow_duration': duration,
                'packet_rate': stats['packet_count'] / duration if duration else 0,
                'byte_rate': stats['byte_count'] / duration if duration else 0,
                'tcp_flags': packet[TCP].flags,
                'window_size': packet[TCP].window
            }
