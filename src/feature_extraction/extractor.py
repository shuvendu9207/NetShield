import time
import logging
from typing import Dict, List, Tuple, Any, Optional

# Setup logging
logger = logging.getLogger(__name__)

class Flow:
    """Represents a bidirectional network flow and tracks its statistics."""

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        
        self.first_timestamp: Optional[float] = None
        self.last_timestamp: Optional[float] = None
        
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        
        self.tcp_flags = 0
        self.total_ttl = 0
        self.total_pkt_len = 0
        self.packet_count = 0

    def add_packet(self, packet_len: int, ttl: int, flags: int, is_forward: bool, timestamp: float):
        """Updates flow state with a new packet."""
        if self.first_timestamp is None:
            self.first_timestamp = timestamp
        self.last_timestamp = timestamp
        
        self.packet_count += 1
        self.total_pkt_len += packet_len
        self.total_ttl += ttl
        self.tcp_flags |= flags
        
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += packet_len
        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_len

    def get_features(self) -> Dict[str, Any]:
        """Calculates and returns the 11 feature dictionary matching the ML model schema."""
        duration_sec = (self.last_timestamp - self.first_timestamp) if (self.last_timestamp and self.first_timestamp) else 0.0
        # Flow duration in microseconds
        duration_us = duration_sec * 1_000_000.0
        
        packets_per_sec = (self.packet_count / duration_sec) if duration_sec > 0 else 0.0
        bytes_per_sec = ((self.fwd_bytes + self.bwd_bytes) / duration_sec) if duration_sec > 0 else 0.0
        avg_packet_len = (self.total_pkt_len / self.packet_count) if self.packet_count > 0 else 0.0
        avg_ttl = int(self.total_ttl / self.packet_count) if self.packet_count > 0 else 64
        
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "Protocol": self.protocol,
            "Source Port": self.src_port,
            "Destination Port": self.dst_port,
            "Packet Length": avg_packet_len,
            "TTL": avg_ttl,
            "TCP Flags": self.tcp_flags,
            "Flow Duration": duration_us,
            "Packets Per Second": packets_per_sec,
            "Bytes Per Second": bytes_per_sec,
            "Forward Packets": self.fwd_packets,
            "Backward Packets": self.bwd_packets
        }


class FlowTracker:
    """Manages and tracks active flows from network packets."""

    def __init__(self):
        self.flows: Dict[Tuple[str, int, str, int, int], Flow] = {}

    def process_packet(self, pkt) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Processes a Scapy packet, updates/creates its flow, and returns flow features."""
        # Check if the packet has an IP layer (IPv4 or IPv6)
        if not (pkt.haslayer("IP") or pkt.haslayer("IPv6")):
            return None, False
            
        # Extract IP layers
        if pkt.haslayer("IP"):
            ip_layer = pkt["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            ttl = ip_layer.ttl
        else:  # IPv6
            ip_layer = pkt["IPv6"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.nh
            ttl = ip_layer.hlim
            
        # Extract Ports and TCP flags
        src_port = 0
        dst_port = 0
        tcp_flags = 0
        
        if pkt.haslayer("TCP"):
            tcp_layer = pkt["TCP"]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            try:
                tcp_flags = int(tcp_layer.flags)
            except Exception:
                flag_str = str(tcp_layer.flags)
                flag_map = {'F': 0x01, 'S': 0x02, 'R': 0x04, 'P': 0x08, 'A': 0x10, 'U': 0x20, 'E': 0x40, 'C': 0x80}
                for char, val in flag_map.items():
                    if char in flag_str:
                        tcp_flags |= val
        elif pkt.haslayer("UDP"):
            udp_layer = pkt["UDP"]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            
        pkt_len = len(pkt)
        timestamp = float(pkt.time) if pkt.time else time.time()
        
        # Define bidirectional flow key 5-tuple
        fwd_key = (src_ip, src_port, dst_ip, dst_port, proto)
        bwd_key = (dst_ip, dst_port, src_ip, src_port, proto)
        
        if fwd_key in self.flows:
            flow = self.flows[fwd_key]
            is_forward = True
        elif bwd_key in self.flows:
            flow = self.flows[bwd_key]
            is_forward = False
        else:
            # Create a new bidirectional flow
            flow = Flow(src_ip, src_port, dst_ip, dst_port, proto)
            self.flows[fwd_key] = flow
            is_forward = True
            
        flow.add_packet(pkt_len, ttl, tcp_flags, is_forward, timestamp)
        return flow.get_features(), True

    def get_all_flows(self) -> List[Dict[str, Any]]:
        """Returns feature dictionaries for all currently tracked flows."""
        return [flow.get_features() for flow in self.flows.values()]
        
    def clear(self):
        """Clears all tracked flows."""
        self.flows.clear()


if __name__ == "__main__":
    # Standard verification block
    logging.basicConfig(level=logging.INFO)
    logger.info("Initializing FlowTracker and verification test...")
    tracker = FlowTracker()
    
    # Create a mock packet-like structure to verify parsing logic
    class MockPacket:
        def __init__(self, src, dst, sport, dport, proto, ttl, flags, length, time_val):
            self.src = src
            self.dst = dst
            self.sport = sport
            self.dport = dport
            self.proto = proto
            self.ttl = ttl
            self.flags = flags
            self.length = length
            self.time = time_val

        def haslayer(self, layer_name):
            if layer_name == "IP" and self.proto in [6, 17]:
                return True
            if layer_name == "TCP" and self.proto == 6:
                return True
            return False

        def __getitem__(self, layer_name):
            return self

        def __len__(self):
            return self.length

    # Simulate 2 packets in a flow (1 forward, 1 backward)
    pkt1 = MockPacket("192.168.1.10", "10.0.0.1", 12345, 80, 6, 64, 0x02, 64, 100.0) # SYN (Fwd)
    pkt2 = MockPacket("10.0.0.1", "192.168.1.10", 80, 12345, 6, 128, 0x12, 60, 100.1) # SYN-ACK (Bwd)

    features1, valid1 = tracker.process_packet(pkt1)
    logger.info(f"Packet 1 features: {features1} (valid: {valid1})")
    
    features2, valid2 = tracker.process_packet(pkt2)
    logger.info(f"Packet 2 features: {features2} (valid: {valid2})")
    
    logger.info("Verification test completed successfully.")
