import pytest
import time
from src.feature_extraction.extractor import Flow, FlowTracker

def test_flow_initialization():
    """Tests that a network flow is initialized correctly."""
    flow = Flow(src_ip="192.168.1.5", src_port=443, dst_ip="10.0.0.5", dst_port=12345, protocol=6)
    assert flow.src_ip == "192.168.1.5"
    assert flow.src_port == 443
    assert flow.dst_ip == "10.0.0.5"
    assert flow.dst_port == 12345
    assert flow.protocol == 6
    assert flow.packet_count == 0
    assert flow.fwd_packets == 0
    assert flow.bwd_packets == 0

def test_flow_adding_packets():
    """Tests updating flow state when adding packets in forward and backward directions."""
    flow = Flow(src_ip="192.168.1.5", src_port=443, dst_ip="10.0.0.5", dst_port=12345, protocol=6)
    
    # Add a forward packet
    flow.add_packet(packet_len=100, ttl=64, flags=0x02, is_forward=True, timestamp=1000.0)
    assert flow.packet_count == 1
    assert flow.fwd_packets == 1
    assert flow.bwd_packets == 0
    assert flow.fwd_bytes == 100
    assert flow.first_timestamp == 1000.0
    assert flow.last_timestamp == 1000.0
    
    # Add a backward packet
    flow.add_packet(packet_len=50, ttl=128, flags=0x12, is_forward=False, timestamp=1002.0)
    assert flow.packet_count == 2
    assert flow.fwd_packets == 1
    assert flow.bwd_packets == 1
    assert flow.bwd_bytes == 50
    assert flow.first_timestamp == 1000.0
    assert flow.last_timestamp == 1002.0

def test_flow_feature_extraction():
    """Tests that Flow.get_features returns the expected 11 features matching the ML schema."""
    flow = Flow(src_ip="192.168.1.5", src_port=443, dst_ip="10.0.0.5", dst_port=12345, protocol=6)
    flow.add_packet(packet_len=100, ttl=64, flags=0x02, is_forward=True, timestamp=1000.0)
    flow.add_packet(packet_len=50, ttl=128, flags=0x12, is_forward=False, timestamp=1002.0)
    
    features = flow.get_features()
    
    assert features["src_ip"] == "192.168.1.5"
    assert features["dst_ip"] == "10.0.0.5"
    assert features["Source Port"] == 443
    assert features["Destination Port"] == 12345
    assert features["Protocol"] == 6
    assert features["Packet Length"] == 75.0  # Average of 100 and 50
    assert features["TTL"] == 96  # Average of 64 and 128
    assert features["TCP Flags"] == 0x12 | 0x02  # Bitwise OR of flags
    assert features["Flow Duration"] == 2.0 * 1_000_000.0  # 2 seconds in microseconds
    assert features["Packets Per Second"] == 2 / 2.0
    assert features["Bytes Per Second"] == 150 / 2.0
    assert features["Forward Packets"] == 1
    assert features["Backward Packets"] == 1

def test_flow_tracker_mock_packet():
    """Tests the FlowTracker's ability to process and aggregate packets."""
    tracker = FlowTracker()
    
    # Mock packet class for testing
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

    # Packet 1 (Forward)
    pkt1 = MockPacket("192.168.1.10", "10.0.0.1", 12345, 80, 6, 64, 0x02, 100, 100.0)
    # Packet 2 (Backward - same flow)
    pkt2 = MockPacket("10.0.0.1", "192.168.1.10", 80, 12345, 6, 128, 0x12, 150, 101.0)
    
    features1, valid1 = tracker.process_packet(pkt1)
    assert valid1 is True
    assert features1 is not None
    assert features1["Forward Packets"] == 1
    assert len(tracker.flows) == 1
    
    features2, valid2 = tracker.process_packet(pkt2)
    assert valid2 is True
    assert features2 is not None
    assert features2["Forward Packets"] == 1
    assert features2["Backward Packets"] == 1
    assert len(tracker.flows) == 1  # Should still be 1 bidirectional flow
