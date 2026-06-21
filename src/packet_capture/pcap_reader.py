import os
import logging
from typing import List, Dict, Any
from scapy.utils import PcapReader

from src.feature_extraction.extractor import FlowTracker

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def read_pcap_flows(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Reads a PCAP file, parses its IP packets, updates bidirectional flows, 
    and returns a list of dictionaries representing the extracted flow features.
    
    Args:
        pcap_path: Path to the PCAP file.
        
    Returns:
        List of dictionaries with features ready for the machine learning model.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
    logger.info(f"Opening PCAP file for parsing: {pcap_path}")
    tracker = FlowTracker()
    packet_count = 0
    valid_ip_count = 0
    
    try:
        # Use streaming PcapReader to avoid loading huge PCAP files entirely in memory
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                packet_count += 1
                _, valid = tracker.process_packet(pkt)
                if valid:
                    valid_ip_count += 1
                    
                if packet_count % 10000 == 0:
                    logger.info(f"Parsed {packet_count} packets... ({valid_ip_count} valid IP packets)")
                    
    except Exception as e:
        logger.error(f"Error parsing PCAP file '{pcap_path}': {e}")
        raise e
        
    flows = tracker.get_all_flows()
    logger.info(f"PCAP parsing complete. Total packets: {packet_count}, "
                f"Valid IP packets: {valid_ip_count}, Extracted flows: {len(flows)}")
    return flows

if __name__ == "__main__":
    # Self-test block: Creates a mock PCAP file and reads it back to verify functionality
    TEST_PCAP = "test_temp.pcap"
    logger.info("Initializing self-test for Packet Parser...")
    
    try:
        from scapy.all import IP, TCP, wrpcap
        
        logger.info("Generating a temporary test PCAP file with Scapy...")
        # Simulate a simple TCP handshake exchange
        packets = [
            IP(src="192.168.1.50", dst="10.0.0.99", ttl=64)/TCP(sport=54321, dport=80, flags="S", seq=1000),
            IP(src="10.0.0.99", dst="192.168.1.50", ttl=128)/TCP(sport=80, dport=54321, flags="SA", seq=2000, ack=1001),
            IP(src="192.168.1.50", dst="10.0.0.99", ttl=64)/TCP(sport=54321, dport=80, flags="A", seq=1001, ack=2001)
        ]
        # Set packet timestamps manually for flow duration calculation
        packets[0].time = 1718973600.00
        packets[1].time = 1718973600.05
        packets[2].time = 1718973600.10
        
        wrpcap(TEST_PCAP, packets)
        logger.info(f"Mock PCAP written to {TEST_PCAP}")
        
        # Test parser
        flows = read_pcap_flows(TEST_PCAP)
        logger.info(f"Extracted flows detail:")
        for i, flow in enumerate(flows):
            logger.info(f"Flow {i+1}: {flow}")
            
    except ImportError:
        logger.error("Scapy is not installed. Please make sure to install requirements first.")
    except Exception as e:
        logger.error(f"Test failed with error: {e}")
    finally:
        # Cleanup temporary PCAP file
        if os.path.exists(TEST_PCAP):
            os.remove(TEST_PCAP)
            logger.info("Temporary test PCAP file cleaned up.")
