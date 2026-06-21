import os
import time
import logging
import threading
from typing import List, Dict, Any, Optional

from scapy.all import sniff, conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from src.feature_extraction.extractor import FlowTracker
from src.inference.predictor import Predictor
from src.alerts.engine import AlertEngine
from src.database.connection import SessionLocal
from src.database.models import DetectionHistory

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class LiveMonitor:
    """Manages real-time network traffic capture, feature extraction, ML inference, and alerting."""

    def __init__(self, interface: str, predictor: Optional[Predictor] = None):
        self.interface = interface
        self.predictor = predictor
        self.alert_engine = AlertEngine(confidence_threshold=90.0)
        self.tracker = FlowTracker()
        
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.processed_flows = 0

    def start(self):
        """Starts sniffing in a daemon thread if not already running."""
        if self.thread and self.thread.is_alive():
            logger.warning(f"Live monitor already running on {self.interface}")
            return
            
        # Ensure predictor is loaded
        if self.predictor is None:
            try:
                self.predictor = Predictor()
            except Exception as e:
                logger.error(f"Cannot start live monitor. Predictor could not be loaded: {e}")
                raise e
                
        self.stop_event.clear()
        self.packet_count = 0
        self.processed_flows = 0
        self.tracker.clear()
        
        self.thread = threading.Thread(
            target=self._sniff_loop,
            name=f"LiveMonitor-{self.interface}",
            daemon=True
        )
        self.thread.start()
        logger.info(f"Live monitoring thread started on interface: {self.interface}")

    def stop(self):
        """Stops the sniffing thread."""
        if not self.thread or not self.thread.is_alive():
            logger.warning("Live monitor is not running.")
            return
            
        logger.info("Stopping live monitor...")
        self.stop_event.set()
        # Join thread with timeout
        self.thread.join(timeout=5.0)
        logger.info("Live monitor stopped.")

    def is_running(self) -> bool:
        """Returns True if the sniffing thread is currently active."""
        return self.thread is not None and self.thread.is_alive()

    def _packet_callback(self, pkt):
        """Callback executed for each sniffed packet."""
        if self.stop_event.is_set():
            return
            
        self.packet_count += 1
        
        try:
            # Process packet through flow tracker
            flow_features, valid = self.tracker.process_packet(pkt)
            if not valid or not flow_features:
                return
                
            # Classify flow using the prediction engine
            db = SessionLocal()
            try:
                # Get prediction
                attack_type, confidence = self.predictor.predict_flow(flow_features)
                
                # Copy and update flow features
                flow_result = flow_features.copy()
                flow_result["attack_type"] = attack_type
                flow_result["confidence"] = confidence
                
                # Save to detection history
                detection = DetectionHistory(
                    src_ip=flow_result.get("src_ip"),
                    dst_ip=flow_result.get("dst_ip"),
                    src_port=int(flow_result.get("src_port", 0)),
                    dst_port=int(flow_result.get("dst_port", 0)),
                    protocol=int(flow_result.get("protocol", 0)),
                    attack_type=attack_type,
                    confidence=confidence
                )
                db.add(detection)
                
                # Process prediction in Alert Engine (commits/saves alert internally if triggered)
                self.alert_engine.process_prediction(db, flow_result)
                
                db.commit()
                self.processed_flows += 1
                
                if self.processed_flows % 100 == 0:
                    logger.info(f"Monitor processed {self.processed_flows} flows (packet count: {self.packet_count})")
                    
            except Exception as e:
                db.rollback()
                logger.error(f"Error processing live flow prediction: {e}")
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error processing packet in callback: {e}")

    def _sniff_loop(self):
        """Internal worker method to run Scapy sniff."""
        # Stop filter checks stop_event to terminate sniffing gracefully
        def stop_filter(pkt):
            return self.stop_event.is_set()

        try:
            logger.info(f"Initiating Scapy sniffing on '{self.interface}'...")
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                stop_filter=stop_filter,
                store=False  # Do not store packets in memory
            )
        except Exception as e:
            logger.error(f"Sniffing error on interface '{self.interface}': {e}")
            self.stop_event.set()


def get_interfaces() -> List[str]:
    """Retrieves a list of available network interface names on the system."""
    try:
        interfaces = [str(iface) for iface in conf.ifaces.keys()]
        if not interfaces:
            from scapy.all import get_if_list
            interfaces = get_if_list()
        return list(set(interfaces))
    except Exception as e:
        logger.error(f"Failed to retrieve interface list: {e}")
        return []

if __name__ == "__main__":
    logger.info("Available network interfaces:")
    ifaces = get_interfaces()
    for iface in ifaces:
        logger.info(f" - {iface}")
