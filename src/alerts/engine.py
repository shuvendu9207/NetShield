import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from src.database.models import Alert
from src.database.connection import SessionLocal, init_db

# Setup logging
logger = logging.getLogger(__name__)

class AlertEngine:
    """Monitors prediction outcomes and generates security alerts based on severity rules."""

    def __init__(self, confidence_threshold: float = 90.0):
        self.confidence_threshold = confidence_threshold

    def process_prediction(self, db: Session, flow_data: Dict[str, Any]) -> Optional[Alert]:
        """
        Analyzes a single prediction record. If it indicates an attack with a confidence
        exceeding the threshold, a security alert is generated and persisted to the database.
        
        Args:
            db: Active SQLAlchemy database session.
            flow_data: Dictionary containing flow attributes and prediction outputs:
                       - 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'
                       - 'attack_type', 'confidence', and optionally 'timestamp'
                       
        Returns:
            The generated Alert object if triggered, otherwise None.
        """
        attack_type = flow_data.get("attack_type", "Benign")
        confidence = flow_data.get("confidence", 0.0)
        
        # Rule: Trigger alert if not Benign and confidence exceeds the threshold
        if attack_type != "Benign" and confidence > self.confidence_threshold:
            src_ip = flow_data.get("src_ip", "0.0.0.0")
            dst_ip = flow_data.get("dst_ip", "0.0.0.0")
            src_port = int(flow_data.get("src_port", 0))
            dst_port = int(flow_data.get("dst_port", 0))
            protocol = int(flow_data.get("protocol", 0))
            
            # Construct a descriptive alert message
            message = (
                f"CRITICAL: {attack_type} attack detected from {src_ip}:{src_port} "
                f"to {dst_ip}:{dst_port} (Protocol: {protocol}) "
                f"with {confidence:.2f}% confidence."
            )
            
            # Print a high-priority warning to system logs
            logger.warning(f"[SECURITY ALERT] {message}")
            
            # Parse timestamp if available, default to now
            timestamp_val = flow_data.get("timestamp")
            if isinstance(timestamp_val, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp_val)
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
            elif isinstance(timestamp_val, datetime):
                timestamp = timestamp_val
            else:
                timestamp = datetime.now(timezone.utc)
                
            # Create Alert model instance
            alert = Alert(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                attack_type=attack_type,
                confidence=confidence,
                message=message
            )
            
            # Persist to database
            try:
                db.add(alert)
                db.commit()
                db.refresh(alert)
                logger.info(f"Alert ID {alert.id} successfully saved to database.")
                return alert
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to persist alert to database: {e}")
                
        return None


if __name__ == "__main__":
    import os
    # Run a self-test with SQLite database
    os.environ["USE_SQLITE"] = "true"
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    
    logger.info("Initializing self-test for Alert Engine...")
    init_db()
    
    # Instantiate engine
    engine = AlertEngine(confidence_threshold=90.0)
    db = SessionLocal()
    
    try:
        # Case 1: Benign flow (Should NOT alert)
        flow_benign = {
            "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
            "src_port": 12345, "dst_port": 80, "protocol": 6,
            "attack_type": "Benign", "confidence": 99.9
        }
        alert_1 = engine.process_prediction(db, flow_benign)
        logger.info(f"Case 1 (Benign): Alert triggered = {alert_1 is not None}")
        
        # Case 2: Attack flow but low confidence (Should NOT alert)
        flow_low_conf = {
            "src_ip": "192.168.1.11", "dst_ip": "10.0.0.2",
            "src_port": 5555, "dst_port": 80, "protocol": 6,
            "attack_type": "DDoS", "confidence": 85.0
        }
        alert_2 = engine.process_prediction(db, flow_low_conf)
        logger.info(f"Case 2 (DDoS, 85% conf): Alert triggered = {alert_2 is not None}")
        
        # Case 3: Attack flow with high confidence (Should alert and save)
        flow_high_conf = {
            "src_ip": "192.168.1.12", "dst_ip": "10.0.0.3",
            "src_port": 6666, "dst_port": 22, "protocol": 6,
            "attack_type": "PortScan", "confidence": 98.5
        }
        alert_3 = engine.process_prediction(db, flow_high_conf)
        logger.info(f"Case 3 (PortScan, 98.5% conf): Alert triggered = {alert_3 is not None}")
        if alert_3:
            logger.info(f"Retrieved saved alert details: ID={alert_3.id}, Msg='{alert_3.message}'")
            
    finally:
        db.close()
        # Clean up database file after test
        if os.path.exists("netshield.db"):
            os.remove("netshield.db")
            logger.info("Temporary test database 'netshield.db' cleaned up.")
