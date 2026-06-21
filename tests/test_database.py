import pytest
from datetime import datetime, timezone
from src.database.models import DetectionHistory, Alert
from src.database.connection import init_db

def test_database_table_initialization(db_session):
    """Verifies that database connection and initialization creates tables correctly."""
    # init_db is tested implicitly via fixture setting up Base metadata, but let's test model properties
    detection = DetectionHistory(
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=80,
        dst_port=4433,
        protocol=17,
        attack_type="Benign",
        confidence=95.0
    )
    db_session.add(detection)
    db_session.commit()
    
    retrieved = db_session.query(DetectionHistory).filter_by(src_ip="10.0.0.1").first()
    assert retrieved is not None
    assert retrieved.dst_port == 4433
    assert retrieved.protocol == 17
    assert retrieved.attack_type == "Benign"
    assert retrieved.confidence == 95.0
    assert isinstance(retrieved.timestamp, datetime)

def test_alert_model_properties(db_session):
    """Verifies fields on the Alert model and formatting."""
    alert = Alert(
        src_ip="192.168.1.15",
        dst_ip="10.0.0.5",
        src_port=22,
        dst_port=54321,
        protocol=6,
        attack_type="BruteForce",
        confidence=98.1,
        message="CRITICAL: BruteForce attack detected."
    )
    db_session.add(alert)
    db_session.commit()
    
    retrieved = db_session.query(Alert).filter_by(attack_type="BruteForce").first()
    assert retrieved is not None
    assert retrieved.src_ip == "192.168.1.15"
    assert retrieved.dst_ip == "10.0.0.5"
    assert retrieved.message == "CRITICAL: BruteForce attack detected."
    assert "BruteForce" in str(retrieved)
