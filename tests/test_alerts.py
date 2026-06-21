import pytest
from src.alerts.engine import AlertEngine
from src.database.models import Alert

def test_alert_engine_benign_no_alert(db_session):
    """Verifies that benign traffic does not trigger security alerts, even with 100% confidence."""
    engine = AlertEngine(confidence_threshold=90.0)
    
    flow_data = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": 6,
        "attack_type": "Benign",
        "confidence": 99.9
    }
    
    alert = engine.process_prediction(db_session, flow_data)
    assert alert is None
    
    # Verify nothing was added to database
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 0

def test_alert_engine_low_confidence_no_alert(db_session):
    """Verifies that attack traffic with confidence below threshold does not trigger alerts."""
    engine = AlertEngine(confidence_threshold=90.0)
    
    flow_data = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": 6,
        "attack_type": "DDoS",
        "confidence": 85.0
    }
    
    alert = engine.process_prediction(db_session, flow_data)
    assert alert is None
    
    # Verify nothing was added to database
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 0

def test_alert_engine_high_confidence_alert_triggered(db_session):
    """Verifies that high confidence attack traffic triggers alerts and persists them correctly."""
    engine = AlertEngine(confidence_threshold=90.0)
    
    flow_data = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": 6,
        "attack_type": "PortScan",
        "confidence": 95.5
    }
    
    alert = engine.process_prediction(db_session, flow_data)
    assert alert is not None
    assert alert.attack_type == "PortScan"
    assert alert.confidence == 95.5
    assert "CRITICAL" in alert.message
    
    # Verify database persistence
    db_alerts = db_session.query(Alert).all()
    assert len(db_alerts) == 1
    assert db_alerts[0].id == alert.id
    assert db_alerts[0].src_ip == "192.168.1.100"
    assert db_alerts[0].dst_ip == "10.0.0.1"
