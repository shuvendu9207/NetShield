import os
import tempfile
import pytest
from scapy.all import IP, TCP, wrpcap
from fastapi.testclient import TestClient
from src.database.models import DetectionHistory, Alert

def test_read_root(client):
    """Tests health check root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "healthy"
    assert "service" in json_data

def test_predict_pcap_invalid_extension(client):
    """Tests endpoint validation error when uploading a non-PCAP file format."""
    files = {"file": ("test.txt", b"random text file content", "text/plain")}
    response = client.post("/predict", files=files)
    assert response.status_code == 400
    assert "Unsupported file format" in response.json()["detail"]

def test_predict_pcap_valid(client, mock_predictor, db_session):
    """Tests processing a valid PCAP file and getting classification results."""
    # 1. Create a tiny test PCAP file using Scapy
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        pcap_path = tmp.name
        
    try:
        packets = [
            IP(src="192.168.1.50", dst="10.0.0.99", ttl=64)/TCP(sport=9999, dport=80, flags="S"),
            IP(src="10.0.0.99", dst="192.168.1.50", ttl=128)/TCP(sport=80, dport=9999, flags="SA")
        ]
        packets[0].time = 1718973600.00
        packets[1].time = 1718973600.05
        wrpcap(pcap_path, packets)
        
        # 2. Upload the PCAP file to the API
        with open(pcap_path, "rb") as f:
            files = {"file": ("test.pcap", f, "application/octet-stream")}
            response = client.post("/predict", files=files)
            
        assert response.status_code == 200
        data = response.json()
        assert data["total_flows"] == 1
        assert len(data["predictions"]) == 1
        
        pred = data["predictions"][0]
        # In mock_predictor, port 9999 triggers PortScan prediction
        assert pred["attack_type"] == "PortScan"
        assert pred["confidence"] == 95.0
        
        # 3. Verify that the prediction was saved in the test database
        detections = db_session.query(DetectionHistory).all()
        assert len(detections) == 1
        assert detections[0].src_ip == "192.168.1.50"
        assert detections[0].attack_type == "PortScan"
        
        # 4. Verify that the alert engine was triggered (confidence 95.0 > 90.0, not Benign)
        alerts = db_session.query(Alert).all()
        assert len(alerts) == 1
        assert alerts[0].attack_type == "PortScan"
        assert alerts[0].confidence == 95.0
        
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

def test_get_detections_history(client, db_session):
    """Tests retrieving stored detection history from the database."""
    # Seed db session with mock detection history record
    det = DetectionHistory(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.99",
        src_port=1234,
        dst_port=80,
        protocol=6,
        attack_type="Benign",
        confidence=98.5
    )
    db_session.add(det)
    db_session.commit()
    
    response = client.get("/detections")
    assert response.status_code == 200
    detections_list = response.json()
    assert len(detections_list) == 1
    assert detections_list[0]["src_ip"] == "192.168.1.50"
    assert detections_list[0]["attack_type"] == "Benign"

def test_get_alerts_history(client, db_session):
    """Tests retrieving stored alerts from the database."""
    # Seed db session with alert record
    alt = Alert(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.99",
        src_port=1234,
        dst_port=80,
        protocol=6,
        attack_type="DDoS",
        confidence=95.5,
        message="CRITICAL Alert"
    )
    db_session.add(alt)
    db_session.commit()
    
    response = client.get("/alerts")
    assert response.status_code == 200
    alerts_list = response.json()
    assert len(alerts_list) == 1
    assert alerts_list[0]["attack_type"] == "DDoS"
    assert alerts_list[0]["message"] == "CRITICAL Alert"

def test_get_monitor_interfaces(client):
    """Tests endpoint listing system/container interfaces."""
    response = client.get("/monitor/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)

def test_monitor_start_and_stop(client, mock_predictor):
    """Tests starting and stopping live monitoring on an interface."""
    # First, list interfaces to find a valid one for the test
    iface_res = client.get("/monitor/interfaces")
    interfaces = iface_res.json()["interfaces"]
    if not interfaces:
        pytest.skip("No network interfaces found to test live monitoring.")
        
    test_iface = interfaces[0]
    
    # Test starting monitor on the interface
    start_res = client.post(f"/monitor/start?interface={test_iface}")
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "success"
    
    # Test stopping monitor on the interface
    stop_res = client.post(f"/monitor/stop?interface={test_iface}")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "success"
