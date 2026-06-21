import os
import pytest
from src.inference.predictor import Predictor

def test_predictor_artifact_loading():
    """Verifies that the Predictor successfully loads artifacts from models/ folder."""
    if not os.path.exists("models/model.pkl"):
        pytest.skip("Model files not found. Skipping prediction tests.")
        
    try:
        predictor = Predictor(models_dir="models")
        assert predictor.model is not None
        assert predictor.scaler is not None
        assert predictor.label_encoder is not None
    except Exception as e:
        pytest.fail(f"Predictor raised an exception during artifact load: {e}")

def test_predictor_missing_directory_raises_error():
    """Verifies that Predictor raises FileNotFoundError when target models folder doesn't exist."""
    with pytest.raises(FileNotFoundError):
        # Point to a non-existent models directory
        Predictor(models_dir="non_existent_folder_abc_123")

def test_predictor_predictions():
    """Verifies that Predictor performs inference and returns valid class names and confidence levels."""
    if not os.path.exists("models/model.pkl"):
        pytest.skip("Model files not found. Skipping prediction tests.")
        
    predictor = Predictor(models_dir="models")
    
    # Mock flow features matching the 11 schema features
    mock_flow = {
        "Protocol": 6,
        "Source Port": 54321,
        "Destination Port": 80,
        "Packet Length": 62.67,
        "TTL": 85,
        "TCP Flags": 19,
        "Flow Duration": 100000.0,
        "Packets Per Second": 30.0,
        "Bytes Per Second": 1880.0,
        "Forward Packets": 2,
        "Backward Packets": 1
    }
    
    # Test predict_flow (single)
    attack_class, confidence = predictor.predict_flow(mock_flow)
    assert isinstance(attack_class, str)
    assert 0.0 <= confidence <= 100.0
    
    # Test predict_flows (batch)
    batch_results = predictor.predict_flows([mock_flow, mock_flow])
    assert len(batch_results) == 2
    assert "attack_type" in batch_results[0]
    assert "confidence" in batch_results[0]
    assert isinstance(batch_results[0]["attack_type"], str)
    assert isinstance(batch_results[0]["confidence"], float)
