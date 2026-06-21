import os
import joblib
import logging
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
FEATURES = [
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Length",
    "TTL",
    "TCP Flags",
    "Flow Duration",
    "Packets Per Second",
    "Bytes Per Second",
    "Forward Packets",
    "Backward Packets"
]

class Predictor:
    """Loads trained artifacts and performs attack classification on network flows."""

    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.model_path = os.path.join(models_dir, "model.pkl")
        self.scaler_path = os.path.join(models_dir, "scaler.pkl")
        self.encoder_path = os.path.join(models_dir, "label_encoder.pkl")
        
        self.model = None
        self.scaler = None
        self.label_encoder = None
        
        self.load_artifacts()

    def load_artifacts(self):
        """Loads serialized model, scaler, and encoder files from models directory."""
        logger.info(f"Loading ML artifacts from '{self.models_dir}'...")
        
        if not (os.path.exists(self.model_path) and 
                os.path.exists(self.scaler_path) and 
                os.path.exists(self.encoder_path)):
            raise FileNotFoundError(
                f"Model artifacts not found in '{self.models_dir}'. "
                "Please run the training pipeline first: python -m src.training.train"
            )
            
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            self.label_encoder = joblib.load(self.encoder_path)
            logger.info("ML artifacts loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ML artifacts: {e}")
            raise e

    def predict_flow(self, flow_features: Dict[str, Any]) -> Tuple[str, float]:
        """
        Predicts whether a single network flow is benign or an attack.
        
        Args:
            flow_features: Dictionary containing flow features matching the schema.
            
        Returns:
            Tuple of (predicted_class_name, confidence_percentage).
        """
        # 1. Convert dict to DataFrame with correct column ordering
        df = pd.DataFrame([flow_features])[FEATURES]
        
        # 2. Scale features
        scaled_features = self.scaler.transform(df)
        
        # 3. Predict class probability
        probabilities = self.model.predict_proba(scaled_features)[0]
        
        # 4. Get class index with highest probability
        predicted_idx = np.argmax(probabilities)
        confidence = float(probabilities[predicted_idx]) * 100.0
        
        # 5. Decode label
        predicted_class = str(self.label_encoder.inverse_transform([predicted_idx])[0])
        
        return predicted_class, confidence

    def predict_flows(self, flows_features: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Classifies a list/batch of network flows.
        
        Args:
            flows_features: List of dictionaries containing flow features.
            
        Returns:
            List of flow feature dictionaries updated with prediction results:
            - 'attack_type': predicted label
            - 'confidence': prediction confidence percentage
        """
        if not flows_features:
            return []
            
        # 1. Convert batch to DataFrame
        df = pd.DataFrame(flows_features)[FEATURES]
        
        # 2. Scale features
        scaled_features = self.scaler.transform(df)
        
        # 3. Predict probabilities
        probabilities_batch = self.model.predict_proba(scaled_features)
        
        # 4. Process predictions for each row
        results = []
        for i, probabilities in enumerate(probabilities_batch):
            predicted_idx = np.argmax(probabilities)
            confidence = float(probabilities[predicted_idx]) * 100.0
            predicted_class = str(self.label_encoder.inverse_transform([predicted_idx])[0])
            
            # Copy original flow data and append prediction
            flow_result = flows_features[i].copy()
            flow_result["attack_type"] = predicted_class
            flow_result["confidence"] = confidence
            results.append(flow_result)
            
        return results


if __name__ == "__main__":
    logger.info("Initializing self-test for Prediction Engine...")
    
    # Create mock flow features
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
    
    try:
        predictor = Predictor()
        
        # Test single prediction
        attack_type, confidence = predictor.predict_flow(mock_flow)
        logger.info(f"Single Prediction Result: Attack Class = '{attack_type}', Confidence = {confidence:.2f}%")
        
        # Test batch prediction
        batch_flows = [mock_flow, mock_flow]
        batch_results = predictor.predict_flows(batch_flows)
        logger.info(f"Batch Prediction Result (first flow): {batch_results[0]}")
        logger.info("Prediction Engine self-test completed successfully.")
        
    except FileNotFoundError as e:
        logger.error(f"Test skipped: {e}")
    except Exception as e:
        logger.error(f"Test failed with error: {e}")
