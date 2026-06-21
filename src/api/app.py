import os
import shutil
import tempfile
import logging
from typing import Dict, List, Any
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from src.database.connection import get_db, init_db
from src.database.models import DetectionHistory, Alert
from src.inference.predictor import Predictor
from src.packet_capture.pcap_reader import read_pcap_flows
from src.alerts.engine import AlertEngine

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize Alert Engine
alert_engine = AlertEngine(confidence_threshold=90.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles startup and shutdown lifecycle events."""
    # 1. Initialize database tables
    init_db()
    
    # 2. Pre-load Predictor so we don't reload model files on every API call
    try:
        app.state.predictor = Predictor()
        logger.info("ML Prediction Engine loaded and ready.")
    except Exception as e:
        logger.warning(
            f"Prediction Engine could not be loaded at startup: {e}. "
            "Note: You must run the training pipeline to generate models."
        )
        app.state.predictor = None
        
    yield
    # Cleanup on shutdown (if any)
    logger.info("Shutting down API server...")

# Initialize FastAPI application
app = FastAPI(
    title="NetShield NIDS API",
    description="Real-time AI-powered Network Intrusion Detection System",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for cross-origin frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    """Service health check endpoint."""
    return {
        "status": "healthy",
        "service": "NetShield NIDS API",
        "model_loaded": app.state.predictor is not None
    }

@app.post("/predict")
async def predict_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Accepts an uploaded PCAP file, parses its network flows, runs ML inference, 
    persists flow details in Detection History, evaluates security alerts, and returns results.
    """
    # 1. Verify file extension
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Unsupported file format. Please upload a .pcap or .pcapng file.")
        
    predictor = app.state.predictor
    if not predictor:
        # Attempt a lazy reload in case model was trained since last startup
        try:
            app.state.predictor = Predictor()
            predictor = app.state.predictor
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail=f"Prediction Engine not available. Model artifacts missing or failed to load. Error: {e}"
            )
            
    # 2. Save uploaded file content to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name
        
    try:
        # 3. Read and parse flows from the temporary PCAP file
        logger.info(f"Received PCAP upload: {file.filename}. Processing...")
        flows = read_pcap_flows(tmp_path)
        
        if not flows:
            return {
                "message": "No valid IP flows extracted from PCAP.",
                "total_flows": 0,
                "predictions": []
            }
            
        # 4. Predict attacks on the batch of flows
        predicted_flows = predictor.predict_flows(flows)
        
        # 5. Save results to database and trigger alert engine
        results = []
        for flow in predicted_flows:
            # Instantiate database record for history
            detection = DetectionHistory(
                src_ip=flow.get("src_ip"),
                dst_ip=flow.get("dst_ip"),
                src_port=int(flow.get("src_port", 0)),
                dst_port=int(flow.get("dst_port", 0)),
                protocol=int(flow.get("protocol", 0)),
                attack_type=flow.get("attack_type", "Benign"),
                confidence=flow.get("confidence", 0.0)
            )
            db.add(detection)
            
            # Process through the Alert Engine (automatically commits to DB if triggered)
            alert_engine.process_prediction(db, flow)
            
            results.append({
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "src_port": flow.get("src_port"),
                "dst_port": flow.get("dst_port"),
                "protocol": flow.get("protocol"),
                "attack_type": flow.get("attack_type"),
                "confidence": flow.get("confidence")
            })
            
        # Commit detection histories
        db.commit()
        logger.info(f"Processed and classified {len(results)} flows from {file.filename}.")
        
        return {
            "message": "PCAP processed successfully.",
            "total_flows": len(results),
            "predictions": results
        }
        
    except Exception as e:
        logger.error(f"Error classifying PCAP: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to process and classify PCAP file: {e}")
        
    finally:
        # Clean up temporary PCAP file
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception as cleanup_err:
                logger.error(f"Failed to delete temp file {tmp_path}: {cleanup_err}")

@app.get("/alerts")
def get_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieves security alerts, sorted by latest timestamp first."""
    alerts = db.query(Alert).order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()
    return alerts

@app.get("/detections")
def get_detections(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db)
):
    """Retrieves flow classification history, sorted by latest timestamp first."""
    detections = db.query(DetectionHistory).order_by(DetectionHistory.timestamp.desc()).offset(offset).limit(limit).all()
    return detections
