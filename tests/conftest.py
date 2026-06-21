import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add src to python path to ensure imports work correctly when running pytest from the root folder
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.connection import Base, get_db
from src.api.app import app
from src.inference.predictor import Predictor

# Use SQLite in-memory database for testing
TEST_DATABASE_URL = "sqlite:///:memory:"

@pytest.fixture(scope="function")
def db_session():
    """Provides a clean in-memory database session for a test function."""
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    """Provides a FastAPI TestClient configured to use the in-memory test database."""
    def _get_db_override():
        try:
            yield db_session
        finally:
            pass

    # Override get_db dependency
    app.dependency_overrides[get_db] = _get_db_override
    
    with TestClient(app) as test_client:
        yield test_client
        
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def mock_predictor():
    """Provides a mock predictor that returns deterministic outputs without loading real models."""
    class MockPredictor:
        def __init__(self, *args, **kwargs):
            pass
            
        def predict_flow(self, flow):
            # Deterministic output for testing
            if flow.get("src_port") == 9999 or flow.get("Source Port") == 9999:
                return "PortScan", 95.0
            return "Benign", 98.0
            
        def predict_flows(self, flows):
            results = []
            for flow in flows:
                f = flow.copy()
                if flow.get("src_port") == 9999 or flow.get("Source Port") == 9999:
                    f["attack_type"] = "PortScan"
                    f["confidence"] = 95.0
                else:
                    f["attack_type"] = "Benign"
                    f["confidence"] = 98.0
                results.append(f)
            return results

    # Override app.state.predictor with the MockPredictor instance
    app.state.predictor = MockPredictor()
    return app.state.predictor
