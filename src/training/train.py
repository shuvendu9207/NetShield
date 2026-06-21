import os
import joblib
import logging
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from src.training.evaluate import evaluate_predictions

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
PROCESSED_DATA_DIR = os.path.join("data", "processed")
MODELS_DIR = "models"

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

def load_data(processed_dir: str):
    """Loads the pre-processed training and testing data."""
    train_path = os.path.join(processed_dir, "train.csv")
    test_path = os.path.join(processed_dir, "test.csv")
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError(
            f"Processed data files not found in {processed_dir}. "
            "Please run the dataset pipeline first: python -m src.training.data_loader"
        )
        
    logger.info(f"Loading training data from {train_path}...")
    train_df = pd.read_csv(train_path)
    
    logger.info(f"Loading testing data from {test_path}...")
    test_df = pd.read_csv(test_path)
    
    return train_df, test_df

def train_random_forest(X_train, y_train):
    """Trains a Random Forest classifier."""
    logger.info("Training Random Forest Classifier...")
    # Initialize Random Forest with reasonable defaults for multiclass and speed
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        verbose=1
    )
    rf_model.fit(X_train, y_train)
    logger.info("Random Forest training complete.")
    return rf_model

def train_xgboost(X_train, y_train, num_classes: int):
    """Trains an XGBoost classifier."""
    logger.info("Training XGBoost Classifier...")
    # Initialize XGBoost with reasonable defaults for multiclass classification
    xgb_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=num_classes,
        random_state=42,
        n_jobs=-1,
        eval_metric="mlogloss"
    )
    xgb_model.fit(X_train, y_train)
    logger.info("XGBoost training complete.")
    return xgb_model

def run_training_pipeline(processed_dir: str = PROCESSED_DATA_DIR):
    """Runs the training pipeline for both Random Forest and XGBoost models."""
    # 1. Load Dataset
    train_df, test_df = load_data(processed_dir)
    
    # Extract features and targets
    X_train_raw = train_df[FEATURES]
    y_train_raw = train_df["Label"]
    
    X_test_raw = test_df[FEATURES]
    y_test_raw = test_df["Label"]
    
    # 6. Label Encoding
    logger.info("Performing label encoding...")
    le = LabelEncoder()
    # Fit encoder on training set and transform both
    y_train = le.fit_transform(y_train_raw)
    y_test = le.transform(y_test_raw)
    classes = list(le.classes_)
    logger.info(f"Classes encoded: {classes}")
    
    # 8. Feature Scaling
    logger.info("Performing feature scaling...")
    scaler = StandardScaler()
    # Fit scaler on training set and transform both
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)
    
    # 9. Train Random Forest & 10. Evaluate
    rf_model = train_random_forest(X_train, y_train)
    logger.info("Evaluating Random Forest on test set...")
    y_pred_rf = rf_model.predict(X_test)
    evaluate_predictions(y_test, y_pred_rf, classes)
    
    # 11. Train XGBoost & 12. Evaluate
    xgb_model = train_xgboost(X_train, y_train, len(classes))
    logger.info("Evaluating XGBoost on test set...")
    y_pred_xgb = xgb_model.predict(X_test)
    evaluate_predictions(y_test, y_pred_xgb, classes)
    
    # Note: Model persistence (saving models, scaler, encoder) will be fully implemented in Module 6.
    # We will save intermediate assets for testing purposes.
    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(rf_model, os.path.join(MODELS_DIR, "rf_model.pkl"))
    joblib.dump(xgb_model, os.path.join(MODELS_DIR, "xgb_model.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.pkl"))
    logger.info("Saved temporary training artifacts to models/ directory.")

if __name__ == "__main__":
    run_training_pipeline()
