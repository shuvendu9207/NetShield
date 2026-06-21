import logging
from typing import List, Dict, Any
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

logger = logging.getLogger(__name__)

def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray, classes: List[str]) -> Dict[str, Any]:
    """
    Computes performance metrics: Accuracy, Precision, Recall, F1 Score, and Confusion Matrix.
    
    Args:
        y_true: True labels (encoded or original string)
        y_pred: Predicted labels (encoded or original string)
        classes: List of class names corresponding to the encoding order
        
    Returns:
        Dict containing accuracy, precision, recall, f1, and confusion matrix.
    """
    # Calculate global metrics
    accuracy = accuracy_score(y_true, y_pred)
    
    # Calculate precision, recall, f1-score (macro and weighted average)
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )
    
    # Generate confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    
    # Generate detailed classification report
    report = classification_report(y_true, y_pred, target_names=classes, zero_division=0)
    
    # Format results
    metrics = {
        "accuracy": accuracy,
        "precision_macro": precision_macro,
        "recall_macro": recall_macro,
        "f1_macro": f1_macro,
        "precision_weighted": precision_weighted,
        "recall_weighted": recall_weighted,
        "f1_weighted": f1_weighted,
        "confusion_matrix": cm.tolist(),
        "classification_report": report
    }
    
    # Log the metrics clearly
    logger.info("=== Model Evaluation Metrics ===")
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Precision (Weighted): {precision_weighted:.4f}")
    logger.info(f"Recall (Weighted): {recall_weighted:.4f}")
    logger.info(f"F1 Score (Weighted): {f1_weighted:.4f}")
    logger.info(f"Precision (Macro): {precision_macro:.4f}")
    logger.info(f"Recall (Macro): {recall_macro:.4f}")
    logger.info(f"F1 Score (Macro): {f1_macro:.4f}")
    logger.info("\nDetailed Classification Report:\n" + report)
    logger.info("\nConfusion Matrix:\n" + str(cm))
    
    return metrics
