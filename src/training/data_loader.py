import os
import glob
import logging
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Constants
RAW_DATA_DIR = os.path.join("data", "raw")
PROCESSED_DATA_DIR = os.path.join("data", "processed")

# Target Attack Classes
TARGET_CLASSES = ["Benign", "DDoS", "PortScan", "Bot", "BruteForce", "WebAttack"]

# Mapping from raw CIC-IDS2017 labels to target classes
LABEL_MAPPING = {
    "BENIGN": "Benign",
    "DDOS": "DDoS",
    "DDoS": "DDoS",
    "PORTSCAN": "PortScan",
    "PortScan": "PortScan",
    "BOT": "Bot",
    "Bot": "Bot",
    "FTP-PATATOR": "BruteForce",
    "FTP-Patator": "BruteForce",
    "SSH-PATATOR": "BruteForce",
    "SSH-Patator": "BruteForce",
    "WEB ATTACK - BRUTE FORCE": "WebAttack",
    "Web Attack - Brute Force": "WebAttack",
    "WEB ATTACK - XSS": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "WEB ATTACK - SQL INJECTION": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack"
}

def generate_mock_dataset(output_path: str, num_samples: int = 1000):
    """Generates a mock CIC-IDS2017 CSV file for testing purposes."""
    logger.info(f"Generating mock dataset with {num_samples} samples at {output_path}...")
    np.random.seed(42)
    
    # Create mock columns matching CIC-IDS2017 schema
    data = {
        " Source IP": [f"192.168.1.{np.random.randint(2, 254)}" for _ in range(num_samples)],
        " Source Port": np.random.randint(1024, 65535, size=num_samples),
        " Destination IP": [f"10.0.0.{np.random.randint(2, 254)}" for _ in range(num_samples)],
        " Destination Port": np.random.choice([80, 443, 22, 21, 8080], size=num_samples),
        " Protocol": np.random.choice([6, 17], size=num_samples),  # TCP=6, UDP=17
        " Timestamp": ["2026-06-21 11:00:00" for _ in range(num_samples)],
        " Flow Duration": np.random.randint(100, 1000000, size=num_samples),
        " Total Fwd Packets": np.random.randint(1, 100, size=num_samples),
        " Total Backward Packets": np.random.randint(0, 100, size=num_samples),
        "Total Length of Fwd Packets": np.random.randint(40, 10000, size=num_samples),
        " Total Length of Bwd Packets": np.random.randint(0, 10000, size=num_samples),
        " Average Packet Size": np.random.uniform(40, 1500, size=num_samples),
        " Flow Packets/s": np.random.uniform(0.1, 10000.0, size=num_samples),
        " Flow Bytes/s": np.random.uniform(10.0, 1000000.0, size=num_samples),
        "FIN Flag Count": np.random.choice([0, 1], p=[0.9, 0.1], size=num_samples),
        " SYN Flag Count": np.random.choice([0, 1], p=[0.7, 0.3], size=num_samples),
        " RST Flag Count": np.random.choice([0, 1], p=[0.95, 0.05], size=num_samples),
        " PSH Flag Count": np.random.choice([0, 1], p=[0.5, 0.5], size=num_samples),
        " ACK Flag Count": np.random.choice([0, 1], p=[0.4, 0.6], size=num_samples),
        " URG Flag Count": np.random.choice([0, 1], p=[0.99, 0.01], size=num_samples),
        " ECE Flag Count": np.random.choice([0, 1], p=[0.999, 0.001], size=num_samples),
        " Label": np.random.choice(list(LABEL_MAPPING.keys()), size=num_samples)
    }
    
    df = pd.DataFrame(data)
    
    # Introduce some NaN/inf values to test data cleaning
    df.loc[np.random.choice(num_samples, 5), " Flow Bytes/s"] = np.nan
    df.loc[np.random.choice(num_samples, 5), " Flow Packets/s"] = np.inf
    
    # Create directories if they do not exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info(f"Mock dataset generated successfully.")

def load_dataset(raw_dir: str) -> pd.DataFrame:
    """Loads all CSV files from raw data directory."""
    csv_files = glob.glob(os.path.join(raw_dir, "*.csv"))
    
    if not csv_files:
        logger.warning(f"No CSV files found in {raw_dir}.")
        mock_file = os.path.join(raw_dir, "mock_cic_ids_2017.csv")
        generate_mock_dataset(mock_file)
        csv_files = [mock_file]
        
    dfs = []
    for file in csv_files:
        logger.info(f"Loading {file}...")
        try:
            # Low memory option for parsing large files safely
            df = pd.read_csv(file, low_memory=False)
            dfs.append(df)
        except Exception as e:
            logger.error(f"Error loading {file}: {e}")
            
    if not dfs:
        raise ValueError("No data could be loaded.")
        
    return pd.concat(dfs, ignore_index=True)

def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans column names, handles missing/infinite values, and drops duplicates."""
    logger.info("Cleaning dataset...")
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Remove rows where Label is missing
    if "Label" in df.columns:
        df = df.dropna(subset=["Label"])
    else:
        raise ValueError("Dataset does not contain a 'Label' column.")
    
    # Clean up column values by replacing infinite values with NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Drop duplicates
    initial_shape = df.shape
    df = df.drop_duplicates()
    logger.info(f"Dropped {initial_shape[0] - df.shape[0]} duplicate rows.")
    
    # Handle missing values
    initial_shape = df.shape
    df = df.dropna()
    logger.info(f"Dropped {initial_shape[0] - df.shape[0]} rows containing NaN/infinite values.")
    
    return df

def feature_selection_and_extraction(df: pd.DataFrame) -> pd.DataFrame:
    """Selects and derives the 11 target features required for training."""
    logger.info("Performing feature selection and extraction...")
    
    # 1. Protocol
    protocol = df["Protocol"].astype(int) if "Protocol" in df.columns else pd.Series(6, index=df.index)
    
    # 2. Source Port
    src_port = df["Source Port"].astype(int) if "Source Port" in df.columns else pd.Series(0, index=df.index)
    
    # 3. Destination Port
    dst_port = df["Destination Port"].astype(int) if "Destination Port" in df.columns else pd.Series(0, index=df.index)
    
    # 4. Packet Length
    # Map to Average Packet Size, fallback to Fwd Packet Length Mean/Bwd Packet Length Mean
    if "Average Packet Size" in df.columns:
        pkt_len = df["Average Packet Size"].astype(float)
    elif "Avg Fwd Segment Size" in df.columns:
        pkt_len = df["Avg Fwd Segment Size"].astype(float)
    else:
        pkt_len = pd.Series(64.0, index=df.index)
        
    # 5. TTL (Time To Live)
    # CIC-IDS2017 does not contain TTL in CSV, we synthetically generate it based on Protocol
    # Standard: TCP uses 64 (Linux) or 128 (Windows), UDP uses 64
    ttl = pd.Series(64, index=df.index, dtype=int)
    if "Protocol" in df.columns:
        # Assign some variability: TCP (6) -> 64/128, UDP (17) -> 64
        ttl = np.where(df["Protocol"] == 6, np.random.choice([64, 128], size=len(df)), 64)
        
    # 6. TCP Flags
    # Standard Scapy/network flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40
    tcp_flags = pd.Series(0, index=df.index, dtype=int)
    flag_mapping = {
        "FIN Flag Count": 0x01,
        "SYN Flag Count": 0x02,
        "RST Flag Count": 0x04,
        "PSH Flag Count": 0x08,
        "ACK Flag Count": 0x10,
        "URG Flag Count": 0x20,
        "ECE Flag Count": 0x40
    }
    for col, bitmask in flag_mapping.items():
        if col in df.columns:
            # If flag count is > 0, set the bit
            # Ensure it is converted to float first to handle any mixed types
            tcp_flags |= (pd.to_numeric(df[col], errors="coerce").fillna(0) > 0).astype(int) * bitmask
            
    # 7. Flow Duration
    flow_duration = df["Flow Duration"].astype(float) if "Flow Duration" in df.columns else pd.Series(0.0, index=df.index)
    
    # 8. Packets Per Second
    packets_per_sec = pd.to_numeric(df["Flow Packets/s"], errors="coerce").fillna(0.0).astype(float)
    
    # 9. Bytes Per Second
    bytes_per_sec = pd.to_numeric(df["Flow Bytes/s"], errors="coerce").fillna(0.0).astype(float)
    
    # 10. Forward Packets
    fwd_pkts = df["Total Fwd Packets"].astype(int) if "Total Fwd Packets" in df.columns else pd.Series(0, index=df.index)
    
    # 11. Backward Packets
    bwd_pkts = df["Total Backward Packets"].astype(int) if "Total Backward Packets" in df.columns else pd.Series(0, index=df.index)
    
    # Target Label
    label = df["Label"].str.strip()
    
    # Construct output DataFrame
    features_df = pd.DataFrame({
        "Protocol": protocol,
        "Source Port": src_port,
        "Destination Port": dst_port,
        "Packet Length": pkt_len,
        "TTL": ttl,
        "TCP Flags": tcp_flags,
        "Flow Duration": flow_duration,
        "Packets Per Second": packets_per_sec,
        "Bytes Per Second": bytes_per_sec,
        "Forward Packets": fwd_pkts,
        "Backward Packets": bwd_pkts,
        "Label": label
    })
    
    return features_df

def map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Maps raw labels to the 6 target categories and filters out any undefined classes."""
    logger.info("Mapping and filtering labels...")
    
    # Standardize labels and strip whitespace
    labels = df["Label"].astype(str).str.strip()
    
    # Create mapped series using substring checks to bypass encoding/dash issues
    mapped = pd.Series(index=df.index, dtype=object)
    
    mapped[labels.str.upper().str.contains("BENIGN")] = "Benign"
    mapped[labels.str.upper().str.contains("DDOS")] = "DDoS"
    mapped[labels.str.upper().str.contains("PORTSCAN")] = "PortScan"
    mapped[labels.str.upper().str.contains("BOT")] = "Bot"
    mapped[labels.str.upper().str.contains("PATATOR") | labels.str.upper().str.contains("BRUTE")] = "BruteForce"
    mapped[labels.str.upper().str.contains("WEB")] = "WebAttack"
    
    df["Label_Mapped"] = mapped
    
    # Log unmatched labels
    unmatched = df[df["Label_Mapped"].isna()]["Label"].unique()
    if len(unmatched) > 0:
        logger.warning(f"Unmatched labels filtered out: {unmatched}")
        
    # Drop rows with unmatched labels
    df = df.dropna(subset=["Label_Mapped"])
    
    # Replace old Label column
    df = df.drop(columns=["Label"]).rename(columns={"Label_Mapped": "Label"})
    
    logger.info(f"Label distribution:\n{df['Label'].value_counts()}")
    return df

def run_pipeline(raw_dir: str = RAW_DATA_DIR, processed_dir: str = PROCESSED_DATA_DIR, test_size: float = 0.2):
    """Executes the entire ingestion pipeline: Load -> Clean -> Deduplicate -> Handle NaNs -> Feature Extract -> Label Map -> Split -> Save."""
    logger.info("Starting Dataset Ingestion Pipeline...")
    
    # 1. Load Dataset
    df = load_dataset(raw_dir)
    
    # 2. Clean Dataset, 3. Remove Duplicates, 4. Handle Missing Values
    df = clean_dataset(df)
    
    # 5. Feature Selection / Extraction (to match the 11 Scapy features)
    df = feature_selection_and_extraction(df)
    
    # 6. Map labels to target classes
    df = map_labels(df)
    
    # 7. Train/Test Split
    logger.info(f"Splitting dataset (test_size={test_size})...")
    train_df, test_df = train_test_split(df, test_size=test_size, random_state=42, stratify=df["Label"])
    
    # Ensure processed directory exists
    os.makedirs(processed_dir, exist_ok=True)
    
    # Save train and test partitions
    train_path = os.path.join(processed_dir, "train.csv")
    test_path = os.path.join(processed_dir, "test.csv")
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    logger.info(f"Pipeline complete! Saved train data to {train_path} ({len(train_df)} rows) and test data to {test_path} ({len(test_df)} rows).")

if __name__ == "__main__":
    run_pipeline()
