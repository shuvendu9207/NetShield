# NetShield: AI-Powered Network Intrusion Detection System (NIDS)

NetShield is a production-quality, AI-powered Network Intrusion Detection System (NIDS) designed to analyze network traffic and detect cyber attacks using Machine Learning. It provides endpoints to parse PCAP files, run predictions on live network traffic, store detection history, and trigger alerts for suspicious traffic.

## Project Structure

```text
NetShield/
├── data/
│   ├── raw/
│   └── processed/
├── models/
├── notebooks/
├── src/
│   ├── api/
│   │   ├── routes/
│   │   └── app.py
│   ├── packet_capture/
│   │   ├── pcap_reader.py
│   │   └── live_capture.py
│   ├── feature_extraction/
│   │   └── extractor.py
│   ├── training/
│   │   ├── train.py
│   │   └── evaluate.py
│   ├── inference/
│   │   └── predictor.py
│   ├── database/
│   │   ├── connection.py
│   │   ├── models.py
│   │   └── crud.py
│   ├── alerts/
│   │   └── engine.py
│   └── config/
├── tests/
├── docker/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## Features

- **PCAP File Parsing:** Upload and extract packet features from PCAP files.
- **Machine Learning Detection:** Predict attack categories such as Benign, DDoS, PortScan, Bot, BruteForce, and WebAttack using trained Random Forest and XGBoost classifiers.
- **Live Traffic Monitoring:** Sniff live network traffic on specified interfaces, extract flow features in real time, and run inference.
- **Database Integration:** Log all detections and alerts to PostgreSQL using SQLAlchemy.
- **Alert Engine:** Generate severity-based alerts when attack confidence exceeds 90%.
- **REST API:** Fully interactive FastAPI Swagger documentation.

## Installation

### Prerequisites
- Python 3.10+
- WinPcap / Npcap (on Windows) or libpcap (on Linux) for Scapy packet capturing.
- PostgreSQL (if running locally without Docker)
- Docker & Docker Compose (optional for containerized deployment)

### Local Setup
1. Clone the repository and navigate to the root directory.
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/macOS:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env` and fill in local database settings.
