<div align="center">

<img src="https://img.shields.io/badge/API_Sentinel-SAM--ADS-0d1117?style=for-the-badge&logo=shield&logoColor=00ff88" alt="API Sentinel"/>

# 🛡️ API Sentinel
### Secure API Monitoring and Attack Detection System (SAM-ADS)

*A real-time API security framework that detects malicious requests using a hybrid approach combining machine learning, anomaly detection, rule-based analysis, and behavioral tracking.*

<br/>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Proxy-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-Deep%20Learning-FF6F00?style=flat-square&logo=tensorflow&logoColor=white)](https://tensorflow.org)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-ML-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)](https://sqlite.org)


<br/>

[Overview](#-overview) · [Features](#-key-features) · [Architecture](#-system-architecture) · [Detection Pipeline](#-detection-pipeline) · [Tech Stack](#-tech-stack) · [Getting Started](#-getting-started) · [Endpoints](#-example-endpoints) · [Roadmap](#-roadmap)

</div>

---

## 🔍 Overview

Modern APIs are prime targets for a growing range of cyber threats. API Sentinel acts as an intelligent **proxy layer** that intercepts, analyzes, and scores every API request before it reaches your backend — providing a battle-hardened security perimeter powered by multiple detection strategies.

### Threats Addressed

| Threat | Detection Method |
|--------|-----------------|
| 🗄️ SQL Injection | Rule-based + ML pattern analysis |
| 🌐 Cross-Site Scripting (XSS) | Signature matching + behavioral scoring |
| 🕵️ Man-in-the-Middle (MITM) | Session/behavioral tracking |


---

## ✨ Key Features

- **🔐 Real-Time API Protection** — Zero-latency proxy intercepts requests before they touch your backend
- **🤖 Hybrid ML Detection** — Three complementary models working in concert:
  - **Random Forest** (Supervised) — Learns from labeled attack patterns
  - **Isolation Forest** (Unsupervised) — Spots anomalies without labeled data
  - **Autoencoder** (Deep Learning) — Detects subtle deviations from normal behavior
- **📊 Risk Scoring & Decision Fusion** — Combines all signals into a single normalized risk score
- **📡 Behavioral & Session Tracking** — Tracks request patterns over time per client/session
- **🧠 Continuous Learning Support** — Architecture designed for retraining as new threats emerge
- **📁 Full Request Logging** — Every request stored in SQLite with metadata and risk scores
- **🚨 Email Alert System** — SMTP-based notifications on suspicious or blocked traffic
- **📈 Interactive Dashboard** — Real-time Flask dashboard for monitoring, search, and alerting

---


## 🔄 Detection Pipeline

Every incoming request passes through a sequential, multi-layered analysis:

```
Request
  │
  ├─ 1. Request Interception          FastAPI proxy captures headers, body, params, IP
  │
  ├─ 2. Feature Extraction            Builds structured feature vector from raw request
  │
  ├─ 3. Rule-Based Detection          Pattern matching for known attack signatures
  │                                   (SQL keywords, XSS payloads, path traversal, etc.)
  │
  ├─ 4. Machine Learning Models
  │      ├─ Random Forest             Predicts attack class from supervised training
  │      ├─ Isolation Forest          Flags statistical outliers (unsupervised)
  │      └─ Autoencoder               Measures reconstruction error vs. normal baseline
  │
  ├─ 5. Behavioral Analysis           Tracks per-IP/session request patterns over time
  │
  ├─ 6. Decision Fusion               Weighted aggregation → normalized Risk Score [0–1]
  │                                   ┌──────────┬────────────┬──────────┐
  │                                   │  < 0.35  │ 0.35–0.70  │  > 0.70  │
  │                                   │  ALLOW   │ SUSPICIOUS │  BLOCK   │
  │                                   └──────────┴────────────┴──────────┘
  │
  └─ 7. Logging + Dashboard + Alerts  Full record stored; dashboard updated; alerts sent
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Proxy** | FastAPI | High-performance async request interception |
| **Dashboard** | Flask | Real-time monitoring UI |
| **Supervised ML** | Scikit-learn (Random Forest) | Attack classification |
| **Unsupervised ML** | Scikit-learn (Isolation Forest) | Anomaly detection |
| **Deep Learning** | TensorFlow / Keras (Autoencoder) | Behavioral deviation detection |
| **Database** | SQLite | Request logging and audit trail |
| **Frontend** | HTML / CSS / JavaScript | Dashboard interface |
| **Alerts** | SMTP | Email notifications |

---

## 📂 Project Structure

```
API_Sentinel/
│
├── backend/
│   ├── api.py                  # FastAPI proxy — request interception & forwarding
│   ├── pipeline.py             # Detection pipeline — model orchestration & decision fusion
│   └── feature_extraction.py  # Shared feature builder (training & runtime)
│
├── models/
│   ├── random_forest.pkl       # Trained Random Forest model
│   ├── isolation_forest.pkl    # Trained Isolation Forest model
│   └── autoencoder.h5          # Trained Autoencoder (Keras)
│
├── dashboard/
│   └── app.py                  # Flask dashboard application
│
├── database/
│   └── sam_ads.db              # Shared SQLite database (proxy + dashboard)
│
├── training/
│   └── API_Sentinel_Training_Only.ipynb  # Model training notebook
│
├── utils/                      # Helper functions (logging, alerts, config)
│
├── pipeline/                   # Detection pipeline modules
│
├── scripts/
│   ├── one_test.py             # Single request test
│   ├── tests_benign.py         # Batch benign traffic simulation
│   └── tests_attacks.py        # Batch attack traffic simulation
│
├── run_system.py               # 🚀 Main entry point — starts all services
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- pip

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/api-sentinel.git
cd api-sentinel
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the System

```bash
python run_system.py
```

This launches all three components simultaneously:

| Service | URL | Description |
|---------|-----|-------------|
| 📊 Dashboard | http://127.0.0.1:5000 | Real-time monitoring UI |
| 🔐 Proxy / Security Layer | http://127.0.0.1:8000 | FastAPI request interceptor |
| 🖥️ Dummy Backend | http://127.0.0.1:8001 | Simulated upstream API |

### 4. Run Tests

Simulate real-world traffic to see the system in action:

```bash
# Single request test
python scripts/one_test.py

# Batch benign traffic
python scripts/tests_benign.py

# Batch attack simulation
python scripts/tests_attacks.py
```
---

## 🚨 Alerts

When a request is flagged as **suspicious** or **blocked**, the system triggers:

- **Dashboard notification** — Highlighted in the live feed with risk score and classification
- **Email alert** — SMTP notification sent to configured recipients with request details

---

## 📊 Dashboard

The Flask dashboard provides:

- **Live request feed** with color-coded risk levels (green / amber / red)
- **Aggregate statistics** — total requests, attack rate, top threat categories
- **Request detail view** — full headers, body, extracted features, and model scores
- **Search & filter** — by IP, endpoint, time range, or risk level
- **Alert history** — log of all triggered notifications

---
