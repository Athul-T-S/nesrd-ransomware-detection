# NESRD — Network Early-Stage Ransomware Detector

A production-grade, real-time ransomware detection and response system built as a capstone project at Lovely Professional University.

NESRD detects ransomware at the **early stage** — before significant file damage occurs — using kernel-level ETW event collection, machine learning, and deterministic tripwires. When ransomware is detected, the system automatically kills the malicious process and isolates the endpoint from the network.

---

## Architecture
Windows VM (Agent)                    Host Machine (Manager)
─────────────────                     ──────────────────────
ETW Collector (logman)                gRPC Server
↓                                     ↓
Sliding Window (256 events)  ←→  FusionEngine (ONNX ML)
↓                                     ↓
gRPC Client ──────────────────→  TripwireEngine
↓                                     ↓
Decision Handler                    AlertService
├── Kill Process                         ↓
└── Network Isolation            Wazuh SIEM Dashboard

---

## Detection Methods

### 1 — Machine Learning (Conv1D)
- Trained on RanSAP 2022 dataset (Ryuk, WannaCry, Sodinokibi, GandCrab4)
- FastText embeddings convert file I/O tokens to dense vectors
- Conv1D model classifies behavioral sequences
- ONNX runtime inference — 1ms per window (88x faster than Keras)
- **Accuracy: 85.12% | Precision: 91.84% | F1: 83.82%**

### 2 — Tripwire Engine (Deterministic Rules)
- Mass file rename detection (>50 files renamed in one window)
- VSS shadow copy deletion
- Ransom note creation (.txt files with ransom keywords)
- Triggers immediate ISOLATE regardless of ML score

---

## Response Actions

When ransomware is detected:

| Action | Method | Time |
|--------|--------|------|
| Kill ransomware process | `taskkill /PID /F /T` | ~80ms |
| Block all outbound traffic | `netsh advfirewall` | ~200ms |
| Block all inbound traffic | `netsh advfirewall` | ~200ms |
| Allow manager connection | `netsh advfirewall` | ~200ms |
| Alert to Wazuh SIEM | Docker exec | ~150ms |
| **Total response time** | | **~670ms** |

---

## SIEM Integration

- Wazuh Rule 110002 — Level 15 (critical)
- MITRE ATT&CK T1486 — Data Encrypted for Impact
- Auto-sync alerts via Docker exec
- Dashboard shows real-time alerts with tactic and technique tags

---

## Project Structure
nesrd-ransomware-detection/
├── api/                        # gRPC server, alert service
│   ├── grpc_server.py          # Manager gRPC server
│   ├── alert_service.py        # Wazuh alert sync
│   └── proto/nesrd.proto       # Protocol buffer definitions
├── core/                       # ML pipeline
│   ├── fusion/
│   │   ├── fusion_engine.py    # ONNX inference engine
│   │   └── tripwires.py        # Deterministic detection rules
│   ├── embeddings/
│   │   └── train_fasttext.py   # FastText training script
│   └── models/
│       └── train_conv1d.py     # Conv1D training script
├── config/
│   └── detection_config.yaml   # Thresholds and settings
├── scripts/                    # Dataset and model pipeline
│   ├── build_ransap_sequences.py
│   ├── balance_dataset.py
│   └── export_to_onnx.py
├── nesrd-agent/                # Windows endpoint agent
│   ├── agent.py                # Main agent entry point
│   ├── watchdog.py             # Agent self-healing watchdog
│   ├── collector/
│   │   └── etw_collector_logman.py  # Real-time ETW via logman
│   ├── grpc_client/
│   │   └── nesrd_client.py     # gRPC streaming client
│   ├── parser/
│   │   └── sliding_window.py   # Sliding window event aggregation
│   └── tokenizer/
│       └── behavior_tokenizer.py    # Event tokenization
├── nesrd_rules.xml             # Wazuh detection rules
├── nesrd_decoder.xml           # Wazuh decoder
└── docker-compose.yml          # Wazuh SIEM stack

---

## Setup

### Prerequisites

**Manager (Host Machine):**
- Python 3.11+
- Docker Desktop (for Wazuh)

**Agent (Windows VM):**
- Windows 10/11
- Python 3.11+
- Administrator privileges (required for ETW collection)

---

### Manager Setup

```bash
# Clone repository
git clone https://github.com/Athul-T-S/nesrd-ransomware-detection.git
cd nesrd-ransomware-detection

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Download models (see Models section below)
# Place models in core/models/

# Start Wazuh SIEM
cd wazuh-docker/single-node
docker compose up -d

# Setup Wazuh integration
.\scripts\setup_wazuh.ps1

# Start manager
python api/grpc_server.py
```

---

### Agent Setup (Windows VM)

```powershell
cd nesrd-agent

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Edit config/agent_config.yaml
# Set manager_host to your manager IP

# Run as Administrator
python agent.py

# Or use watchdog for auto-restart
python watchdog.py
```

---

### Configuration

**`config/detection_config.yaml`**
```yaml
thresholds:
  warning: 0.60      # ALERT threshold
  critical: 0.85     # ISOLATE threshold

tripwires:
  rapid_rename_threshold: 50    # files renamed in one window
```

**`nesrd-agent/config/agent_config.yaml`**
```yaml
manager:
  host: "10.0.0.1"    # Replace with your manager IP
  port: 50051

agent:
  id: "vm-win10-001"
  heartbeat_interval_sec: 30
```

---

## Models

The trained models are not included in this repository due to file size. To reproduce:

```bash
# 1. Download RanSAP 2022 dataset
# https://www.kaggle.com/datasets/hiranomanabu/ransap-2022-ransomware-behavioral-features

# 2. Build sequences
python scripts/build_ransap_sequences.py

# 3. Balance dataset
python scripts/balance_dataset.py

# 4. Train FastText embeddings
python core/embeddings/train_fasttext.py

# 5. Train Conv1D model
python core/models/train_conv1d.py

# 6. Export to ONNX
python scripts/export_to_onnx.py
```

---

## Performance

| Metric | Value |
|--------|-------|
| Detection accuracy | 85.12% |
| Precision | 91.84% |
| Recall | 77.09% |
| F1 Score | 83.82% |
| False Positive Rate | 6.85% |
| ONNX inference time | ~1ms |
| Keras inference time | ~94ms |
| ONNX speedup | 88x |
| Detection to isolation | ~670ms |

---

## Dataset

**RanSAP 2022** — Ransomware Storage Access Patterns  
- Source: Kaggle (Manabu Hirano, National Institute of Technology Toyota College)  
- Ransomware families: Ryuk, WannaCry, Sodinokibi, GandCrab4  
- Benign applications: Excel, Firefox  
- Storage condition: Windows 7, 120GB SSD  
- Training samples: 178,000 (89,000 ransomware + 89,000 benign, balanced)

---

## Multi-Agent Support

NESRD supports monitoring multiple endpoints simultaneously. Each agent connects independently to the manager via gRPC. The manager handles up to 10 concurrent agent connections.

To add a new agent:
1. Copy `nesrd-agent/` to the new endpoint
2. Edit `config/agent_config.yaml` — set a unique `agent.id`
3. Set `manager.host` to the manager IP
4. Run `python agent.py` as Administrator

---

## Acknowledgements

- RanSAP dataset: M. Hirano and R. Kobayashi, "RanSAP: An open dataset of ransomware storage access patterns", Forensic Science International: Digital Investigation, 2022
- Wazuh open source SIEM platform
- Microsoft ETW (Event Tracing for Windows) kernel provider

---

## Author

**Athul T.S**  
Lovely Professional University  
Capstone Project — Cybersecurity