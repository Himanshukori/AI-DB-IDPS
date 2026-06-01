# 🛡️ AI-DB-IDPS
## AI-Powered Inline Database Intrusion Detection & Prevention System

```
Application  →  AI-IDS Gateway  →  Database
```

Every SQL query is intercepted, analyzed by a trained deep-learning model,
and either **forwarded safely** or **blocked immediately** — before it reaches your database.

---

## 🏗️ Architecture

```
ai_db_idps/
├── main.py                    # Entrypoint
├── api/
│   └── gateway.py             # FastAPI proxy gateway
├── detection/
│   └── engine.py              # Real-time inference engine (singleton)
├── model/
│   ├── autoencoder.py         # PyTorch Autoencoder (16→64→32→16→32→64→16)
│   └── train.py               # Training script
├── features/
│   └── extractor.py           # 16-dimensional SQL feature extraction
├── database/
│   └── connector.py           # Safe PostgreSQL forwarding layer
├── logging_system/
│   └── logger.py              # Structured JSON (JSONL) logger
├── alerts/
│   └── alerter.py             # Async SMTP email alerts
├── config/
│   └── settings.py            # All configuration & thresholds
└── tests/
    └── simulate_attacks.py    # Attack simulation suite
```

---

## ⚙️ Technology Stack

| Component      | Technology          |
|----------------|---------------------|
| API Gateway    | FastAPI             |
| Database       | PostgreSQL          |
| ML Framework   | PyTorch             |
| SQL Parsing    | sqlparse            |
| Data           | NumPy / Pandas      |
| Logging        | JSONL (Elasticsearch-ready) |
| Alerts         | SMTP Email          |

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
cd ai_db_idps
pip install -r requirements.txt
```

### 2. Train the model
```bash
# Using built-in normal queries (demo)
python -m model.train

# Using your own CSV (columns: query, user, ip)
python -m model.train --data data/normal_queries.csv --epochs 150
```

### 3. Start the gateway
```bash
# Start directly
python main.py

# Train + start in one command
python main.py --train

# Custom host/port
python main.py --host 0.0.0.0 --port 8000
```

### 4. Configure (environment variables)
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=mydb
export DB_USER=postgres
export DB_PASSWORD=secret

export ANOMALY_THRESHOLD=0.05   # lower = stricter
export MODEL_PATH=model/autoencoder.pt

export SMTP_HOST=smtp.gmail.com
export SMTP_USER=alerts@company.com
export SMTP_PASSWORD=apppassword
export ALERT_TO=security@company.com
```

---

## 📡 API Reference

### `POST /query` — Submit a SQL query
```json
{
  "user": "alice",
  "ip": "192.168.1.10",
  "query": "SELECT * FROM orders WHERE user_id = 1"
}
```

**SAFE response:**
```json
{
  "status": "allowed",
  "anomaly_score": 0.0031,
  "latency_ms": 3.2,
  "data": {"rows": [...], "count": 5}
}
```

**BLOCKED response (HTTP 403):**
```json
{
  "status": "blocked",
  "reason": "Anomaly score 0.2341 exceeds threshold 0.0500",
  "anomaly_score": 0.2341,
  "latency_ms": 2.8
}
```

### `POST /admin/score` — Dry-run scoring (no DB execution)
### `GET  /stats`        — System statistics
### `GET  /logs?n=50`    — Recent query logs
### `POST /admin/threshold` — Update threshold live
### `GET  /health`          — Health check

---

## 🔬 Query Flow (Critical Path)

```
POST /query
    │
    ▼
Extract 16 features from SQL
    │
    ▼
Run Autoencoder forward pass
    │
    ▼
Compute MSE reconstruction error
    │
    ├── error < threshold ──→ Forward to PostgreSQL ──→ Return data
    │
    └── error ≥ threshold ──→ Block (HTTP 403)
                              └──→ Log + Email Alert
```

---

## 🧠 Feature Engineering (16 Dimensions)

| # | Feature                  | Description                            |
|---|--------------------------|----------------------------------------|
| 1 | Query type ID            | SELECT=0, INSERT=0.11, DROP=0.44, etc |
| 2 | Query length             | Log-normalized character count         |
| 3 | Statement count          | Stacked queries (`;` separated)        |
| 4 | Has UNION                | Boolean                                |
| 5 | Has JOIN                 | Boolean                                |
| 6 | Table count              | Number of tables referenced            |
| 7 | Sensitive table access   | Touches users/passwords/ssn/etc        |
| 8 | Has SQL comment          | `--` or `/* */`                        |
| 9 | Tautology pattern        | `1=1` or `'a'='a'`                     |
|10 | Time-delay functions     | SLEEP / WAITFOR / PG_SLEEP             |
|11 | Execution functions      | EXEC / xp_cmdshell / sp_executesql    |
|12 | Has subquery             | Nested SELECT                          |
|13 | Hour of day              | Normalized 0–1                         |
|14 | After-hours flag         | Before 8am or after 8pm               |
|15 | IP entropy               | Private IP = low, external = high      |
|16 | Username length          | Proxy for script-generated names       |

---

## 🧠 Model Architecture

```
Input (16)
    │
   [64] ReLU + BatchNorm    ← encoder
   [32] ReLU + BatchNorm
   [16] ReLU                ← latent bottleneck
   [32] ReLU + BatchNorm    ← decoder
   [64] ReLU + BatchNorm
    │
Output (16) Sigmoid
```

- **Loss:** MSE between input and reconstruction
- **Optimizer:** Adam with weight decay
- **Scheduler:** StepLR
- **Trained ONLY on normal queries**
- Anomalies reconstruct poorly → high MSE → blocked

---

## 🧪 Testing Attacks

```bash
# Offline mode (no server needed)
python -m tests.simulate_attacks --offline

# Against live server
python -m tests.simulate_attacks --url http://localhost:8000
```

Attack categories tested:
- ✅ Normal SELECT / INSERT / UPDATE / DELETE
- 🚨 SQL Injection (`OR 1=1`, `UNION SELECT`, tautologies)
- 🚨 Data Exfiltration (sensitive table mass-dumps)
- 🚨 Time-Based Injection (SLEEP / PG_SLEEP)
- 🚨 Command Execution (xp_cmdshell)
- 🚨 After-Hours Anomalous Access

---

## 📊 Log Format (JSONL / Elasticsearch-ready)

```json
{
  "@timestamp": "2025-03-15T02:31:07+00:00",
  "user": "hacker",
  "ip": "185.220.101.5",
  "query": "' UNION SELECT username, password FROM users --",
  "decision": "blocked",
  "anomaly_score": 0.234561,
  "latency_ms": 4.2,
  "reason": "Anomaly score 0.2346 exceeds threshold 0.0500"
}
```

---

## 🔄 Retraining the Model

```bash
# Export more normal queries to CSV first
# Then retrain with new data
python -m model.train \
    --data data/normal_queries.csv \
    --epochs 200 \
    --lr 0.0005 \
    --save model/autoencoder.pt
```

The suggested threshold is printed after training. Update via:
```bash
curl -X POST http://localhost:8000/admin/threshold \
     -H "Content-Type: application/json" \
     -d '{"threshold": 0.045}'
```

---

## 📧 Alert Email

When a query is blocked, an HTML email is sent immediately containing:
- Timestamp, User, IP
- Anomaly score
- The exact blocked query
- Reason for blocking

---

## 🔐 Security Properties

| Property               | Implementation                              |
|------------------------|---------------------------------------------|
| No direct DB exposure  | DB only accessible via gateway              |
| Explainable decisions  | Anomaly score returned in every response    |
| Non-repudiation        | Every query logged with full metadata       |
| Live threshold tuning  | `POST /admin/threshold` without restart     |
| Fast inference         | <10ms scoring (PyTorch, CPU-compatible)     |
| Async alerts           | Email sent in background thread             |
