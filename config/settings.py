"""
AI-DB-IDPS Configuration
"""

import os

# ── Database ─────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "mydb")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# ── Model ─────────────────────────────────────────────────
MODEL_PATH = os.getenv("MODEL_PATH", "model/autoencoder.pt")
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.001"))
INPUT_DIM = 16  # feature vector size

# ── Alerts ────────────────────────────────────────────────
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "himanshukori947@gmail.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_TO = os.getenv("ALERT_TO", "himanshukori947@gmail.com")

# ── Sensitive Tables ──────────────────────────────────────
SENSITIVE_TABLES = {"users", "payments", "orders", "admin", "credentials"}

# ── Logging ───────────────────────────────────────────────
LOG_FILE = os.getenv("LOG_FILE", "logs/idps.jsonl")

# ── Rate limiting (queries per minute per user) ───────────
RATE_LIMIT_QPM = int(os.getenv("RATE_LIMIT_QPM", 100))
