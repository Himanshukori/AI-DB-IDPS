"""
api/gateway.py  —  AI-DB-IDPS FastAPI Gateway

Query flow:
  POST /query
       │
       ▼
  Rule-based pre-filter  (deterministic, ~0.1ms)
       │ blocked → 403 immediately
       │
       ▼
  ML Autoencoder scoring  (<5ms)
       │ score ≥ threshold → 403
       │
       ▼
  Forward to PostgreSQL → return data
"""

import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from logging_system.logger import read_logs

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.settings import ANOMALY_THRESHOLD, MODEL_PATH
from detection.engine import engine
from detection.rules import rule_check
from database.connector import db
from logging_system.logger import log_event
from alerts.alerter import send_alert


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "=" * 60)
    print("  AI-DB-IDPS Gateway — Starting")
    print("=" * 60)
    engine.initialize(MODEL_PATH, ANOMALY_THRESHOLD)
    await db.initialize()
    print(f"  Threshold : {engine.threshold}")
    print(f"  Model     : {MODEL_PATH}")
    print("=" * 60 + "\n")
    yield
    await db.close()
    print("\n[Gateway] Shutdown complete.")


app = FastAPI(
    title="AI-DB-IDPS Gateway",
    description="AI-powered Inline Database Intrusion Detection & Prevention System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────
class QueryRequest(BaseModel):
    user: str
    ip: str
    query: str


class ThresholdUpdate(BaseModel):
    threshold: float


# ── Main endpoint ─────────────────────────────────────────
from alerts.alerter import send_alert
from logging_system.logger import log_event

@app.get("/")
def home():
    return {
        "message": "AI-DB-IDPS is running 🚀",
        "docs": "/docs"
    }


@app.post("/query")
async def analyze(req: QueryRequest):
    result = engine.score(req.query, req.user, req.ip)

    decision = "allowed" if result["allowed"] else "blocked"

    # ✅ Log everything
    log_event(
        {
            "user": req.user,
            "ip": req.ip,
            "query": req.query,
            "decision": decision,
            "score": result["anomaly_score"],
            "explanation": result.get("explanation", "No explanation available"),
        }
    )

    if not result["allowed"]:
        send_alert(
            user=req.user,
            ip=req.ip,
            query=req.query,
            anomaly_score=result["anomaly_score"],
            explanation=result.get("explanation", "No explanation"),
        )

    return {"status": decision, **result}


# ── Admin / monitoring endpoints ──────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": engine._initialized,
        "threshold": engine.threshold,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/stats")
async def stats():
    return log_event.get_stats()


@app.get("/logs")
async def recent_logs(n: int = 50):
    logs = read_logs(limit=n)
    return {"logs": logs}


@app.post("/admin/threshold")
async def update_threshold(body: ThresholdUpdate):
    engine.update_threshold(body.threshold)
    return {"status": "ok", "threshold": body.threshold}


@app.post("/admin/score")
async def score_only(req: QueryRequest):
    """Dry-run: analyze both layers without executing the query."""
    rule_result = rule_check(req.query)
    if rule_result["blocked"]:
        return {
            "verdict": "MALICIOUS",
            "layer": "rules",
            "reason": rule_result["reason"],
            "anomaly_score": 1.0,
        }
    result = engine.score(req.query, req.user, req.ip)
    return {
        "verdict": "SAFE" if result["allowed"] else "MALICIOUS",
        "layer": "ml",
        "anomaly_score": result["anomaly_score"],
        "threshold": engine.threshold,
        "latency_ms": result["latency_ms"],
        "features": result["features"],
    }
