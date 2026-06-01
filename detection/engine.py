"""
detection/engine.py

Real-time inference engine.
Loads the model ONCE at startup and scores each query in <10ms.
"""

import os
import time
import sys

import torch
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from model.autoencoder import SQLAutoencoder
from features.extractor import extract_features
from config.settings import MODEL_PATH, ANOMALY_THRESHOLD, INPUT_DIM


class DetectionEngine:
    """Inference engine — call initialize() once at app startup."""

    def __init__(self):
        self._initialized = False
        self.model = None
        self.threshold = ANOMALY_THRESHOLD

    def initialize(
        self, model_path: str = MODEL_PATH, threshold: float = ANOMALY_THRESHOLD
    ):
        self.threshold = threshold
        self.model = SQLAutoencoder(INPUT_DIM)

        if os.path.exists(model_path):
            self.model.load_state_dict(
                torch.load(model_path, map_location="cpu", weights_only=True)
            )
            print(f"[DetectionEngine] Model loaded from {model_path}")
        else:
            print(f"[DetectionEngine] ⚠ Model not found at {model_path}.")
            print(f"[DetectionEngine]   Run: python -m model.train  to train first.")

        self.model.eval()
        self._initialized = True

    def score(self, query: str, user: str = "", ip: str = "") -> dict:
        if not self._initialized:
            self.initialize()

        t0 = time.perf_counter()

        features = extract_features(query, user, ip)
        tensor = torch.tensor([features], dtype=torch.float32)

        error = self.model.reconstruction_error(tensor).item()
        is_anomaly = error > self.threshold

        allowed = not is_anomaly
        latency = (time.perf_counter() - t0) * 1000

        # 🧠 Explanation
        if is_anomaly:
            explanation = (
                f"Query deviates from learned normal behavior "
                f"(score={error:.6f}, threshold={self.threshold})"
            )
        else:
            explanation = "Query matches learned normal behavior"

        # 🚨 Severity
        if error > self.threshold * 5:
            severity = "HIGH"
        elif error > self.threshold * 2:
            severity = "MEDIUM"
        elif error > self.threshold:
            severity = "LOW"
        else:
            severity = "NORMAL"

        # 🎯 Attack Type
        q = query.lower()
        if "union" in q:
            attack_type = "SQL Injection"
        elif "sleep" in q or "waitfor" in q:
            attack_type = "Time-Based Injection"
        elif "xp_cmdshell" in q or "exec" in q:
            attack_type = "Command Execution"
        elif "information_schema" in q:
            attack_type = "Schema Enumeration"
        else:
            attack_type = "Normal / Unknown"

        # 🔥 Highlight query
        def highlight_query(query: str) -> str:
            dangerous = ["union", "select", "--", "1=1", "drop", "exec"]
            q = query
            for word in dangerous:
                q = q.replace(word, f"[⚠ {word.upper()}]")
            return q

        return {
            "allowed": allowed,
            "anomaly_score": round(error, 6),
            "latency_ms": round(latency, 3),
            "features": features,
            "explanation": explanation,
            "severity": severity,
            "attack_type": attack_type,
            "highlighted_query": highlight_query(query),
        }

    def score_batch(self, queries: list) -> list:
        return [
            self.score(q.get("query", ""), q.get("user", ""), q.get("ip", ""))
            for q in queries
        ]

    def update_threshold(self, new_threshold: float):
        self.threshold = new_threshold
        print(f"[DetectionEngine] Threshold updated to {new_threshold}")


# One engine per process — instantiated fresh each run
engine = DetectionEngine()
