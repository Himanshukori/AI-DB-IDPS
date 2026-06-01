"""
database/connector.py

Safe database forwarding layer.
Executes ONLY pre-approved queries — never called for blocked queries.
"""

import os
import sys
from typing import Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.settings import DATABASE_URL


class DatabaseConnector:
    """
    Thin async wrapper around psycopg2 / asyncpg.
    Falls back to simulation mode if no DB is available.
    """

    def __init__(self):
        self._pool = None
        self._simulation_mode = False

    async def initialize(self):
        try:
            import asyncpg
            self._pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
            print("[DB] Connected to PostgreSQL")
        except Exception as e:
            print(f"[DB] Could not connect to PostgreSQL: {e}")
            print("[DB] Running in SIMULATION mode — queries will return mock data")
            self._simulation_mode = True

    async def execute_query(self, query: str) -> dict:
        """Execute a safe (pre-approved) SQL query."""
        if self._simulation_mode:
            return self._simulate(query)

        try:
            async with self._pool.acquire() as conn:
                q = query.strip().upper()
                if q.startswith("SELECT"):
                    rows = await conn.fetch(query)
                    return {"rows": [dict(r) for r in rows], "count": len(rows)}
                else:
                    result = await conn.execute(query)
                    return {"status": result, "count": 0}
        except Exception as e:
            return {"error": str(e), "count": 0}

    def _simulate(self, query: str) -> dict:
        """Return plausible mock results for demo/test mode."""
        q = query.strip().upper()
        if "SELECT" in q:
            return {
                "rows": [
                    {"id": 1, "name": "Mock Row 1", "value": "data_a"},
                    {"id": 2, "name": "Mock Row 2", "value": "data_b"},
                ],
                "count": 2,
                "note": "simulation_mode",
            }
        elif "INSERT" in q:
            return {"status": "INSERT 1", "count": 1, "note": "simulation_mode"}
        elif "UPDATE" in q:
            return {"status": "UPDATE 1", "count": 1, "note": "simulation_mode"}
        elif "DELETE" in q:
            return {"status": "DELETE 0", "count": 0, "note": "simulation_mode"}
        return {"status": "OK", "note": "simulation_mode"}

    async def close(self):
        if self._pool:
            await self._pool.close()


# ── Global instance ───────────────────────────────────────
db = DatabaseConnector()
