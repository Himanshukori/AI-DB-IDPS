"""
features/extractor.py

Extracts a fixed-size numeric feature vector from a raw SQL string.
All features are normalized to [0, 1] where possible.
"""

import re
import math
import time
from datetime import datetime
from typing import List

import sqlparse
from sqlparse.sql import IdentifierList, Identifier
from sqlparse.tokens import Keyword, DML

from config.settings import SENSITIVE_TABLES

# ── Query type mapping ────────────────────────────────────
QUERY_TYPES = {
    "SELECT": 0, "INSERT": 1, "UPDATE": 2, "DELETE": 3,
    "DROP": 4, "CREATE": 5, "ALTER": 6, "EXEC": 7,
    "UNION": 8, "TRUNCATE": 9,
}


def _get_query_type_id(parsed) -> float:
    for token in parsed.tokens:
        if token.ttype is DML:
            return QUERY_TYPES.get(token.value.upper(), 9) / 9.0
    for token in parsed.flatten():
        if token.ttype is Keyword and token.value.upper() in QUERY_TYPES:
            return QUERY_TYPES.get(token.value.upper(), 9) / 9.0
    return 0.9


def _extract_tables(parsed) -> List[str]:
    tables = []
    from_seen = False
    for token in parsed.flatten():
        if token.ttype is Keyword and token.value.upper() in ("FROM", "INTO", "UPDATE", "JOIN"):
            from_seen = True
            continue
        if from_seen:
            if token.ttype is sqlparse.tokens.Name:
                tables.append(token.value.lower())
                from_seen = False
            elif token.ttype not in (sqlparse.tokens.Whitespace, sqlparse.tokens.Newline):
                from_seen = False
    return tables


def extract_features(query: str, user: str = "", ip: str = "") -> List[float]:
    """
    Returns a 16-dimensional float list representing the SQL query.
    """
    q = query.strip()
    parsed = sqlparse.parse(q)[0] if q else None

    # 1. Query type id (normalized 0-1)
    f1 = _get_query_type_id(parsed) if parsed else 0.9

    # 2. Query length (log-normalized)
    f2 = min(math.log1p(len(q)) / 10.0, 1.0)

    # 3. Number of statements (stacked queries)
    f3 = min(len(sqlparse.parse(q)) / 5.0, 1.0)

    # 4. Has UNION
    f4 = 1.0 if re.search(r'\bUNION\b', q, re.I) else 0.0

    # 5. Has JOIN
    f5 = 1.0 if re.search(r'\bJOIN\b', q, re.I) else 0.0

    # 6. Number of tables accessed (normalized)
    tables = _extract_tables(parsed) if parsed else []
    f6 = min(len(tables) / 10.0, 1.0)

    # 7. Sensitive table touched
    f7 = 1.0 if any(t in SENSITIVE_TABLES for t in tables) else 0.0

    # 8. Has comment (-- or /* */)
    f8 = 1.0 if re.search(r'(--|/\*)', q) else 0.0

    # 9. Has OR/AND with tautology pattern (1=1, 'a'='a')
    f9 = 1.0 if re.search(r"(\b1\s*=\s*1\b|'[^']+'\s*=\s*'[^']+')", q, re.I) else 0.0

    # 10. Has SLEEP/WAITFOR/BENCHMARK (time-based injection)
    f10 = 1.0 if re.search(r'\b(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\b', q, re.I) else 0.0

    # 11. Has EXEC/xp_cmdshell/EXECUTE
    f11 = 1.0 if re.search(r'\b(EXEC|EXECUTE|xp_cmdshell|sp_executesql)\b', q, re.I) else 0.0

    # 12. Has subquery (nested SELECT)
    f12 = 1.0 if re.search(r'\(\s*SELECT\b', q, re.I) else 0.0

    # 13. Hour of day (normalized 0-1)
    hour = datetime.now().hour
    f13 = hour / 23.0

    # 14. Is after-hours (before 8am or after 8pm) 
    f14 = 1.0 if hour < 8 or hour >= 20 else 0.0

    # 15. IP address entropy (how "unusual" is the IP)
    f15 = _ip_entropy(ip)

    # 16. Username length (proxy for script-generated usernames)
    f16 = min(len(user) / 32.0, 1.0)

    return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16]


def _ip_entropy(ip: str) -> float:
    """Simple heuristic: private IPs = low score, unusual = higher."""
    if not ip:
        return 0.5
    private_prefixes = ("10.", "192.168.", "172.16.", "127.", "::1")
    if any(ip.startswith(p) for p in private_prefixes):
        return 0.1
    # Non-private IP gets moderate entropy score
    return 0.7
