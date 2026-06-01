"""
detection/rules.py

Rule-based pre-filter — fast deterministic checks that catch
high-confidence attacks BEFORE the ML model even runs.
Used as defence-in-depth alongside the autoencoder.
"""

import re
from config.settings import SENSITIVE_TABLES

# ── Hard-block patterns (regex) ───────────────────────────
HARD_BLOCK_PATTERNS = [
    (re.compile(r'\bOR\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?', re.I),     "Tautology OR injection"),
    (re.compile(r'\bAND\b\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+[\'"]?', re.I),    "Tautology AND injection"),
    (re.compile(r"'[^']*'\s*=\s*'[^']*'", re.I),                               "String tautology"),
    (re.compile(r'\bUNION\b.{0,60}\bSELECT\b', re.I | re.S),                  "UNION SELECT injection"),
    (re.compile(r'\b(SLEEP|WAITFOR\s+DELAY|PG_SLEEP|BENCHMARK)\s*\(', re.I),  "Time-delay injection"),
    (re.compile(r'\bEXEC\s*\(|xp_cmdshell|sp_executesql', re.I),              "Command execution"),
    (re.compile(r'(--|#)\s*$', re.M),                                           "SQL comment terminator"),
    (re.compile(r'/\*.*?\*/', re.S),                                            "Block comment"),
    (re.compile(r';\s*(DROP|TRUNCATE|DELETE\s+FROM\s+\w+\s*;|ALTER)', re.I),  "Stacked destructive statement"),
    (re.compile(r'\bINFORMATION_SCHEMA\b', re.I),                              "Schema enumeration"),
    (re.compile(r'\bSYS(TABLES|COLUMNS|OBJECTS|DATABASES)\b', re.I),          "System table enumeration"),
    (re.compile(r'\bLOAD_FILE\b|\bINTO\s+OUTFILE\b|\bINTO\s+DUMPFILE\b', re.I), "File I/O injection"),
    (re.compile(r'\bCHAR\s*\(\s*\d+', re.I),                                  "CHAR encoding obfuscation"),
    (re.compile(r'0x[0-9a-fA-F]{4,}', re.I),                                  "Hex encoding"),
]

# ── Sensitive table mass-dump detector ────────────────────
# Block SELECT * FROM <sensitive_table>  with no meaningful WHERE
_WILDCARD_SENSITIVE = re.compile(r'\bSELECT\s+\*\s+FROM\s+(\w+)', re.I)

def _is_mass_dump(query: str) -> tuple[bool, str]:
    """Block SELECT * FROM <sensitive> without a specific WHERE clause."""
    for m in _WILDCARD_SENSITIVE.finditer(query):
        table = m.group(1).lower()
        if table in SENSITIVE_TABLES:
            # Allow if there's a WHERE with an equality on a specific id
            has_specific_where = bool(re.search(
                r'\bWHERE\b.{0,80}\b\w+\s*=\s*[\d\'"]', query, re.I | re.S
            ))
            if not has_specific_where:
                return True, f"Mass dump attempt on sensitive table '{table}'"
    return False, ""


# ── JOIN on multiple sensitive tables ─────────────────────
def _is_sensitive_join_dump(query: str) -> tuple[bool, str]:
    """Block queries that JOIN two or more sensitive tables (exfiltration pattern)."""
    import sqlparse
    parsed = sqlparse.parse(query)
    tables_hit = set()
    for token in (parsed[0].flatten() if parsed else []):
        if token.ttype is sqlparse.tokens.Name:
            if token.value.lower() in SENSITIVE_TABLES:
                tables_hit.add(token.value.lower())
    if len(tables_hit) >= 2:
        return True, f"Query joins multiple sensitive tables: {tables_hit}"
    return False, ""


def rule_check(query: str) -> dict:
    """
    Run all rule-based checks.
    Returns:
        { "blocked": bool, "reason": str or None }
    """
    # 1. Hard-block regex patterns
    for pattern, reason in HARD_BLOCK_PATTERNS:
        if pattern.search(query):
            return {"blocked": True, "reason": f"Rule: {reason}"}

    # 2. Mass dump of sensitive table
    blocked, reason = _is_mass_dump(query)
    if blocked:
        return {"blocked": True, "reason": f"Rule: {reason}"}

    # 3. Multi-sensitive-table JOIN
    blocked, reason = _is_sensitive_join_dump(query)
    if blocked:
        return {"blocked": True, "reason": f"Rule: {reason}"}

    return {"blocked": False, "reason": None}
