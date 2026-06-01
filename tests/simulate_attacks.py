"""
tests/simulate_attacks.py

Simulates realistic normal and attack queries against the AI-DB-IDPS.

Usage:
    # Offline (no server needed):
    python -m tests.simulate_attacks --offline

    # Against live server:
    python -m tests.simulate_attacks --url http://localhost:8000
"""

import argparse
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

TEST_CASES = [
    # ── NORMAL ────────────────────────────────────────────
    {"category": "Normal", "user": "alice",    "ip": "192.168.1.10",
     "query": "SELECT id, name FROM products WHERE category = 'books'",          "expected": "allowed"},
    {"category": "Normal", "user": "bob",      "ip": "10.0.0.5",
     "query": "SELECT COUNT(*) FROM orders WHERE status = 'pending'",            "expected": "allowed"},
    {"category": "Normal", "user": "charlie",  "ip": "192.168.1.20",
     "query": "INSERT INTO cart (user_id, product_id, qty) VALUES (5, 12, 1)",   "expected": "allowed"},
    {"category": "Normal", "user": "alice",    "ip": "192.168.1.10",
     "query": "UPDATE users SET last_login = NOW() WHERE id = 3",                "expected": "allowed"},
    {"category": "Normal", "user": "dave",     "ip": "10.0.0.8",
     "query": "SELECT p.name, c.name FROM products p JOIN categories c ON p.cat_id = c.id LIMIT 20",
                                                                                  "expected": "allowed"},
    {"category": "Normal", "user": "svc",      "ip": "10.0.0.1",
     "query": "DELETE FROM sessions WHERE expires < NOW()",                       "expected": "allowed"},
    {"category": "Normal", "user": "analyst",  "ip": "10.0.0.15",
     "query": "SELECT COUNT(*), status FROM orders GROUP BY status",              "expected": "allowed"},

    # ── SQL INJECTION ──────────────────────────────────────
    {"category": "SQL Injection", "user": "hacker",   "ip": "185.220.101.5",
     "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --",                      "expected": "blocked"},
    {"category": "SQL Injection", "user": "attacker", "ip": "45.33.32.156",
     "query": "' UNION SELECT username, password FROM users --",                 "expected": "blocked"},
    {"category": "SQL Injection", "user": "bot",      "ip": "198.51.100.22",
     "query": "SELECT * FROM accounts WHERE '1'='1'",                            "expected": "blocked"},
    {"category": "SQL Injection", "user": "evil",     "ip": "203.0.113.50",
     "query": "1; DROP TABLE users; --",                                          "expected": "blocked"},

    # ── DATA EXFILTRATION ─────────────────────────────────
    {"category": "Data Exfiltration", "user": "insider",   "ip": "192.168.1.99",
     "query": "SELECT ssn, credit_card, salary FROM users UNION SELECT null,null,null FROM information_schema.tables",
                                                                                  "expected": "blocked"},
    {"category": "Data Exfiltration", "user": "rogue_svc", "ip": "10.5.5.5",
     "query": "SELECT * FROM passwords JOIN users ON passwords.user_id = users.id",
                                                                                  "expected": "blocked"},
    {"category": "Data Exfiltration", "user": "exfil",     "ip": "203.0.113.77",
     "query": "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'",
                                                                                  "expected": "blocked"},

    # ── TIME-BASED INJECTION ──────────────────────────────
    {"category": "Time-Based Injection", "user": "slowbot",  "ip": "198.18.0.55",
     "query": "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",                   "expected": "blocked"},
    {"category": "Time-Based Injection", "user": "pgattack", "ip": "198.18.0.60",
     "query": "SELECT pg_sleep(10) FROM accounts",                               "expected": "blocked"},

    # ── COMMAND EXECUTION ──────────────────────────────────
    {"category": "Command Execution", "user": "sysattack",    "ip": "45.33.32.200",
     "query": "EXEC xp_cmdshell('whoami')",                                       "expected": "blocked"},
    {"category": "Command Execution", "user": "root_attempt", "ip": "185.220.0.1",
     "query": "EXECUTE sp_executesql N'DROP TABLE secrets'",                      "expected": "blocked"},

    # ── SCHEMA ENUMERATION ────────────────────────────────
    {"category": "Schema Enumeration", "user": "recon", "ip": "185.220.0.99",
     "query": "SELECT table_name FROM information_schema.tables",                 "expected": "blocked"},

    # ── AFTER-HOURS ANOMALY ───────────────────────────────
    {"category": "After-Hours Access", "user": "night_crawler", "ip": "192.168.1.200",
     "query": "SELECT * FROM salaries WHERE department = 'exec'",                 "expected": "blocked"},
]


def run_offline():
    from detection.engine import engine
    from detection.rules import rule_check
    from config.settings import MODEL_PATH, ANOMALY_THRESHOLD

    engine.initialize(MODEL_PATH, ANOMALY_THRESHOLD)

    print("\n" + "═"*72)
    print("  AI-DB-IDPS Attack Simulation  —  OFFLINE MODE")
    print(f"  Threshold: {engine.threshold}  |  Model: {MODEL_PATH}")
    print("═"*72)

    passed = failed = 0
    cat_stats = {}

    for i, tc in enumerate(TEST_CASES, 1):
        # Layer 1: rules
        rule_result = rule_check(tc["query"])
        if rule_result["blocked"]:
            verdict = "blocked"
            score   = 1.0
            layer   = "rules"
            detail  = rule_result["reason"]
        else:
            # Layer 2: ML
            r       = engine.score(tc["query"], tc["user"], tc["ip"])
            verdict = "allowed" if r["allowed"] else "blocked"
            score   = r["anomaly_score"]
            layer   = "ml"
            detail  = f"score={score:.4f}"

        ok     = verdict == tc["expected"]
        symbol = "✅" if ok else "❌"
        status = "PASS" if ok else "FAIL"

        print(f"\n[{i:02d}] {symbol}  {tc['category']:<22} [{layer.upper()}]  {status}")
        print(f"       User   : {tc['user']} @ {tc['ip']}")
        print(f"       Query  : {tc['query'][:68]}{'…' if len(tc['query'])>68 else ''}")
        print(f"       Detail : {detail}")
        print(f"       Expect : {tc['expected'].upper()}  →  Got : {verdict.upper()}")

        cat = tc["category"]
        cat_stats.setdefault(cat, {"pass": 0, "fail": 0})
        if ok:
            passed += 1
            cat_stats[cat]["pass"] += 1
        else:
            failed += 1
            cat_stats[cat]["fail"] += 1

    total = passed + failed
    acc   = passed / total * 100

    print("\n" + "═"*72)
    print("  CATEGORY BREAKDOWN")
    print("  " + "─"*50)
    for cat, s in cat_stats.items():
        t = s["pass"] + s["fail"]
        print(f"  {cat:<26} {s['pass']}/{t}")
    print("  " + "─"*50)
    print(f"  TOTAL  {passed}/{total}  ({acc:.1f}% accuracy)")
    print("═"*72 + "\n")


def run_against_server(base_url: str):
    import urllib.request

    print("\n" + "═"*72)
    print(f"  AI-DB-IDPS Attack Simulation  →  {base_url}")
    print("═"*72)

    passed = failed = 0

    for i, tc in enumerate(TEST_CASES, 1):
        payload = json.dumps({"user": tc["user"], "ip": tc["ip"], "query": tc["query"]}).encode()
        req = urllib.request.Request(f"{base_url}/query", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = json.loads(resp.read())
            except urllib.error.HTTPError as e:
                body = json.loads(e.read())

            verdict = body.get("status", "unknown")
            score   = body.get("anomaly_score", -1)
            layer   = body.get("layer", "?")
            ok      = verdict == tc["expected"]
            symbol  = "✅" if ok else "❌"
            status  = "PASS" if ok else "FAIL"

            print(f"\n[{i:02d}] {symbol}  {tc['category']:<22} [{layer.upper()}]  {status}")
            print(f"       Score={score}  Verdict={verdict.upper()}  Expected={tc['expected'].upper()}")

            if ok: passed += 1
            else:  failed += 1
            time.sleep(0.05)

        except Exception as e:
            print(f"\n[{i:02d}] ⚠  Error: {e}")
            failed += 1

    total = passed + failed
    acc   = passed / total * 100 if total else 0
    print("\n" + "═"*72)
    print(f"  TOTAL  {passed}/{total}  ({acc:.1f}% accuracy)")
    print("═"*72 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-DB-IDPS Attack Simulator")
    parser.add_argument("--url",     type=str, default=None)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    if args.offline or not args.url:
        run_offline()
    else:
        run_against_server(args.url)
