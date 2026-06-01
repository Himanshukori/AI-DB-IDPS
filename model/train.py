"""
model/train.py

Train the Autoencoder on NORMAL SQL queries only.
Usage:
    python -m model.train
    python -m model.train --data data/normal_queries.csv --epochs 200
"""

import argparse
import json
import os
import sys

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from model.autoencoder import SQLAutoencoder
from features.extractor import extract_features
from config.settings import MODEL_PATH, INPUT_DIM

# ── Large set of normal SQL queries ──────────────────────
DEFAULT_NORMAL_QUERIES = [
    # SELECT — simple lookups
    ("SELECT * FROM orders WHERE user_id = 1", "alice", "192.168.1.10"),
    ("SELECT id, name FROM products LIMIT 10", "bob", "192.168.1.11"),
    ("SELECT COUNT(*) FROM sessions WHERE active = true", "dave", "10.0.0.8"),
    ("SELECT email FROM users WHERE id = 5", "alice", "192.168.1.10"),
    ("SELECT * FROM categories", "guest", "192.168.1.50"),
    ("SELECT name, price FROM products WHERE category = 'electronics'", "dave", "10.0.0.8"),
    ("SELECT AVG(rating) FROM reviews WHERE product_id = 7", "bob", "192.168.1.11"),
    ("SELECT total FROM invoices WHERE status = 'paid' ORDER BY created_at DESC LIMIT 5", "bob", "192.168.1.11"),
    ("SELECT id, title, body FROM posts WHERE published = true LIMIT 20", "reader", "10.0.0.20"),
    ("SELECT username FROM accounts WHERE email = 'alice@example.com'", "alice", "192.168.1.10"),
    ("SELECT stock FROM inventory WHERE product_id = 42", "svc_user", "10.0.0.1"),
    ("SELECT * FROM shipping WHERE order_id = 100", "alice", "192.168.1.10"),
    ("SELECT city, country FROM addresses WHERE user_id = 3", "charlie", "10.0.0.5"),
    ("SELECT MAX(amount) FROM transactions WHERE date = '2024-01-01'", "finance", "10.0.0.9"),
    ("SELECT * FROM tags WHERE post_id = 55", "editor", "192.168.1.30"),

    # SELECT with JOIN — normal business queries
    ("SELECT p.name, c.title FROM products p JOIN categories c ON p.cat_id = c.id", "bob", "192.168.1.11"),
    ("SELECT o.id, u.email FROM orders o JOIN users u ON o.user_id = u.id LIMIT 10", "admin", "192.168.1.1"),
    ("SELECT r.body, u.username FROM reviews r JOIN users u ON r.user_id = u.id WHERE r.product_id = 5", "guest", "192.168.1.50"),
    ("SELECT i.stock, p.name FROM inventory i JOIN products p ON i.product_id = p.id WHERE i.stock < 10", "svc_user", "10.0.0.1"),
    ("SELECT a.city, COUNT(o.id) FROM addresses a JOIN orders o ON a.user_id = o.user_id GROUP BY a.city", "analyst", "10.0.0.15"),

    # INSERT — normal writes
    ("INSERT INTO logs (event, ts) VALUES ('login', NOW())", "charlie", "10.0.0.5"),
    ("INSERT INTO cart (user_id, product_id, qty) VALUES (1, 20, 2)", "charlie", "10.0.0.5"),
    ("INSERT INTO events (type, payload) VALUES ('view', '{}')", "alice", "192.168.1.10"),
    ("INSERT INTO reviews (user_id, product_id, rating, body) VALUES (3, 7, 5, 'Great!')", "dave", "10.0.0.8"),
    ("INSERT INTO sessions (user_id, token, expires) VALUES (1, 'abc123', NOW() + INTERVAL '1 hour')", "svc_user", "10.0.0.1"),
    ("INSERT INTO notifications (user_id, message, read) VALUES (5, 'Your order shipped', false)", "svc_user", "10.0.0.1"),

    # UPDATE — normal record mutations
    ("UPDATE users SET last_login = NOW() WHERE id = 42", "alice", "192.168.1.10"),
    ("UPDATE inventory SET stock = stock - 1 WHERE product_id = 15", "svc_user", "10.0.0.1"),
    ("UPDATE orders SET status = 'shipped' WHERE id = 300", "logistics", "10.0.0.12"),
    ("UPDATE sessions SET expires = NOW() + INTERVAL '30 minutes' WHERE token = 'xyz789'", "svc_user", "10.0.0.1"),
    ("UPDATE reviews SET body = 'Updated review' WHERE id = 88 AND user_id = 3", "dave", "10.0.0.8"),

    # DELETE — safe cleanup
    ("DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL '7 days'", "svc_user", "10.0.0.1"),
    ("DELETE FROM sessions WHERE expires < NOW()", "svc_user", "10.0.0.1"),
    ("DELETE FROM cart WHERE user_id = 5 AND product_id = 10", "charlie", "10.0.0.5"),
    ("DELETE FROM notifications WHERE user_id = 3 AND read = true", "alice", "192.168.1.10"),

    # Aggregation & reporting
    ("SELECT COUNT(*), status FROM orders GROUP BY status", "analyst", "10.0.0.15"),
    ("SELECT DATE_TRUNC('month', created_at), SUM(total) FROM invoices GROUP BY 1 ORDER BY 1", "finance", "10.0.0.9"),
    ("SELECT category, AVG(price) FROM products GROUP BY category ORDER BY AVG(price) DESC", "analyst", "10.0.0.15"),
]


def load_queries_from_csv(path: str):
    import csv
    queries = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            queries.append((row["query"], row.get("user", ""), row.get("ip", "")))
    return queries


def build_feature_matrix(queries):
    features = []
    for query, user, ip in queries:
        try:
            feat = extract_features(query, user, ip)
            features.append(feat)
        except Exception as e:
            print(f"[WARN] Skipping query: {e}")
    return np.array(features, dtype=np.float32)


def train(queries, epochs=200, batch_size=16, lr=5e-4, save_path=MODEL_PATH):
    print(f"[INFO] Training on {len(queries)} normal queries for {epochs} epochs")

    X = build_feature_matrix(queries)

    # Augment with small Gaussian noise for robustness
    augmented = []
    for _ in range(5):
        noise = np.random.normal(0, 0.008, X.shape).astype(np.float32)
        augmented.append(np.clip(X + noise, 0, 1))
    X_all = np.vstack([X] + augmented)

    tensor = torch.tensor(X_all)
    dataset = TensorDataset(tensor)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

    model = SQLAutoencoder(INPUT_DIM)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.MSELoss()
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_loss = float("inf")
    model.train()

    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            output = model(batch)
            loss = criterion(output, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(loader)
        scheduler.step()

        if epoch % 20 == 0 or epoch == 1:
            print(f"  Epoch {epoch:4d}/{epochs} | Loss: {avg_loss:.6f}")

        if avg_loss < best_loss:
            best_loss = avg_loss
            os.makedirs(os.path.dirname(save_path) if os.path.dirname(save_path) else ".", exist_ok=True)
            torch.save(model.state_dict(), save_path)

    print(f"\n[✓] Training complete. Best loss: {best_loss:.6f}")
    print(f"[✓] Model saved to: {save_path}")

    # Compute threshold from training data errors
    model.eval()
    model.load_state_dict(torch.load(save_path, weights_only=True))
    errors = model.reconstruction_error(torch.tensor(X)).numpy()

    mean_err = float(np.mean(errors))
    std_err  = float(np.std(errors))
    # threshold = mean + 2σ gives ~97.7% true-positive rate on normal
    threshold = mean_err + 2 * std_err

    print(f"[✓] Training error  → mean={mean_err:.4f}  std={std_err:.4f}")
    print(f"[✓] Suggested threshold (mean + 2σ): {threshold:.4f}")
    print(f"    → Set ANOMALY_THRESHOLD={threshold:.4f} in config/settings.py or env")

    stats = {
        "threshold_suggested": threshold,
        "train_error_mean": mean_err,
        "train_error_std": std_err,
        "n_samples": len(X),
    }
    stats_path = save_path.replace(".pt", "_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"[✓] Stats saved to: {stats_path}")

    return model, threshold


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train AI-DB-IDPS Autoencoder")
    parser.add_argument("--data",       type=str,   default=None,      help="CSV (columns: query,user,ip)")
    parser.add_argument("--epochs",     type=int,   default=200)
    parser.add_argument("--batch-size", type=int,   default=16)
    parser.add_argument("--lr",         type=float, default=5e-4)
    parser.add_argument("--save",       type=str,   default=MODEL_PATH)
    args = parser.parse_args()

    if args.data:
        queries = load_queries_from_csv(args.data)
        print(f"[INFO] Loaded {len(queries)} queries from {args.data}")
    else:
        print("[INFO] Using built-in normal query set for training")
        queries = DEFAULT_NORMAL_QUERIES

    train(queries, epochs=args.epochs, batch_size=args.batch_size,
          lr=args.lr, save_path=args.save)
