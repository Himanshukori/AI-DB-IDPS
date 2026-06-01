"""
main.py — Start the AI-DB-IDPS Gateway

Usage:
    python main.py
    python main.py --host 0.0.0.0 --port 8000
    python main.py --train          # train model first, then start
"""
# deply
import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="AI-DB-IDPS Gateway")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--train", action="store_true", help="Train model before starting")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")
    args = parser.parse_args()

    if args.train:
        print("[main] Training model...")
        from model.train import train, DEFAULT_NORMAL_QUERIES
        train(DEFAULT_NORMAL_QUERIES, epochs=100)
        print("[main] Training complete.\n")

    import uvicorn
    uvicorn.run(
        "api.gateway:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )

if __name__ == "__main__":
    main()
