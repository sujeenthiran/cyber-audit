"""Lance CYBER AUDIT : python run.py  ->  http://127.0.0.1:8090"""
import argparse
import os

import uvicorn

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CYBER AUDIT")
    ap.add_argument("--host", default=os.environ.get("AUDIT_HOST", "127.0.0.1"), help="0.0.0.0 pour y accéder depuis le réseau")
    ap.add_argument("--port", type=int, default=int(os.environ.get("AUDIT_PORT", "8090")))
    a = ap.parse_args()
    print(f"\n  CYBER AUDIT : http://{'127.0.0.1' if a.host in ('0.0.0.0', '::') else a.host}:{a.port}\n")
    from app import main  # noqa: F401  (affiche le mot de passe généré au premier lancement)
    uvicorn.run("app.main:app", host=a.host, port=a.port, log_level="warning")
