"""Réglages (data/reglages.json) et chemins."""
from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = Path(os.environ.get("AUDIT_DATA", ROOT / "data"))
REPORTS = DATA / "rapports"
CACHE = DATA / "cache"
for d in (DATA, REPORTS, CACHE):
    d.mkdir(parents=True, exist_ok=True)

DEFAULTS = {
    # Réseaux que l'outil a le droit d'auditer. Les réseaux privés du lab sont autorisés par défaut ;
    # une IP publique doit être ajoutée ici à la main ET tu dois avoir l'autorisation écrite de son propriétaire.
    "cibles_autorisees": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
    "ollama_url": "http://127.0.0.1:11434",
    "modele_ia": "qwen3:8b",
    "nvd_api_key": "",            # facultatif : accélère les recherches CVE (clé gratuite sur nvd.nist.gov)
    "auditeur": "",
    "organisation": "",
}

_path = DATA / "reglages.json"


def load() -> dict:
    cfg = dict(DEFAULTS)
    if _path.exists():
        try:
            cfg.update({k: v for k, v in json.loads(_path.read_text(encoding="utf-8")).items() if k in DEFAULTS})
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


def save(values: dict) -> dict:
    cfg = load()
    for k, v in values.items():
        if k in DEFAULTS:
            cfg[k] = [str(x).strip() for x in v if str(x).strip()] if isinstance(DEFAULTS[k], list) else str(v).strip()
    _path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    return cfg


if not _path.exists():
    save({})
