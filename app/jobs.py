"""Déroulement d'un audit en arrière-plan, avec progression et journal."""
from __future__ import annotations

import datetime as dt
import json
import threading
import time
import traceback
import uuid
from pathlib import Path

from . import ai, checks, report, scanner, scoring, vulns
from .config import REPORTS

STEPS = ["Découverte des machines", "Scan des services", "Contrôles web et TLS", "Veille vulnérabilités (CVE)",
         "Synthèse par l'IA", "Rapport PDF"]
MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]

_lock = threading.Lock()
_running: dict[str, dict] = {}


def _dir(audit_id: str) -> Path:
    return REPORTS / audit_id


def _save(a: dict) -> None:
    d = _dir(a["id"])
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "audit.json.tmp"
    tmp.write_text(json.dumps(a, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(d / "audit.json")


def get(audit_id: str) -> dict | None:
    if audit_id in _running:
        return _running[audit_id]
    f = _dir(audit_id) / "audit.json"
    if f.exists() and audit_id.isalnum():
        return json.loads(f.read_text(encoding="utf-8"))
    return None


def list_audits() -> list[dict]:
    out = []
    for f in sorted(REPORTS.glob("*/audit.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            a = _running.get(f.parent.name) or json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({k: a.get(k) for k in ("id", "name", "target", "status", "date_fr", "started", "progress", "error", "pdf")} |
                   {"grade": (a.get("grade") or {}).get("letter"), "score": (a.get("grade") or {}).get("score"),
                    "counts": (a.get("grade") or {}).get("counts")})
    return out


def busy() -> bool:
    return any(a["status"] == "en cours" for a in _running.values())


def start(target: str, name: str, profile: str) -> dict:
    now = dt.datetime.now()
    a = {
        "id": uuid.uuid4().hex[:12], "name": name or f"Audit {target}", "target": target, "profile": profile,
        "profile_label": scanner.PROFILES[profile]["label"], "status": "en cours", "progress": 0, "step": 0,
        "steps": STEPS, "log": [], "started": time.time(), "date_fr": f"{now.day} {MOIS[now.month - 1]} {now.year} à {now:%H:%M}",
        "hosts": [], "findings": [], "grade": None, "summary": None, "intel": {}, "pdf": False, "error": None,
    }
    with _lock:
        _running[a["id"]] = a
    _save(a)
    threading.Thread(target=_run, args=(a,), daemon=True).start()
    return a


def _log(a: dict, msg: str) -> None:
    a["log"].append({"t": time.strftime("%H:%M:%S"), "msg": msg})
    a["log"] = a["log"][-200:]


def _step(a: dict, i: int, pct: int) -> None:
    a["step"], a["progress"] = i, pct
    _save(a)


def _run(a: dict) -> None:
    try:
        _step(a, 0, 3)
        _log(a, f"Découverte des machines actives sur {a['target']}…")
        hosts_ip = scanner.discover(a["target"])
        if "/" not in a["target"] and not hosts_ip:
            hosts_ip = [a["target"]]  # hôte qui ne répond pas au ping : on le scanne quand même
        _log(a, f"{len(hosts_ip)} machine(s) active(s) : {', '.join(hosts_ip[:20])}{'…' if len(hosts_ip) > 20 else ''}")
        if not hosts_ip:
            raise scanner.ScanError("Aucune machine active trouvée sur cette cible.")

        _step(a, 1, 8)
        hosts = []
        for i, ip in enumerate(hosts_ip):
            _log(a, f"Scan des services de {ip} ({i + 1}/{len(hosts_ip)})…")
            h = scanner.scan_host(ip, a["profile"])
            _log(a, f"{ip} : {len(h['ports'])} port(s) ouvert(s) " + (", ".join(str(p['port']) for p in h["ports"][:15]) or ""))
            hosts.append(h)
            a["hosts"] = hosts
            a["progress"] = 8 + int(52 * (i + 1) / len(hosts_ip))
            _save(a)

        _step(a, 2, 62)
        findings = []
        for h in hosts:
            _log(a, f"Contrôles des services, du web et du TLS sur {h['ip']}…")
            for check in (checks.service_findings, checks.http_findings, checks.tls_findings):
                try:
                    findings += check(h)
                except Exception as e:  # noqa: BLE001  un contrôle en échec ne doit pas bloquer l'audit
                    _log(a, f"⚠ Contrôle {check.__name__} ignoré sur {h['ip']} : {e}")

        _step(a, 3, 72)
        intel = vulns.Intel()
        _log(a, "Téléchargement du catalogue CISA des failles activement exploitées…")
        intel.load_kev()
        findings += vulns.vuln_findings(hosts, intel, lambda m: _log(a, m))
        a["intel"] = intel.sources
        if intel.sources.get("nvd") is False:
            _log(a, "⚠ Base NVD injoignable : les CVE n'ont pas pu être vérifiées (accès Internet nécessaire).")

        findings = scoring.sort_findings(findings)
        a["findings"] = findings
        a["grade"] = scoring.grade(findings)
        _step(a, 4, 86)
        _log(a, "Rédaction de la synthèse par l'IA locale…")
        a["summary"] = ai.summarize(a["target"], a["grade"], hosts, findings)
        _log(a, a["summary"]["source"])

        _step(a, 5, 94)
        secs = int(time.time() - a["started"])
        a["duration"] = f"{secs // 60} min {secs % 60:02d} s"
        d = _dir(a["id"])
        (d / "rapport.html").write_text(report.render_html(a), encoding="utf-8")
        engine = report.to_pdf(d / "rapport.html", d / "rapport.pdf")
        a["pdf"] = bool(engine)
        _log(a, f"Rapport PDF généré ({engine})." if engine else "PDF impossible (aucun moteur) : le rapport HTML est disponible.")
        a["status"], a["progress"] = "terminé", 100
        _log(a, f"Audit terminé : note {a['grade']['letter']} ({a['grade']['score']}/100).")
    except Exception as e:  # noqa: BLE001
        a["status"], a["error"] = "erreur", str(e)
        _log(a, f"Erreur : {e}")
        (_dir(a["id"]) / "erreur.txt").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        _save(a)
        with _lock:
            _running.pop(a["id"], None)
