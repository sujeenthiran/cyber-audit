"""Veille vulnérabilités : NVD (CVE + CVSS), catalogue CISA KEV (failles exploitées), EPSS (probabilité d'exploitation)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from pathlib import Path

import httpx

from . import config
from .checks import finding

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE = config.CACHE
TTL = 24 * 3600
_last_nvd_call = 0.0


class Intel:
    """Garde l'état de la veille pour un audit (sources disponibles ou non)."""

    def __init__(self):
        self.sources = {"nvd": None, "kev": None, "epss": None}
        self.kev: dict[str, dict] = {}
        self.kev_date = ""

    def load_kev(self) -> None:
        data = _cached_get("kev.json", KEV_URL, {})
        if data:
            self.kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            self.kev_date = data.get("dateReleased", "")[:10]
            self.sources["kev"] = f"CISA KEV ({len(self.kev)} failles exploitées, mise à jour {self.kev_date})"
        else:
            self.sources["kev"] = False


def _cache_file(name: str) -> Path:
    return CACHE / name


def _cached_get(name: str, url: str, params: dict, headers: dict | None = None, ttl: int = TTL):
    f = _cache_file(name)
    if f.exists() and time.time() - f.stat().st_mtime < ttl:
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    try:
        r = httpx.get(url, params=params, headers=headers or {}, timeout=40, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        f.write_text(json.dumps(data), encoding="utf-8")
        return data
    except Exception:  # noqa: BLE001  réseau indisponible : on garde l'ancien cache s'il existe
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return None
        return None


def to_cpe23(cpe: str, version: str = "") -> str | None:
    """cpe:/a:openbsd:openssh:8.4p1 -> cpe:2.3:a:openbsd:openssh:8.4p1:*:*:*:*:*:*:*"""
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) < 3 or parts[0] not in ("a", "o", "h"):
        return None
    part, vendor, product = parts[0], parts[1], parts[2]
    ver = parts[3] if len(parts) > 3 and parts[3] else (version.split()[0] if version and part == "a" else "")
    if not ver:
        return None
    ver = ver.replace(" ", "_")
    return f"cpe:2.3:{part}:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def _metrics(cve: dict) -> tuple[float | None, str, str]:
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            entry = sorted(m[key], key=lambda x: x.get("type") != "Primary")[0]
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or entry.get("baseSeverity", "")
            return score, sev, data.get("vectorString", "")
    return None, "", ""


def nvd_for_cpe(cpe23: str) -> list[dict] | None:
    global _last_nvd_call
    name = "nvd-" + hashlib.sha1(cpe23.encode()).hexdigest()[:16] + ".json"
    key = config.load().get("nvd_api_key", "")
    f = _cache_file(name)
    if not (f.exists() and time.time() - f.stat().st_mtime < TTL):
        # Limite publique NVD : 5 requêtes / 30 s sans clé, 50 avec clé
        wait = (0.7 if key else 6.5) - (time.time() - _last_nvd_call)
        if wait > 0:
            time.sleep(wait)
        _last_nvd_call = time.time()
    data = _cached_get(name, NVD_URL, {"virtualMatchString": cpe23, "noRejected": "", "resultsPerPage": 500},
                       {"apiKey": key} if key else None)
    if data is None:
        return None
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        score, sev, vector = _metrics(c)
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "fr"), None) or \
            next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        out.append({"id": c.get("id"), "published": (c.get("published") or "")[:10], "cvss": score,
                    "cvss_severity": sev, "vector": vector, "description": desc[:600]})
    return out


def epss_for(cves: list[str]) -> dict[str, dict]:
    res: dict[str, dict] = {}
    for i in range(0, len(cves), 100):
        chunk = sorted(cves[i:i + 100])
        name = "epss-" + hashlib.sha1(",".join(chunk).encode()).hexdigest()[:16] + ".json"
        data = _cached_get(name, EPSS_URL, {"cve": ",".join(chunk)})
        if not data:
            return res
        for d in data.get("data", []):
            res[d["cve"]] = {"epss": float(d.get("epss", 0)), "percentile": float(d.get("percentile", 0))}
    return res


def cvss_to_sev(score: float | None) -> str:
    if score is None:
        return "moyenne"
    return "critique" if score >= 9 else "élevée" if score >= 7 else "moyenne" if score >= 4 else "faible"


def vuln_findings(hosts: list[dict], intel: Intel, log=lambda msg: None) -> list[dict]:
    """Croise chaque service versionné avec la NVD, puis enrichit avec KEV et EPSS."""
    out = []
    seen: dict[str, list[dict] | None] = {}
    targets = []
    for h in hosts:
        for p in h["ports"]:
            for cpe in p["cpe"]:
                c23 = to_cpe23(cpe, p["version"])
                if c23:
                    targets.append((h, p, c23))
    nvd_ok = None
    for h, p, c23 in targets:
        if c23 not in seen:
            log(f"Recherche des CVE pour {p['product'] or p['service']} {p['version']}…")
            seen[c23] = nvd_for_cpe(c23)
            nvd_ok = (nvd_ok or False) or seen[c23] is not None
        cves = seen[c23]
        if not cves:
            continue
        p.setdefault("cves", []).extend(cves)
    intel.sources["nvd"] = ("NVD (NIST) – base CVE officielle" if nvd_ok else False) if targets else "aucun service versionné à vérifier"
    all_ids = sorted({c["id"] for h in hosts for p in h["ports"] for c in p.get("cves", [])})
    epss = epss_for(all_ids) if all_ids else {}
    intel.sources["epss"] = "FIRST EPSS (probabilité d'exploitation à 30 jours)" if epss else (False if all_ids else None)
    one_year = (dt.date.today() - dt.timedelta(days=365)).isoformat()
    for h in hosts:
        for p in h["ports"]:
            cves = {c["id"]: c for c in p.get("cves", [])}.values()
            if not cves:
                continue
            enriched = []
            for c in cves:
                e = dict(c)
                e["kev"] = c["id"] in intel.kev
                e["kev_info"] = intel.kev.get(c["id"], {}).get("requiredAction", "")
                e["ransomware"] = intel.kev.get(c["id"], {}).get("knownRansomwareCampaignUse") == "Known"
                e["epss"] = epss.get(c["id"], {}).get("epss")
                e["recent"] = c["published"] >= one_year
                enriched.append(e)
            enriched.sort(key=lambda e: (e["kev"], e["cvss"] or 0, e["epss"] or 0), reverse=True)
            p["cves"] = enriched
            top = enriched[0]
            kev_n = sum(e["kev"] for e in enriched)
            crit_n = sum((e["cvss"] or 0) >= 9 for e in enriched)
            recent_n = sum(e["recent"] for e in enriched)
            sev = "critique" if kev_n else cvss_to_sev(top["cvss"])
            backport = any(x in (p["version"] + " " + p["extrainfo"]).lower() for x in ("debian", "ubuntu", "red hat", "rhel", "centos", "alma", "rocky"))
            label = f"{p['product'] or p['service']} {p['version']}".strip()
            desc = (f"{label} est concerné par {len(enriched)} vulnérabilité(s) publiée(s) : {crit_n} critique(s), "
                    f"{kev_n} activement exploitée(s) (CISA KEV), {recent_n} publiée(s) ces 12 derniers mois.")
            if backport:
                desc += (" Attention : ce paquet vient d'une distribution Linux qui corrige souvent les failles sans changer "
                         "le numéro de version (backport). Vérifie avec le gestionnaire de paquets avant de conclure.")
            out.append(finding(
                h["ip"], p["port"], f"Vulnérabilités connues : {label}", sev, "Vulnérabilité (CVE)", desc,
                f"Mettre à jour {p['product'] or p['service']} vers la dernière version stable de l'éditeur, puis relancer l'audit."
                + (" Priorité absolue : au moins une faille est exploitée par des attaquants en ce moment." if kev_n else ""),
                evidence=", ".join(e["id"] for e in enriched[:8]),
                references=[f"https://nvd.nist.gov/vuln/detail/{e['id']}" for e in enriched[:5]],
                cves=[e["id"] for e in enriched], cve_details=enriched[:12], confidence="à confirmer" if backport else "probable",
            ))
    return out
