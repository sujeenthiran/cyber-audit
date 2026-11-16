"""Génère docs/exemple-rapport.pdf à partir des données de test (CVE simulées) : python tests/make_demo.py"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AUDIT_DATA", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from app import ai, checks, report, scoring, vulns  # noqa: E402
from app.scanner import parse_nmap_xml  # noqa: E402
from test_audit import fake_nvd  # noqa: E402

vulns.nvd_for_cpe = fake_nvd
vulns.epss_for = lambda ids: {"CVE-2021-41773": {"epss": 0.944}, "CVE-2021-42013": {"epss": 0.943}, "CVE-2024-6387": {"epss": 0.38}}
h = parse_nmap_xml((ROOT / "tests/fixtures/scan_lab.xml").read_text())[0]
h["ip"] = "10.10.0.50"
h["command"] = "nmap -sV --top-ports 1000 -T4 --script \"(default or vuln or discovery) and safe\" -Pn 10.10.0.50"
intel = vulns.Intel()
intel.kev = {"CVE-2021-41773": {"requiredAction": "Apply updates", "knownRansomwareCampaignUse": "Known"},
             "CVE-2021-42013": {"requiredAction": "Apply updates", "knownRansomwareCampaignUse": "Unknown"}}
intel.sources["kev"] = "CISA KEV (exemple)"
fs = []
for f in checks.service_findings(h):
    f["host"] = "10.10.0.50"
    fs.append(f)
fs += vulns.vuln_findings([h], intel)
fs.append(checks.finding("10.10.0.50", 8099, "Dépôt Git exposé", "élevée", "Exposition de données",
                         checks.SENSITIVE_PATHS[0][4], checks.SENSITIVE_PATHS[0][5], "http://10.10.0.50:8099/.git/HEAD"))
fs = scoring.sort_findings(fs)
g = scoring.grade(fs)
a = {"id": "exemple", "name": "Exemple – serveur de test", "target": "10.10.0.50", "profile_label": "Rapide",
     "date_fr": "16 novembre 2026 à 15:00", "duration": "2 min 14 s", "hosts": [h], "findings": fs, "grade": g,
     "summary": ai.fallback(g, [h], fs), "intel": intel.sources}
out = ROOT / "docs"
(out / "exemple-rapport.html").write_text(report.render_html(a), encoding="utf-8")
print(report.to_pdf(out / "exemple-rapport.html", out / "exemple-rapport.pdf"))
