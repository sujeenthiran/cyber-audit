"""Tests : périmètre, analyse Nmap, contrôles, veille CVE (données simulées), note, rapport."""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("AUDIT_DATA", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from app import checks, report, scoring, vulns  # noqa: E402
from app.scanner import parse_nmap_xml  # noqa: E402
from app.scope import ScopeError, validate_target  # noqa: E402

XML = (ROOT / "tests/fixtures/scan_lab.xml").read_text()


def test_scope():
    assert validate_target("10.10.0.105") and validate_target("192.168.1.0/24")
    for bad in ["8.8.8.8", "1.1.1.0/24", "10.0.0.0/8", "-oN /tmp/x", "10.10.0.1;id", ""]:
        with pytest.raises(ScopeError):
            validate_target(bad)


def test_parse():
    h = parse_nmap_xml(XML)[0]
    assert h["ip"] == "127.0.0.1" and h["hostname"] == "lab-web.sujee.lab"
    assert [p["port"] for p in h["ports"]] == [21, 22, 6379, 8099]
    assert h["ports"][1]["cpe"][0] == "cpe:/a:openbsd:openssh:8.4p1"
    assert "smb2-security-mode" in h["host_scripts"]


def test_service_findings():
    h = parse_nmap_xml(XML)[0]
    titles = {f["title"] for f in checks.service_findings(h)}
    for t in ["FTP non chiffré", "Connexion FTP anonyme autorisée", "Algorithmes SSH faibles acceptés", "Redis accessible",
              "Signature SMB non obligatoire", "Vulnérabilité détectée par le script http-vuln-cve2021-41773"]:
        assert t in titles, t


def test_cpe():
    assert vulns.to_cpe23("cpe:/a:openbsd:openssh:8.4p1") == "cpe:2.3:a:openbsd:openssh:8.4p1:*:*:*:*:*:*:*"
    assert vulns.to_cpe23("cpe:/a:apache:http_server", "2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert vulns.to_cpe23("cpe:/o:linux:linux_kernel") is None


def fake_nvd(cpe23):
    if "http_server:2.4.49" in cpe23:
        return [{"id": "CVE-2021-41773", "published": "2021-10-05", "cvss": 7.5, "cvss_severity": "HIGH", "vector": "", "description": "Path traversal"},
                {"id": "CVE-2021-42013", "published": "2021-10-07", "cvss": 9.8, "cvss_severity": "CRITICAL", "vector": "", "description": "RCE"}]
    if "openssh:8.4p1" in cpe23:
        return [{"id": "CVE-2024-6387", "published": "2024-07-01", "cvss": 8.1, "cvss_severity": "HIGH", "vector": "", "description": "regreSSHion"},
                {"id": "CVE-2026-0001", "published": "2026-06-01", "cvss": 5.0, "cvss_severity": "MEDIUM", "vector": "", "description": "Récente"}]
    return []


def test_vulns(monkeypatch):
    monkeypatch.setattr(vulns, "nvd_for_cpe", fake_nvd)
    monkeypatch.setattr(vulns, "epss_for", lambda ids: {i: {"epss": 0.9, "percentile": 0.99} for i in ids})
    h = parse_nmap_xml(XML)[0]
    intel = vulns.Intel()
    intel.kev = {"CVE-2021-41773": {"requiredAction": "Apply updates", "knownRansomwareCampaignUse": "Known"}}
    fs = vulns.vuln_findings([h], intel)
    apache = next(f for f in fs if "Apache" in f["title"])
    assert apache["severity"] == "critique" and apache["cve_details"][0]["kev"]
    ssh = next(f for f in fs if "OpenSSH" in f["title"])
    assert ssh["confidence"] == "à confirmer"  # Debian : backport possible
    assert any(c["recent"] for c in ssh["cve_details"])
    assert intel.sources["nvd"] and intel.sources["epss"]


def test_grade_and_report(tmp_path, monkeypatch):
    monkeypatch.setattr(vulns, "nvd_for_cpe", fake_nvd)
    monkeypatch.setattr(vulns, "epss_for", lambda ids: {})
    h = parse_nmap_xml(XML)[0]
    h["command"] = "nmap -sV 127.0.0.1"
    intel = vulns.Intel()
    fs = scoring.sort_findings(checks.service_findings(h) + vulns.vuln_findings([h], intel))
    g = scoring.grade(fs)
    assert g["letter"] in ("D", "E", "F") and g["score"] <= 39
    from app import ai
    a = {"id": "test123", "name": "Lab de test", "target": "127.0.0.1", "profile_label": "Rapide", "date_fr": "16 novembre 2026 à 15:00",
         "duration": "1 min 02 s", "hosts": [h], "findings": fs, "grade": g, "summary": ai.fallback(g, [h], fs), "intel": intel.sources}
    html = report.render_html(a)
    assert "CVE-2021-42013" in html and "Plan d'action" in html
    (tmp_path / "r.html").write_text(html, encoding="utf-8")
    if os.environ.get("CHROME_PATH"):
        assert report.to_pdf(tmp_path / "r.html", tmp_path / "r.pdf") == "chromium"
        assert (tmp_path / "r.pdf").read_bytes()[:4] == b"%PDF"
