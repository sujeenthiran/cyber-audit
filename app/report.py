"""Génération du rapport HTML puis PDF (Chromium headless, sinon WeasyPrint)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__, config

env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape(["html", "j2"]))
GRADE_COLORS = {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "E": "#ef4444", "F": "#dc2626"}


def render_html(audit: dict) -> str:
    by_host: dict[str, list] = {}
    for f in audit["findings"]:
        by_host.setdefault(f["host"], []).append(f)
    return env.get_template("report.html.j2").render(
        a=audit, g=audit["grade"], s=audit["summary"], hosts=audit["hosts"], findings=audit["findings"],
        intel=audit["intel"], by_host=by_host, total=max(1, len(audit["findings"])),
        n_ports=sum(len(h["ports"]) for h in audit["hosts"]), cfg=config.load(), version=__version__,
        grade_color=GRADE_COLORS.get(audit["grade"]["letter"], "#00b8d9"),
    )


def _browser() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "msedge", "chrome"):
        p = shutil.which(name)
        if p:
            return p
    for p in (os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
              os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
              os.environ.get("CHROME_PATH", "")):
        if p and os.path.exists(p):
            return p
    return None


def to_pdf(html_path: Path, pdf_path: Path) -> str | None:
    """Retourne le moteur utilisé, ou None si aucun n'est disponible (le rapport HTML reste disponible)."""
    browser = _browser()
    if browser:
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
               "--run-all-compositor-stages-before-draw", f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()]
        try:
            subprocess.run(cmd, capture_output=True, timeout=120)
            if pdf_path.exists() and pdf_path.stat().st_size > 1000:
                return "chromium"
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return "weasyprint"
    except Exception:  # noqa: BLE001
        return None
