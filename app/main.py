"""Interface web de CYBER AUDIT (FastAPI) protégée par mot de passe."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__, config, jobs, scanner
from .proc import which
from .scope import ScopeError, validate_target

app = FastAPI(title="CYBER AUDIT", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
STATIC = Path(__file__).parent / "static"

# ---------------------------------------------------------------- authentification
_secret_file = config.DATA / ".secret"
if not _secret_file.exists():
    _secret_file.write_text(secrets.token_hex(32))
SECRET = _secret_file.read_text().strip().encode()


def _password() -> str:
    pw = os.environ.get("AUDIT_PASSWORD", "").strip()
    if pw:
        return pw
    f = config.DATA / "mot_de_passe.txt"
    if not f.exists():
        f.write_text(secrets.token_urlsafe(12))
        print(f"\n  Mot de passe généré : {f.read_text().strip()}  (fichier {f})\n")
    return f.read_text().strip()


PASSWORD = _password()
_fails: dict[str, list[float]] = {}


def _sign(exp: int) -> str:
    return f"{exp}.{hmac.new(SECRET, str(exp).encode(), hashlib.sha256).hexdigest()}"


def _valid(cookie: str | None) -> bool:
    try:
        exp, sig = (cookie or "").split(".", 1)
        return int(exp) > time.time() and hmac.compare_digest(sig, _sign(int(exp)).split(".", 1)[1])
    except ValueError:
        return False


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path != "/api/login":
        if not _valid(request.cookies.get("audit_session")):
            return JSONResponse({"detail": "Connexion requise"}, status_code=401)
        if request.method not in ("GET", "HEAD") and request.headers.get("x-requested-with") != "cyber-audit":
            return JSONResponse({"detail": "Requête refusée"}, status_code=403)
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not path.endswith(".html") or path == "/":
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
    return resp


@app.post("/api/login")
async def login(request: Request, body: dict = Body(...)):
    ip = request.client.host if request.client else "?"
    recent = [t for t in _fails.get(ip, []) if time.time() - t < 300]
    if len(recent) >= 5:
        raise HTTPException(429, "Trop d'essais : réessaie dans 5 minutes.")
    if not hmac.compare_digest(str(body.get("password", "")), PASSWORD):
        _fails[ip] = recent + [time.time()]
        raise HTTPException(401, "Mot de passe incorrect.")
    resp = JSONResponse({"ok": True})
    resp.set_cookie("audit_session", _sign(int(time.time()) + 12 * 3600), httponly=True, samesite="strict", max_age=12 * 3600)
    return resp


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("audit_session")
    return resp


# ---------------------------------------------------------------- API
@app.get("/api/info")
async def info():
    return {
        "version": __version__,
        "profiles": {k: v["label"] for k, v in scanner.PROFILES.items()},
        "tools": {"nmap": bool(which("nmap")), "root": scanner.is_root()},
        "settings": {k: v for k, v in config.load().items() if k != "nvd_api_key"} | {"nvd_api_key_set": bool(config.load()["nvd_api_key"])},
    }


@app.put("/api/settings")
async def settings(values: dict = Body(...)):
    if "nvd_api_key" in values and not values["nvd_api_key"]:
        values.pop("nvd_api_key")
    config.save(values)
    return await info()


@app.get("/api/audits")
async def audits():
    return jobs.list_audits()


@app.post("/api/audits")
async def new_audit(body: dict = Body(...)):
    if body.get("autorisation") is not True:
        raise HTTPException(400, "Tu dois certifier être autorisé à auditer cette cible.")
    if jobs.busy():
        raise HTTPException(409, "Un audit est déjà en cours : attends qu'il se termine.")
    try:
        target = validate_target(str(body.get("cible", "")))
    except ScopeError as e:
        raise HTTPException(400, str(e))
    if not which("nmap"):
        raise HTTPException(400, "Nmap n'est pas installé sur cette machine.")
    profile = body.get("profil") if body.get("profil") in scanner.PROFILES else "rapide"
    a = jobs.start(target, str(body.get("nom", ""))[:80], profile)
    return {"id": a["id"]}


@app.get("/api/audits/{audit_id}")
async def audit(audit_id: str):
    a = jobs.get(audit_id)
    if not a:
        raise HTTPException(404, "Audit introuvable")
    return a


def _file(audit_id: str, name: str) -> Path:
    if not audit_id.isalnum():
        raise HTTPException(404)
    f = config.REPORTS / audit_id / name
    if not f.exists():
        raise HTTPException(404, "Rapport indisponible")
    return f


@app.get("/api/audits/{audit_id}/rapport.pdf")
async def pdf(audit_id: str):
    a = jobs.get(audit_id) or {}
    return FileResponse(_file(audit_id, "rapport.pdf"), media_type="application/pdf",
                        filename=f"audit-{a.get('target', audit_id).replace('/', '_')}-{audit_id[:6]}.pdf")


@app.get("/api/audits/{audit_id}/rapport.html")
async def html(audit_id: str):
    return FileResponse(_file(audit_id, "rapport.html"), media_type="text/html")


@app.delete("/api/audits/{audit_id}")
async def delete(audit_id: str):
    import shutil
    if audit_id.isalnum() and (config.REPORTS / audit_id).exists() and audit_id not in jobs._running:
        shutil.rmtree(config.REPORTS / audit_id)
    return {"ok": True}


@app.get("/")
async def index():
    return HTMLResponse((STATIC / "index.html").read_text(encoding="utf-8"))
