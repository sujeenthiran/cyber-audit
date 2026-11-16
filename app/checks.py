"""Contrôles de sécurité non intrusifs à partir de l'inventaire Nmap + vérifications HTTP/TLS en lecture seule."""
from __future__ import annotations

import datetime as dt
import re
import socket
import ssl
import uuid

import httpx

SEV_ORDER = {"critique": 4, "élevée": 3, "moyenne": 2, "faible": 1, "info": 0}


def finding(host: str, port: int | None, title: str, severity: str, category: str, description: str,
            remediation: str, evidence: str = "", references: list[str] | None = None, **extra) -> dict:
    return {"id": uuid.uuid4().hex[:8], "host": host, "port": port, "title": title, "severity": severity,
            "category": category, "description": description, "remediation": remediation,
            "evidence": evidence.strip()[:1500], "references": references or [], **extra}


# Services sensibles exposés : (ports, noms) -> (titre, gravité, description, remédiation)
RISKY_SERVICES = [
    ({23}, {"telnet"}, "Telnet exposé", "élevée",
     "Telnet transmet identifiants et commandes en clair sur le réseau.",
     "Désactiver Telnet et utiliser SSH à la place."),
    ({21}, {"ftp"}, "FTP non chiffré", "moyenne",
     "FTP transmet les mots de passe en clair.", "Remplacer par SFTP/FTPS ou restreindre au réseau d'administration."),
    ({445, 139}, {"microsoft-ds", "netbios-ssn"}, "Partage Windows (SMB) exposé", "moyenne",
     "SMB est une cible privilégiée des rançongiciels et vers (EternalBlue, etc.).",
     "Limiter SMB aux postes qui en ont besoin via le pare-feu, désactiver SMBv1, exiger la signature SMB."),
    ({3389}, {"ms-wbt-server"}, "Bureau à distance (RDP) exposé", "moyenne",
     "RDP est très ciblé par le brute-force et des failles critiques (BlueKeep).",
     "Restreindre RDP à un VPN ou à des IP d'administration, activer NLA et le verrouillage de compte."),
    ({5900, 5901}, {"vnc"}, "VNC exposé", "élevée",
     "VNC est souvent peu protégé (mot de passe faible, pas de chiffrement).", "Passer par un tunnel SSH/VPN et imposer un mot de passe fort."),
    ({3306}, {"mysql"}, "Base de données MySQL/MariaDB accessible", "moyenne",
     "Une base de données accessible depuis le réseau augmente la surface d'attaque.", "Lier la base à 127.0.0.1 ou la restreindre au serveur applicatif."),
    ({5432}, {"postgresql"}, "Base PostgreSQL accessible", "moyenne",
     "Une base de données accessible depuis le réseau augmente la surface d'attaque.", "Restreindre listen_addresses et pg_hba.conf."),
    ({6379}, {"redis"}, "Redis accessible", "élevée",
     "Redis sans authentification permet souvent de prendre le contrôle du serveur.", "Lier Redis à 127.0.0.1, activer requirepass / ACL."),
    ({27017}, {"mongodb", "mongod"}, "MongoDB accessible", "élevée",
     "MongoDB exposé est une cause fréquente de fuites de données.", "Activer l'authentification et lier à 127.0.0.1."),
    ({9200}, {"elasticsearch"}, "Elasticsearch accessible", "élevée",
     "Elasticsearch exposé permet souvent de lire toutes les données indexées.", "Activer la sécurité (xpack) et restreindre l'accès."),
    ({2375}, {"docker"}, "API Docker exposée sans TLS", "critique",
     "L'API Docker non protégée donne un accès root complet à la machine.", "Désactiver l'écoute TCP ou imposer TLS mutuel (port 2376)."),
    ({161}, {"snmp"}, "SNMP exposé", "moyenne",
     "SNMP v1/v2c utilise des communautés en clair, souvent « public ».", "Passer en SNMPv3 ou désactiver SNMP."),
    ({11434}, set(), "API Ollama exposée sur le réseau", "moyenne",
     "N'importe qui sur le réseau peut utiliser ou supprimer les modèles d'IA.", "Lier Ollama à 127.0.0.1 ou filtrer le port 11434."),
]

WEAK_SSH = re.compile(r"(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|ssh-dss|arcfour\w*|\w+-cbc|hmac-md5\w*|hmac-sha1-96)")
VULN_STATE = re.compile(r"State:\s*(LIKELY\s+)?VULNERABLE", re.I)
HTTP_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http", "ssl/https"}
SEC_HEADERS = {
    "strict-transport-security": ("HSTS absent", "Ajouter « Strict-Transport-Security: max-age=31536000; includeSubDomains »."),
    "content-security-policy": ("Politique CSP absente", "Définir une Content-Security-Policy adaptée pour limiter les XSS."),
    "x-content-type-options": ("En-tête X-Content-Type-Options absent", "Ajouter « X-Content-Type-Options: nosniff »."),
    "x-frame-options": ("Protection anti-clickjacking absente", "Ajouter « X-Frame-Options: DENY » ou « frame-ancestors » dans la CSP."),
}
SENSITIVE_PATHS = [
    ("/.git/HEAD", lambda r: r.status_code == 200 and r.text.startswith("ref:"), "Dépôt Git exposé", "élevée",
     "Le dossier .git est téléchargeable : code source, historique et parfois mots de passe récupérables.",
     "Bloquer l'accès aux dossiers cachés (.git) dans la configuration du serveur web."),
    ("/.env", lambda r: r.status_code == 200 and re.search(r"^[A-Z_]{3,}=", r.text, re.M) is not None, "Fichier .env exposé", "critique",
     "Le fichier de configuration .env (souvent clés et mots de passe) est lisible publiquement.",
     "Retirer le fichier du dossier web, changer immédiatement les secrets qu'il contient."),
    ("/server-status", lambda r: r.status_code == 200 and "Apache Server Status" in r.text, "Page server-status Apache exposée", "moyenne",
     "Révèle les requêtes en cours, IP des clients et URL internes.", "Restreindre mod_status à localhost."),
    ("/phpinfo.php", lambda r: r.status_code == 200 and "phpinfo()" in r.text, "phpinfo() exposé", "moyenne",
     "Révèle la configuration complète de PHP et du serveur.", "Supprimer le fichier phpinfo.php."),
]


def service_findings(host: dict) -> list[dict]:
    out = []
    ip = host["ip"]
    for p in host["ports"]:
        name = p["service"]
        for ports, names, title, sev, desc, fix in RISKY_SERVICES:
            if p["port"] in ports or name in names:
                out.append(finding(ip, p["port"], title, sev, "Exposition", desc, fix, f"{p['port']}/{p['proto']} {name} {p['product']} {p['version']}"))
                break
        sc = p["scripts"]
        if "ftp-anon" in sc and "Anonymous FTP login allowed" in sc["ftp-anon"]:
            out.append(finding(ip, p["port"], "Connexion FTP anonyme autorisée", "élevée", "Authentification",
                               "N'importe qui peut se connecter au FTP sans mot de passe.", "Désactiver l'accès anonyme.", sc["ftp-anon"]))
        if "ssh2-enum-algos" in sc:
            weak = sorted(set(WEAK_SSH.findall(sc["ssh2-enum-algos"])))
            if weak:
                out.append(finding(ip, p["port"], "Algorithmes SSH faibles acceptés", "faible", "Chiffrement",
                                   "Le serveur SSH accepte des algorithmes obsolètes.",
                                   "Retirer ces algorithmes de sshd_config (KexAlgorithms, Ciphers, MACs).", ", ".join(weak)))
        for sid, text in sc.items():
            if VULN_STATE.search(text):
                cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))
                out.append(finding(ip, p["port"], f"Vulnérabilité détectée par le script {sid}", "élevée", "Vulnérabilité",
                                   "Un script de détection Nmap a confirmé une vulnérabilité sur ce service.",
                                   "Appliquer le correctif de l'éditeur ou mettre à jour le service.", text, cves=cves))
    for sid, text in host.get("host_scripts", {}).items():
        if sid in ("smb2-security-mode", "smb-security-mode") and re.search(r"not required|disabled", text, re.I):
            out.append(finding(ip, 445, "Signature SMB non obligatoire", "moyenne", "Configuration",
                               "Sans signature SMB, un attaquant sur le réseau peut relayer des authentifications (NTLM relay).",
                               "Activer « Microsoft network server: Digitally sign communications (always) ».", text))
        if VULN_STATE.search(text):
            out.append(finding(ip, None, f"Vulnérabilité détectée par le script {sid}", "élevée", "Vulnérabilité",
                               "Un script de détection Nmap a confirmé une vulnérabilité sur cet hôte.",
                               "Appliquer les correctifs de sécurité du système.", text,
                               cves=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text)))))
    return out


def _is_http(p: dict) -> bool:
    return p["service"] in HTTP_NAMES or p["service"].startswith("http") or p["port"] in (80, 443, 8080, 8443, 8000, 8081, 3000, 3001)


def _is_tls(p: dict) -> bool:
    return p["tunnel"] == "ssl" or p["service"] in ("https", "ssl/http", "https-alt") or p["port"] in (443, 8443, 993, 995, 465, 636)


def http_findings(host: dict, timeout: float = 6.0) -> list[dict]:
    out = []
    ip = host["ip"]
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers={"User-Agent": "CyberAudit/1.0 (authorized security audit)"}) as c:
        for p in host["ports"]:
            if not _is_http(p):
                continue
            scheme = "https" if _is_tls(p) else "http"
            base = f"{scheme}://{ip}:{p['port']}"
            try:
                r = c.get(base + "/")
            except httpx.HTTPError:
                if scheme == "http":
                    try:
                        scheme, base = "https", f"https://{ip}:{p['port']}"
                        r = c.get(base + "/")
                    except httpx.HTTPError:
                        continue
                else:
                    continue
            h = {k.lower(): v for k, v in r.headers.items()}
            p["http"] = {"status": r.status_code, "server": h.get("server", ""), "title": _title(r.text)}
            if scheme == "http" and not (300 <= r.status_code < 400 and h.get("location", "").startswith("https")):
                out.append(finding(ip, p["port"], "Site web sans HTTPS", "moyenne", "Chiffrement",
                                   "Les échanges (dont identifiants) circulent en clair sur le réseau.",
                                   "Activer HTTPS (certificat local ou Let's Encrypt) et rediriger HTTP vers HTTPS.", f"{base}/ → {r.status_code}"))
            missing = [k for k in SEC_HEADERS if k not in h and (k != "strict-transport-security" or scheme == "https")]
            if missing and r.status_code < 400:
                out.append(finding(ip, p["port"], "En-têtes de sécurité HTTP manquants", "faible", "Configuration web",
                                   "Le site ne définit pas certains en-têtes qui protègent les navigateurs (XSS, clickjacking, rétrogradation HTTPS).",
                                   " ".join(SEC_HEADERS[k][1] for k in missing), "Manquants : " + ", ".join(missing)))
            banner = " ".join(x for x in (h.get("server", ""), h.get("x-powered-by", "")) if x)
            if re.search(r"\d+\.\d+", banner):
                out.append(finding(ip, p["port"], "Version du serveur web divulguée", "faible", "Divulgation d'information",
                                   "Le serveur annonce sa version exacte, ce qui aide un attaquant à cibler les failles connues.",
                                   "Masquer la version (ServerTokens Prod / server_tokens off / expose_php Off).", banner))
            if "<title>Index of /" in r.text:
                out.append(finding(ip, p["port"], "Listage de répertoire activé", "moyenne", "Configuration web",
                                   "Le contenu des dossiers est visible par tous.", "Désactiver « Options Indexes » / « autoindex ».", base + "/"))
            for path, test, title, sev, desc, fix in SENSITIVE_PATHS:
                try:
                    rr = c.get(base + path)
                except httpx.HTTPError:
                    continue
                if test(rr):
                    out.append(finding(ip, p["port"], title, sev, "Exposition de données", desc, fix, base + path))
    return out


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""


def _tls_version_accepted(ip: str, port: int, version) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((ip, port), timeout=5) as s, ctx.wrap_socket(s) as t:
            return t.version() is not None
    except (OSError, ssl.SSLError, ValueError):
        return False


def tls_findings(host: dict) -> list[dict]:
    out = []
    ip = host["ip"]
    for p in host["ports"]:
        if not _is_tls(p) and not (p.get("http") and p.get("http", {}).get("status") and p["port"] == 443):
            continue
        cert_text = p["scripts"].get("ssl-cert", "")
        m = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})", cert_text)
        if m:
            exp = dt.date.fromisoformat(m.group(1))
            days = (exp - dt.date.today()).days
            if days < 0:
                out.append(finding(ip, p["port"], "Certificat TLS expiré", "moyenne", "Chiffrement",
                                   f"Le certificat a expiré il y a {-days} jours : les navigateurs affichent une alerte et les utilisateurs prennent l'habitude de l'ignorer.",
                                   "Renouveler le certificat (automatiser avec Let's Encrypt / ACME).", cert_text))
            elif days < 30:
                out.append(finding(ip, p["port"], "Certificat TLS bientôt expiré", "faible", "Chiffrement",
                                   f"Le certificat expire dans {days} jours.", "Renouveler le certificat.", cert_text))
        subj = re.search(r"Subject:\s*(.+)", cert_text)
        issuer = re.search(r"Issuer:\s*(.+)", cert_text)
        if subj and issuer and subj.group(1).strip() == issuer.group(1).strip():
            out.append(finding(ip, p["port"], "Certificat auto-signé", "info", "Chiffrement",
                               "Normal dans un lab, mais les utilisateurs ne peuvent pas vérifier l'identité du serveur.",
                               "Utiliser une autorité de certification interne ou Let's Encrypt.", cert_text))
        old = [name for name, v in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)) if _tls_version_accepted(ip, p["port"], v)]
        if old:
            out.append(finding(ip, p["port"], "Protocoles TLS obsolètes acceptés", "moyenne", "Chiffrement",
                               "TLS 1.0/1.1 sont dépréciés (RFC 8996) et vulnérables à plusieurs attaques.",
                               "N'autoriser que TLS 1.2 et 1.3 dans la configuration du service.", ", ".join(old)))
    return out
