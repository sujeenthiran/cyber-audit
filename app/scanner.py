"""Découverte réseau et inventaire des services avec Nmap (profils non intrusifs)."""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET

from .proc import run, which

# Scripts NSE : uniquement la catégorie "safe" (aucune exploitation, aucun brute-force, aucun déni de service).
SAFE_SCRIPTS = "(default or vuln or discovery) and safe and not broadcast and not external"

PROFILES = {
    "rapide": {"label": "Rapide (1 000 ports courants, ~2 min/hôte)", "args": ["-sV", "--top-ports", "1000", "-T4"]},
    "complet": {"label": "Complet (65 535 ports, ~10 min/hôte)", "args": ["-sV", "-p-", "-T4", "--min-rate", "800"]},
}


class ScanError(Exception):
    pass


def nmap_path() -> str:
    p = which("nmap")
    if not p:
        raise ScanError("Nmap n'est pas installé (inclus dans l'image Docker ; sinon : sudo apt install nmap).")
    return p


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def discover(target: str) -> list[str]:
    """Liste les hôtes actifs d'une IP ou d'un réseau."""
    code, out, err = run([nmap_path(), "-sn", "-T4", "-oX", "-", "--", target], timeout=600)
    if code != 0 and not out:
        raise ScanError(err.strip() or "Échec de la découverte réseau.")
    hosts = []
    for h in ET.fromstring(out).findall("host"):
        if h.find("status") is not None and h.find("status").get("state") == "up":
            addr = h.find("address[@addrtype='ipv4']")
            if addr is None:
                addr = h.find("address")
            if addr is not None:
                hosts.append(addr.get("addr"))
    return hosts


def scan_host(ip: str, profile: str = "rapide") -> dict:
    args = list(PROFILES.get(profile, PROFILES["rapide"])["args"])
    if is_root():
        args += ["-O", "--osscan-limit"]
    argv = [nmap_path(), *args, "--script", SAFE_SCRIPTS, "--script-timeout", "60s", "-Pn", "-oX", "-", "--", ip]
    code, out, err = run(argv, timeout=3600)
    if not out.strip():
        raise ScanError(err.strip() or f"Échec du scan de {ip}.")
    hosts = parse_nmap_xml(out)
    host = hosts[0] if hosts else {"ip": ip, "hostname": "", "os": "", "mac": "", "vendor": "", "ports": [], "host_scripts": {}}
    host["command"] = "nmap " + " ".join(a if " " not in a else f'"{a}"' for a in argv[1:])
    return host


def _cpe_list(service) -> list[str]:
    return [c.text.strip() for c in service.findall("cpe") if c.text] if service is not None else []


def parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = mac = vendor = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4" or (a.get("addrtype") == "ipv6" and not ip):
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr", ""), a.get("vendor", "")
        hn = h.find("hostnames/hostname")
        osm = h.find("os/osmatch")
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            scripts = {s.get("id"): s.get("output", "").strip() for s in p.findall("script")}
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
                "tunnel": svc.get("tunnel", "") if svc is not None else "",
                "cpe": _cpe_list(svc),
                "scripts": scripts,
            })
        hosts.append({
            "ip": ip,
            "hostname": hn.get("name") if hn is not None else "",
            "os": f"{osm.get('name')} ({osm.get('accuracy')} %)" if osm is not None else "",
            "mac": mac,
            "vendor": vendor,
            "ports": sorted(ports, key=lambda x: x["port"]),
            "host_scripts": {s.get("id"): s.get("output", "").strip() for s in h.findall("hostscript/script")},
        })
    return hosts
