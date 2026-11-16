"""Périmètre : seules les cibles autorisées peuvent être auditées."""
from __future__ import annotations

import ipaddress
import re
import socket

from . import config


class ScopeError(Exception):
    pass


def validate_target(target: str) -> str:
    t = (target or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.\-:/]{1,100}", t) or t.startswith("-"):
        raise ScopeError("Cible invalide : indique une IP (10.10.0.105), un réseau (10.10.0.0/24) ou un nom d'hôte.")
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        try:
            net = ipaddress.ip_network(socket.gethostbyname(t))
        except OSError:
            raise ScopeError(f"Impossible de trouver l'adresse de {t}.")
    if net.num_addresses > 4096:
        raise ScopeError("Réseau trop grand (maximum /20). Découpe ton audit en plusieurs parties.")
    for allowed in config.load()["cibles_autorisees"]:
        try:
            a = ipaddress.ip_network(allowed, strict=False)
        except ValueError:
            continue
        if net.version == a.version and net.subnet_of(a):
            return t
    raise ScopeError(
        f"{t} est hors du périmètre autorisé. Par sécurité, seuls ces réseaux peuvent être audités : "
        f"{', '.join(config.load()['cibles_autorisees'])}. Une adresse publique ne doit être ajoutée (dans Réglages) "
        "que si tu as l'autorisation écrite de son propriétaire."
    )
