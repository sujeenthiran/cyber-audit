"""Note globale A à F et statistiques."""
from __future__ import annotations

from .checks import SEV_ORDER

WEIGHTS = {"critique": 25, "élevée": 10, "moyenne": 4, "faible": 1, "info": 0}
GRADES = [(90, "A", "Très bon"), (75, "B", "Bon"), (60, "C", "Moyen"), (40, "D", "Insuffisant"), (20, "E", "Mauvais"), (0, "F", "Critique")]


def stats(findings: list[dict]) -> dict:
    counts = {k: 0 for k in WEIGHTS}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def grade(findings: list[dict]) -> dict:
    counts = stats(findings)
    score = max(0, 100 - sum(WEIGHTS[k] * n for k, n in counts.items()))
    if counts["critique"]:
        score = min(score, 59)  # plafond D
    elif counts["élevée"]:
        score = min(score, 74)
    for threshold, letter, label in GRADES:
        if score >= threshold:
            return {"score": score, "letter": letter, "label": label, "counts": counts}
    return {"score": score, "letter": "F", "label": "Critique", "counts": counts}


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (-SEV_ORDER[f["severity"]], f["host"], f["port"] or 0))
