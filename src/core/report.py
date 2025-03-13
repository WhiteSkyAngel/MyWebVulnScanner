# src/core/report.py
import json
from datetime import datetime

def generate_report(target_url, vulnerabilities):
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "vulnerabilities": vulnerabilities,
        "recommendations": []
    }
    vuln_types = {v["type"] for v in vulnerabilities}
    if "SQL Injection" in vuln_types or "Blind SQLi" in vuln_types:
        report["recommendations"].append("Utiliser des requêtes paramétrées et valider les entrées")
    if "XSS" in vuln_types:
        report["recommendations"].append("Échapper les entrées et implémenter une CSP stricte")
    if "LFI" in vuln_types or "RFI" in vuln_types:
        report["recommendations"].append("Valider les chemins de fichiers et filtrer les entrées PHP")
    if "SSRF" in vuln_types:
        report["recommendations"].append("Restreindre les requêtes serveur et valider les URL")
    if "CSRF" in vuln_types:
        report["recommendations"].append("Ajouter des tokens CSRF à tous les formulaires")
    if "IDOR" in vuln_types:
        report["recommendations"].append("Vérifier les autorisations d’accès aux objets")
    if "File Upload Vulnerability" in vuln_types:
        report["recommendations"].append("Valider les types de fichiers uploadés")
    if "Missing Security Header" in vuln_types:
        report["recommendations"].append("Ajouter les en-têtes de sécurité manquants")
    if "Information Leak" in vuln_types:
        report["recommendations"].append("Supprimer les stack traces et masquer les versions/logiciels")

    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=4)
    print("Rapport généré: scan_report.json")