# src/checks/headers.py
import requests
import re
from ..utils.helpers import check_stack_traces_and_leaks

def check_security_headers(url, session, vulnerabilities, lock):
    try:
        response = session.get(url, timeout=5)
        headers = response.headers
        required_headers = {
            "X-Frame-Options": "Protection contre le clickjacking",
            "X-Content-Type-Options": "Prévention MIME sniffing",
            "Content-Security-Policy": "Contrôle des ressources",
            "Strict-Transport-Security": "Forçage HTTPS"
        }
        for header, purpose in required_headers.items():
            if header not in headers:
                with lock:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "payload": header,
                        "evidence": f"Missing {purpose}",
                        "location": f"HTTP Headers on {url}",
                        "response_time": response.elapsed.total_seconds(),
                        "status_code": response.status_code
                    })
        leaks = check_stack_traces_and_leaks(response.text, headers)
        if leaks:
            with lock:
                for leak in leaks:
                    vulnerabilities.append({
                        "type": "Information Leak",
                        "payload": "N/A",
                        "evidence": f"Detected {leak}",
                        "location": f"HTTP Headers or body on {url}",
                        "response_time": response.elapsed.total_seconds(),
                        "status_code": response.status_code
                    })
    except requests.RequestException:
        pass