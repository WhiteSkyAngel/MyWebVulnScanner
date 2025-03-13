# src/utils/helpers.py
import requests
import re
import time
import difflib
import logging
from urllib.parse import urlparse

def get_page_content(url, session, driver):
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        logging.warning(f"URL invalide ignorée dans get_page_content : {url}")
        return ""
    logging.debug(f"Récupération du contenu de {url}")
    if driver:
        try:
            driver.get(url)
            time.sleep(2)
            content = driver.page_source
            logging.debug(f"Contenu récupéré avec Selenium pour {url}, longueur : {len(content)}")
            return content
        except Exception as e:
            logging.error(f"Erreur Selenium lors de la récupération de {url}: {e}")
            return ""
    else:
        try:
            response = session.get(url, timeout=5)
            content = response.text
            logging.debug(f"Contenu récupéré avec requests pour {url}, longueur : {len(content)}")
            return content
        except requests.RequestException as e:
            logging.error(f"Erreur lors de la récupération de {url}: {e}")
            return ""

def check_stack_traces_and_leaks(text, headers):
    patterns = {
        "stack_trace": [r"PHP Fatal error", r"PHP Warning", r"Stack trace: #[0-9]+"],
        "sensitive_info": [r"PHP/[0-9]\.[0-9]\.[0-9]", r"Server:.*(nginx|apache)", r"mysql_connect"]
    }
    findings = []
    for category, regex_list in patterns.items():
        for pattern in regex_list:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(f"{category}: {pattern}")
    if "Server" in headers and re.search(r"nginx|apache|PHP", headers["Server"], re.IGNORECASE):
        findings.append(f"sensitive_info: Server header reveals {headers['Server']}")
    return findings

def check_file_inclusion(text, payload):
    if "etc/passwd" in payload and re.search(r"root:[x0]:", text):
        return True
    if "phpinfo" in payload and "phpinfo()" in text:
        return True
    return False

def check_ssrf_response(text, payload):
    if "localhost" in payload and "127.0.0.1" in text:
        return True
    if "file://" in payload and re.search(r"root:|\[extensions\]", text):
        return True
    return False

def check_form_response(text, payload):
    patterns = [r"error", r"invalid", r"<script", r"alert\("]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns) or payload in text

def check_sql_response(text):
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in [
        r"mysql_fetch", r"sql syntax", r"unclosed quotation"
    ])

def check_xss_response(text, payload):
    return payload in text or any(char in text for char in ['<script', 'onerror', 'alert('])

def calculate_suspicion_score(response, payload, baseline, vuln_type, previous_responses):
    score = 0
    response_time = response.elapsed.total_seconds()
    response_length = len(response.text)
    response_headers = dict(response.headers)
    response_cookies = dict(response.cookies)
    
    if response_time > baseline["time"] * 2 and "DELAY" in payload.upper():
        score += 40
    if abs(response_length - baseline["length"]) > baseline["length"] * 0.3:
        score += 30
    diff_ratio = difflib.SequenceMatcher(None, response.text, baseline["text"]).ratio()
    if diff_ratio < 0.9:
        score += 20
    if response.status_code in [500, 403, 400]:
        score += 30
    if vuln_type == "SQL Injection" and check_sql_response(response.text):
        score += 50
    elif vuln_type == "XSS" and check_xss_response(response.text, payload):
        score += 50
    elif vuln_type in ["LFI", "RFI"] and check_file_inclusion(response.text, payload):
        score += 50
    elif vuln_type == "SSRF" and check_ssrf_response(response.text, payload):
        score += 50
    elif vuln_type == "Form Vulnerability" and check_form_response(response.text, payload):
        score += 50
    leaks = check_stack_traces_and_leaks(response.text, response_headers)
    if leaks:
        score += 50
    return score