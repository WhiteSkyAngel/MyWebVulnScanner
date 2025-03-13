# src/checks/injection.py
from bs4 import BeautifulSoup
import requests
import time
import logging
import difflib
from ..utils.helpers import get_page_content, check_sql_response, check_xss_response, calculate_suspicion_score

def check_xss(url, soup, session, payloads, vulnerabilities, lock):
    """Vérifie les vulnérabilités XSS dans les formulaires."""
    if not soup:
        logging.warning(f"Aucun contenu parsé fourni pour {url}, abandon du test XSS")
        return

    forms = soup.find_all('form')
    logging.info(f"Nombre de formulaires trouvés sur {url} : {len(forms)}")
    baseline = _get_baseline(url, session)
    for form in forms:
        action = form.get('action') or url
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'select', 'textarea'])
        data = {input.get('name'): "test" for input in inputs if input.get('name')}
        logging.info(f"Test de {len(inputs)} champs sur {action} ({method})")
        for payload in payloads:  # payloads est une liste
            for name in data:
                test_data = data.copy()
                test_data[name] = payload
                try:
                    start_time = time.time()
                    if method == 'post':
                        response = session.post(action, data=test_data, timeout=10)
                    else:
                        response = session.get(action, params=test_data, timeout=10)
                    response_time = time.time() - start_time
                    if baseline:
                        score = calculate_suspicion_score(response, payload, baseline, "XSS", [])
                        logging.debug(f"Score pour {payload} (XSS) sur {name} : {score}")
                        if score >= 50:
                            with lock:
                                vulnerabilities.append({
                                    "type": "XSS",
                                    "payload": payload,
                                    "evidence": f"Suspicion score: {score}",
                                    "location": f"Form field: {name} on {url}",
                                    "response_time": response_time,
                                    "status_code": response.status_code
                                })
                                logging.info(f"XSS détecté : {payload} sur {url}")
                except requests.RequestException:
                    continue

def check_sql_injection(url, soup, session, payloads, vulnerabilities, lock):
    """Vérifie les vulnérabilités SQLi dans les formulaires."""
    if not soup:
        logging.warning(f"Aucun contenu parsé fourni pour {url}, abandon du test SQLi")
        return

    forms = soup.find_all('form')
    logging.info(f"Nombre de formulaires trouvés sur {url} : {len(forms)}")
    baseline = _get_baseline(url, session)
    for form in forms:
        action = form.get('action') or url
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'select', 'textarea'])
        data = {input.get('name'): "test" for input in inputs if input.get('name')}
        logging.info(f"Test de {len(inputs)} champs sur {action} ({method})")
        for payload in payloads:  # payloads est une liste
            for name in data:
                test_data = data.copy()
                test_data[name] = payload
                try:
                    start_time = time.time()
                    if method == 'post':
                        response = session.post(action, data=test_data, timeout=10)
                    else:
                        response = session.get(action, params=test_data, timeout=10)
                    response_time = time.time() - start_time
                    if baseline:
                        score = calculate_suspicion_score(response, payload, baseline, "SQL Injection", [])
                        logging.debug(f"Score pour {payload} (SQLi) sur {name} : {score}")
                        if score >= 50:
                            with lock:
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "payload": payload,
                                    "evidence": f"Suspicion score: {score}",
                                    "location": f"Form field: {name} on {url}",
                                    "response_time": response_time,
                                    "status_code": response.status_code
                                })
                                logging.info(f"SQLi détecté : {payload} sur {url}")
                except requests.RequestException:
                    continue

def _get_forms(url, session):
    content = get_page_content(url, session, None)
    if not content:
        logging.warning(f"Aucun contenu récupéré pour {url} dans _get_forms")
        return []
    soup = BeautifulSoup(content, 'html.parser')
    return soup.find_all('form')

def _get_baseline(url, session):
    try:
        response = session.get(url, params={"q": "test"}, timeout=5)
        return {
            "text": response.text,
            "time": response.elapsed.total_seconds(),
            "status": response.status_code,
            "length": len(response.text),
            "headers": dict(response.headers),
            "cookies": dict(response.cookies)
        }
    except requests.RequestException:
        return None