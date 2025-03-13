# src/checks/file_access.py
from bs4 import BeautifulSoup
import requests
import time
import logging
from ..utils.helpers import get_page_content, check_file_inclusion, check_ssrf_response, calculate_suspicion_score

def check_lfi_rfi(url, soup, session, lfi_payloads, rfi_payloads, vulnerabilities, lock):
    """Vérifie les vulnérabilités LFI/RFI dans les paramètres des formulaires ou URL."""
    if not soup:
        logging.warning(f"Aucun contenu parsé fourni pour {url}, abandon du test LFI/RFI")
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
        
        for vuln_type, payloads in [("LFI", lfi_payloads), ("RFI", rfi_payloads)]:
            for payload in payloads:
                for name in data:
                    test_data = data.copy()
                    test_data[name] = payload
                    try:
                        start_time = time.time()
                        if method == 'post':
                            response = session.post(action, data=test_data, timeout=10)
                            logging.debug(f"Réponse POST pour {action} avec {test_data}: {response.text[:500]}")
                        else:
                            response = session.get(action, params=test_data, timeout=10)
                        response_time = time.time() - start_time
                        if baseline:
                            score = calculate_suspicion_score(response, payload, baseline, vuln_type, [])
                            logging.debug(f"Score pour {payload} ({vuln_type}) sur {name} : {score}")
                            if score >= 50:
                                with lock:
                                    vulnerabilities.append({
                                        "type": vuln_type,
                                        "payload": payload,
                                        "evidence": f"Suspicion score: {score}",
                                        "location": f"Form field: {name} on {url}",
                                        "response_time": response_time,
                                        "status_code": response.status_code
                                    })
                                    logging.info(f"{vuln_type} détecté : {payload} sur {url}")
                    except requests.RequestException as e:
                        logging.debug(f"Erreur lors du test de {payload} sur {name} : {e}")
                        continue

def check_ssrf(url, session, payloads, vulnerabilities, lock, test_localhost=False):
    """Vérifie les vulnérabilités SSRF dans les formulaires."""
    forms = _get_forms(url, session)
    logging.info(f"Nombre de formulaires trouvés sur {url} : {len(forms)}")
    baseline = _get_baseline(url, session)
    for form in forms:
        action = form.get('action') or url
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'select', 'textarea'])
        data = {input.get('name'): "test" for input in inputs if input.get('name')}
        for payload in payloads:
            if "localhost" in payload and not test_localhost:
                continue
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
                        score = calculate_suspicion_score(response, payload, baseline, "SSRF", [])
                        if score >= 50:
                            with lock:
                                vulnerabilities.append({
                                    "type": "SSRF",
                                    "payload": payload,
                                    "evidence": f"Suspicion score: {score}",
                                    "location": f"Form field: {name} on {url}",
                                    "response_time": response_time,
                                    "status_code": response.status_code
                                })
                            logging.info(f"SSRF détecté : {payload} sur {url}")
                except requests.RequestException:
                    continue

def _get_forms(url, session):
    """Récupère les formulaires d'une page."""
    content = get_page_content(url, session, None)  # Pas de driver ici
    if not content:
        logging.warning(f"Aucun contenu récupéré pour {url} dans _get_forms")
        return []
    soup = BeautifulSoup(content, 'html.parser')
    return soup.find_all('form')

def _get_baseline(url, session):
    """Récupère une réponse de référence pour comparaison."""
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