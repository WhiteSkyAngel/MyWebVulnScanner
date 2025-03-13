# src/checks/forms.py (corrigé)
from bs4 import BeautifulSoup
import requests
import re
import time
from urllib.parse import urljoin
from ..utils.helpers import get_page_content, check_form_response, calculate_suspicion_score

def check_form_vulnerability(url, soup, session, payloads, vulnerabilities, lock, baseline, test_localhost=False):
    """Vérifie les vulnérabilités dans les formulaires."""
    forms = soup.find_all('form')
    if not forms:
        return

    for form in forms:
        action = form.get('action') or url
        action = urljoin(url, action)  # Gérer les URLs relatives
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'select', 'textarea'])
        data = {input.get('name'): "test" if 'email' not in input.get('name', '').lower() else "test@example.com" 
                for input in inputs if input.get('name')}
        if not data:
            continue
        # Vérification CSRF
        csrf_token = form.find('input', {'name': re.compile(r'csrf|token', re.I)})
        if not csrf_token:
            with lock:
                vulnerabilities.append({
                    "type": "CSRF",
                    "evidence": "No CSRF token found",
                    "location": url,
                    "response_time": 0,
                    "status_code": 200
                })
        # Test des payloads
        for vuln_type, payload_list in payloads.items():
            for payload in payload_list:
                if "localhost" in payload and not test_localhost:
                    continue  # Ignorer localhost pour sites distants
                test_data = {key: payload for key in data}
                try:
                    start_time = time.time()
                    if method == 'post':
                        response = session.post(action, data=test_data, timeout=5)
                    else:
                        response = session.get(action, params=test_data, timeout=5)
                    response_time = time.time() - start_time
                    if baseline:
                        score = calculate_suspicion_score(response, payload, baseline, vuln_type, [])
                        if score >= 50:
                            with lock:
                                vulnerabilities.append({
                                    "type": vuln_type,
                                    "payload": payload,
                                    "evidence": f"Suspicion score: {score}",
                                    "location": url,
                                    "response_time": response_time,
                                    "status_code": response.status_code
                                })
                except requests.RequestException:
                    continue
        # Vérification IDOR
        check_idor(url, form, session, vulnerabilities, lock)

def test_file_upload(url, session, vulnerabilities, lock):
    forms = _get_forms(url, session)
    for form in forms:
        if any(input.get('type') == 'file' for input in form.find_all('input')):
            action = form.get('action') or url
            action = urljoin(url, action)  # Gérer les URLs relatives
            files = {'file': ('test.php', '<?php echo "executed"; ?>', 'application/x-php')}
            try:
                response = session.post(action, files=files, timeout=10)
                if "executed" in response.text:
                    with lock:
                        vulnerabilities.append({
                            "type": "File Upload Vulnerability",
                            "payload": "test.php with <?php echo 'executed'; ?>",
                            "evidence": "PHP code executed",
                            "location": f"Upload form on {url}",
                            "response_time": response.elapsed.total_seconds(),
                            "status_code": response.status_code
                        })
            except requests.RequestException:
                pass

def check_idor(url, form, session, vulnerabilities, lock):
    inputs = form.find_all('input', {'type': 'hidden'})
    for input_tag in inputs:
        name = input_tag.get('name')
        value = input_tag.get('value')
        if name and value and value.isdigit():
            test_data = {name: str(int(value) + 1)}
            action = form.get('action', url)
            target_url = urljoin(url, action)  # Gérer les URLs relatives
            try:
                resp = session.post(target_url, data=test_data, timeout=5)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    with lock:
                        vulnerabilities.append({
                            "type": "IDOR",
                            "evidence": f"Modified {name} from {value} to {test_data[name]}",
                            "location": url,
                            "response_time": resp.elapsed.total_seconds(),
                            "status_code": resp.status_code
                        })
            except requests.RequestException:
                pass

def _get_forms(url, session):
    content = get_page_content(url, session, None)
    soup = BeautifulSoup(content, 'html.parser')
    return soup.find_all('form')