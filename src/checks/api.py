# src/checks/api.py
import requests
import logging
from urllib.parse import urlparse

def check_api_endpoints(urls, session, driver, payloads, vulnerabilities, lock, test_localhost=False):
    if not driver:
        return
    api_urls = set()
    for url in urls:
        try:
            driver.get(url)
            import time
            time.sleep(2)
            requests_log = driver.execute_script("return window.performance.getEntriesByType('resource');")
            api_urls.update(entry['name'] for entry in requests_log if ('/api/' in entry['name'] or '.json' in entry['name']) 
                            and urlparse(entry['name']).hostname not in ['localhost', '127.0.0.1'])
        except Exception as e:
            logging.error(f"Erreur lors de la récupération des ressources réseau pour {url} : {e}")
    
    logging.info(f"API endpoints détectés : {api_urls}")
    
    for api_url in api_urls:
        parsed_url = urlparse(api_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            logging.warning(f"URL invalide ignorée : {api_url}")
            continue
        for vuln_type, payload_list in payloads.items():
            for payload in payload_list:
                if "localhost" in payload and not test_localhost:
                    continue
                try:
                    test_url = f"{api_url}?test={payload}"
                    logging.info(f"Testing API endpoint {test_url}")
                    resp = session.get(test_url, timeout=5)
                    if payload in resp.text:
                        with lock:
                            vulnerabilities.append({
                                "type": vuln_type,
                                "payload": payload,
                                "evidence": "Payload reflected in API",
                                "location": api_url,
                                "response_time": resp.elapsed.total_seconds(),
                                "status_code": resp.status_code
                            })
                except requests.RequestException as e:
                    logging.debug(f"Erreur lors du test de {test_url} : {e}")
                    continue