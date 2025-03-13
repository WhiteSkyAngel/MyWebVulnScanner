import requests
import re
from urllib.parse import urlparse, urljoin
import sys
from bs4 import BeautifulSoup
import json
from datetime import datetime
import time
import difflib
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
import argparse
import os
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class WebVulnScanner:
    def __init__(self, target_url, username=None, password=None, max_pages=50, threads=5, depth=2, scan_all=False, use_js=False, subdomains=False, payloads_file="payloads.json"):
        self.target_url = target_url
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.baseline_response = None
        self.username = username
        self.password = password
        self.max_pages = max_pages
        self.threads = threads
        self.depth = depth
        self.scan_all = scan_all
        self.use_js = use_js
        self.subdomains = subdomains
        self.lock = threading.Lock()
        self.payloads = self.load_payloads(payloads_file)
        self.driver = None
        if use_js:
            self.setup_selenium()

    def load_payloads(self, payloads_file):
        """Charge les payloads depuis un fichier JSON"""
        default_payloads = {
            "XSS": ["<script>alert('xss')</script>", "';alert('xss');//", "<img src=x onerror=alert('xss')>", "javascript:alert(1)"],
            "SQLi": ["' OR 1=1 --", "1' UNION SELECT NULL, @@version --", "' DROP TABLE users; --", "' AND SLEEP(5) --"],
            "Command Injection": ["; ls", "&& dir", "| whoami", "; sleep 5"],
            "LFI": ["../../../../../../etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
            "RFI": ["http://example.com/malicious.php"],
            "SSRF": ["http://localhost", "file:///etc/hosts"]
        }
        if os.path.exists(payloads_file):
            with open(payloads_file, 'r') as f:
                return json.load(f)
        logging.info(f"Fichier {payloads_file} non trouvé, utilisation des payloads par défaut")
        return default_payloads

    def setup_selenium(self):
        """Configure Selenium pour les pages dynamiques"""
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)

    def get_page_content(self, url):
        """Récupère le contenu avec Selenium ou requests"""
        if self.use_js and self.driver:
            self.driver.get(url)
            time.sleep(2)  # Attendre le chargement JS
            return self.driver.page_source
        else:
            response = self.session.get(url, timeout=5)
            return response.text

    def get_baseline(self, url):
        """Obtient une réponse de référence"""
        try:
            response = self.session.get(url, params={"q": "test"}, timeout=5)
            return {
                "text": response.text,
                "time": response.elapsed.total_seconds(),
                "status": response.status_code,
                "length": len(response.text),
                "headers": dict(response.headers),
                "cookies": dict(response.cookies)
            }
        except requests.RequestException as e:
            logging.error(f"Erreur baseline {url}: {e}")
            return None

    def crawl(self):
        """Explore le site pour trouver toutes les URL"""
        urls = set([self.target_url])
        visited = set()
        parsed_base = urlparse(self.target_url)
        base_domain = parsed_base.netloc
        current_depth = 0

        while urls and current_depth <= self.depth:
            current_depth += 1
            urls_to_process = urls.copy()
            urls.clear()
            for url in urls_to_process:
                if url in visited or len(visited) >= self.max_pages:
                    continue
                visited.add(url)
                logging.info(f"Visiting: {url}")
                try:
                    content = self.get_page_content(url)
                    soup = BeautifulSoup(content, 'html.parser')
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href'].strip()
                        if not href or href.startswith(','):
                            continue
                        full_url = urljoin(url, href)
                        if full_url.startswith('https://') or full_url.startswith('http://'):
                            scheme, rest = full_url.split('://', 1)
                            full_url = scheme + '://' + re.sub(r'/+', '/', rest)
                        parsed_full = urlparse(full_url)
                        if (parsed_full.netloc == base_domain) or (self.subdomains and base_domain in parsed_full.netloc):
                            if full_url not in visited and full_url not in urls:
                                urls.add(full_url)
                except Exception as e:
                    logging.error(f"Erreur lors du crawl de {url}: {e}")
            if not self.scan_all:
                break
        return visited

    def login(self, login_url):
        """Tente une connexion si les identifiants sont fournis"""
        if not self.username or not self.password:
            return
        forms = self.get_forms(login_url)
        if not forms:
            logging.warning("Aucun formulaire de login trouvé")
            return
        form = forms[0]
        action = form.get('action') or login_url
        data = {input.get('name'): self.username if 'user' in input.get('name', '').lower() else self.password 
                for input in form.find_all('input') if input.get('name')}
        try:
            self.session.post(action, data=data, timeout=5)
            logging.info("Tentative de login effectuée")
        except requests.RequestException as e:
            logging.error(f"Erreur lors du login: {e}")

    def get_forms(self, url):
        """Récupère les formulaires d’une page"""
        try:
            content = self.get_page_content(url)
            soup = BeautifulSoup(content, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException:
            return []

    def check_stack_traces_and_leaks(self, text, headers):
        """Vérifie les fuites d’information"""
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

    def check_file_inclusion(self, text, payload):
        """Vérifie les inclusions de fichiers"""
        if "etc/passwd" in payload and re.search(r"root:[x0]:", text):
            return True
        if "phpinfo" in payload and "phpinfo()" in text:
            return True
        return False

    def check_ssrf_response(self, text, payload):
        """Vérifie les réponses SSRF"""
        if "localhost" in payload and "127.0.0.1" in text:
            return True
        if "file://" in payload and re.search(r"root:|\[extensions\]", text):
            return True
        return False

    def check_form_response(self, text, payload):
        """Vérifie les réponses des formulaires"""
        patterns = [r"error", r"invalid", r"<script", r"alert\("]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns) or payload in text

    def calculate_suspicion_score(self, response, payload, baseline, vuln_type, previous_responses):
        """Calcule un score de suspicion"""
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
        if vuln_type == "SQL Injection" and self.check_sql_response(response.text):
            score += 50
        elif vuln_type == "XSS" and self.check_xss_response(response.text, payload):
            score += 50
        elif vuln_type in ["LFI", "RFI"] and self.check_file_inclusion(response.text, payload):
            score += 50
        elif vuln_type == "SSRF" and self.check_ssrf_response(response.text, payload):
            score += 50
        elif vuln_type == "Form Vulnerability" and self.check_form_response(response.text, payload):
            score += 50
        leaks = self.check_stack_traces_and_leaks(response.text, response_headers)
        if leaks:
            score += 50
        return score

    def test_form(self, form, payloads, vuln_type, url):
        """Teste un formulaire avec des payloads"""
        action = form.get('action') or url
        method = form.get('method', 'get').lower()
        inputs = form.find_all(['input', 'select', 'textarea'])
        data = {input.get('name'): "test" if 'email' not in input.get('name', '').lower() else "test@example.com" 
                for input in inputs if input.get('name')}

        previous_responses = []
        baseline = self.get_baseline(url) or self.baseline_response
        for payload in payloads:
            for name in data.keys():
                test_data = data.copy()
                test_data[name] = payload
                try:
                    start_time = time.time()
                    if method == 'post':
                        response = self.session.post(action, data=test_data, timeout=10)
                    else:
                        response = self.session.get(action, params=test_data, timeout=10)
                    end_time = time.time()
                    
                    prev_response = {"text": response.text, "status": response.status_code}
                    previous_responses.append(prev_response)
                    
                    if baseline:
                        score = self.calculate_suspicion_score(response, payload, baseline, vuln_type, previous_responses)
                        if score >= 50:
                            with self.lock:
                                self.vulnerabilities.append({
                                    "type": vuln_type,
                                    "payload": payload,
                                    "evidence": f"Suspicion score: {score}",
                                    "location": f"Form field: {name} on {url}",
                                    "response_time": end_time - start_time,
                                    "status_code": response.status_code
                                })
                except requests.RequestException:
                    continue

    def test_file_upload(self, form, url):
        """Teste les vulnérabilités d’upload de fichiers"""
        action = form.get('action') or url
        files = {'file': ('test.php', '<?php echo "executed"; ?>', 'application/x-php')}
        try:
            response = self.session.post(action, files=files, timeout=10)
            if "executed" in response.text:
                with self.lock:
                    self.vulnerabilities.append({
                        "type": "File Upload Vulnerability",
                        "payload": "test.php with <?php echo 'executed'; ?>",
                        "evidence": "PHP code executed",
                        "location": f"Upload form on {url}",
                        "response_time": response.elapsed.total_seconds(),
                        "status_code": response.status_code
                    })
        except requests.RequestException:
            pass

    def check_sql_injection(self, url):
        """Vérifie les injections SQL"""
        forms = self.get_forms(url)
        for form in forms:
            self.test_form(form, self.payloads["SQLi"], "SQL Injection", url)
            # Test booléen pour Blind SQLi
            action = form.get('action') or url
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'select', 'textarea'])
            data = {input.get('name'): "test" for input in inputs if input.get('name')}
            for name in data:
                true_data = data.copy()
                false_data = data.copy()
                true_data[name] = "' OR 1=1 --"
                false_data[name] = "' OR 1=2 --"
                try:
                    if method == 'post':
                        true_resp = self.session.post(action, data=true_data, timeout=5)
                        false_resp = self.session.post(action, data=false_data, timeout=5)
                    else:
                        true_resp = self.session.get(action, params=true_data, timeout=5)
                        false_resp = self.session.get(action, params=false_data, timeout=5)
                    if true_resp.text != false_resp.text:
                        with self.lock:
                            self.vulnerabilities.append({
                                "type": "Blind SQL Injection",
                                "payload": "' OR 1=1 -- vs ' OR 1=2 --",
                                "evidence": "Boolean response difference",
                                "location": f"Form field: {name} on {url}",
                                "response_time": true_resp.elapsed.total_seconds(),
                                "status_code": true_resp.status_code
                            })
                except requests.RequestException:
                    continue

    def check_xss(self, url):
        """Vérifie les XSS"""
        forms = self.get_forms(url)
        for form in forms:
            self.test_form(form, self.payloads["XSS"], "XSS", url)

    def check_lfi_rfi(self, url):
        """Vérifie LFI/RFI"""
        forms = self.get_forms(url)
        for form in forms:
            self.test_form(form, self.payloads["LFI"], "LFI", url)
            self.test_form(form, self.payloads["RFI"], "RFI", url)

    def check_ssrf(self, url):
        """Vérifie SSRF"""
        forms = self.get_forms(url)
        for form in forms:
            self.test_form(form, self.payloads["SSRF"], "SSRF", url)

    def check_form_vulnerability(self, url):
        """Teste les formulaires pour diverses vulnérabilités"""
        try:
            content = self.get_page_content(url)
            soup = BeautifulSoup(content, 'html.parser')
            forms = soup.find_all('form')
            if not forms:
                logging.info(f"Aucun formulaire trouvé sur {url}")
                return []

            vulnerabilities = []
            baseline_resp = self.session.get(url, timeout=5).text

            for form in forms:
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                inputs = form.find_all(['input', 'select', 'textarea'])
                form_data = {input.get('name'): '' for input in inputs if input.get('name')}
                if not form_data:
                    continue

                target_url = urljoin(url, action)
                # Vérification CSRF
                csrf_token = form.find('input', {'name': re.compile(r'csrf|token', re.I)})
                if not csrf_token:
                    vulnerabilities.append({
                        "type": "CSRF",
                        "evidence": "No CSRF token found",
                        "location": url,
                        "response_time": 0,
                        "status_code": 200
                    })

                # Vérification IDOR
                self.check_idor(url, form)

                for vuln_type, payload_list in self.payloads.items():
                    for payload in payload_list:
                        test_data = {key: payload for key in form_data}
                        try:
                            start_time = time.time()
                            if method == 'post':
                                resp = self.session.post(target_url, data=test_data, timeout=5, allow_redirects=True)
                            else:
                                resp = self.session.get(target_url, params=test_data, timeout=5, allow_redirects=True)
                            response_time = time.time() - start_time

                            if payload in resp.text:
                                vulnerabilities.append({
                                    "type": vuln_type,
                                    "payload": payload,
                                    "evidence": f"Payload reflected: {payload}",
                                    "location": f"Form on {url}",
                                    "response_time": response_time,
                                    "status_code": resp.status_code
                                })
                            elif vuln_type == "SQLi" and "SLEEP" in payload.upper() and response_time > 4:
                                vulnerabilities.append({
                                    "type": "Blind SQLi",
                                    "payload": payload,
                                    "evidence": f"Delay: {response_time:.2f}s",
                                    "location": f"Form on {url}",
                                    "response_time": response_time,
                                    "status_code": resp.status_code
                                })
                        except requests.RequestException:
                            continue
            return vulnerabilities
        except requests.RequestException as e:
            logging.error(f"Erreur dans check_form_vulnerability: {e}")
            return []

    def check_idor(self, url, form):
        """Test basique pour IDOR"""
        inputs = form.find_all('input', {'type': 'hidden'})
        for input_tag in inputs:
            name = input_tag.get('name')
            value = input_tag.get('value')
            if name and value and value.isdigit():
                test_data = {name: str(int(value) + 1)}
                action = form.get('action', url)
                target_url = urljoin(url, action)
                try:
                    resp = self.session.post(target_url, data=test_data, timeout=5)
                    if resp.status_code == 200 and "error" not in resp.text.lower():
                        self.vulnerabilities.append({
                            "type": "IDOR",
                            "evidence": f"Modified {name} from {value} to {test_data[name]}",
                            "location": url,
                            "response_time": resp.elapsed.total_seconds(),
                            "status_code": resp.status_code
                        })
                except requests.RequestException:
                    pass

    def check_api_endpoints(self, url):
        """Détecte et teste les endpoints API avec Selenium"""
        if not self.use_js or not self.driver:
            return
        self.driver.get(url)
        time.sleep(2)
        requests_log = self.driver.execute_script("return window.performance.getEntriesByType('resource');")
        api_urls = {entry['name'] for entry in requests_log if '/api/' in entry['name'] or '.json' in entry['name']}
        for api_url in api_urls:
            for vuln_type, payload_list in self.payloads.items():
                for payload in payload_list:
                    try:
                        resp = self.session.get(f"{api_url}?test={payload}", timeout=5)
                        if payload in resp.text:
                            self.vulnerabilities.append({
                                "type": vuln_type,
                                "payload": payload,
                                "evidence": "Payload reflected in API",
                                "location": api_url,
                                "response_time": resp.elapsed.total_seconds(),
                                "status_code": resp.status_code
                            })
                    except requests.RequestException:
                        continue

    def check_security_headers(self, url):
        """Vérifie les en-têtes de sécurité"""
        try:
            response = self.session.get(url, timeout=5)
            headers = response.headers
            required_headers = {
                "X-Frame-Options": "Protection contre le clickjacking",
                "X-Content-Type-Options": "Prévention MIME sniffing",
                "Content-Security-Policy": "Contrôle des ressources",
                "Strict-Transport-Security": "Forçage HTTPS"
            }
            for header, purpose in required_headers.items():
                if header not in headers:
                    with self.lock:
                        self.vulnerabilities.append({
                            "type": "Missing Security Header",
                            "payload": header,
                            "evidence": f"Missing {purpose}",
                            "location": f"HTTP Headers on {url}",
                            "response_time": response.elapsed.total_seconds(),
                            "status_code": response.status_code
                        })
            leaks = self.check_stack_traces_and_leaks(response.text, headers)
            if leaks:
                with self.lock:
                    for leak in leaks:
                        self.vulnerabilities.append({
                            "type": "Information Leak",
                            "payload": "N/A",
                            "evidence": f"Detected {leak}",
                            "location": f"HTTP Headers or body on {url}",
                            "response_time": response.elapsed.total_seconds(),
                            "status_code": response.status_code
                        })
        except requests.RequestException:
            pass

    def check_sql_response(self, text):
        """Vérifie les réponses SQL"""
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in [
            r"mysql_fetch", r"sql syntax", r"unclosed quotation"
        ])

    def check_xss_response(self, text, payload):
        """Vérifie les réponses XSS"""
        return payload in text or any(char in text for char in ['<script', 'onerror', 'alert('])

    def scan_page(self, url):
        """Scanne une page pour toutes les vulnérabilités"""
        logging.info(f"Scanning {url}")
        self.check_sql_injection(url)
        self.check_xss(url)
        self.check_lfi_rfi(url)
        self.check_ssrf(url)
        form_vulns = self.check_form_vulnerability(url)
        with self.lock:
            self.vulnerabilities.extend(form_vulns)
        self.check_security_headers(url)
        self.check_api_endpoints(url)
        forms = self.get_forms(url)
        for form in forms:
            if any(input.get('type') == 'file' for input in form.find_all('input')):
                self.test_file_upload(form, url)

    def scan(self):
        """Lance le scan complet"""
        print(f"Scan de {self.target_url} en cours...")
        if self.scan_all:
            print("Mode -all activé : scanning de toutes les pages détectées.")
            urls_to_scan = self.crawl()
        else:
            print(f"Mode standard : scanning uniquement de {self.target_url}")
            urls_to_scan = {self.target_url}

        self.baseline_response = self.get_baseline(self.target_url)
        if self.username and self.password:
            self.login(self.target_url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_page, urls_to_scan)

        if self.driver:
            self.driver.quit()

        if self.vulnerabilities:
            print(f"\n{len(self.vulnerabilities)} vulnérabilités détectées.")
        else:
            print("\nAucune vulnérabilité détectée.")
        self.generate_report()

    def generate_report(self):
        """Génère un rapport JSON"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target_url,
            "vulnerabilities": self.vulnerabilities,
            "recommendations": []
        }
        vuln_types = {v["type"] for v in self.vulnerabilities}
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

def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="URL cible à scanner")
    parser.add_argument("-u", "--username", help="Nom d'utilisateur")
    parser.add_argument("-p", "--password", help="Mot de passe")
    parser.add_argument("-all", "--scan-all", action="store_true", help="Scanner toutes les pages")
    parser.add_argument("-js", "--use-js", action="store_true", help="Utiliser Selenium pour JS")
    parser.add_argument("-sub", "--subdomains", action="store_true", help="Inclure les sous-domaines")
    parser.add_argument("-m", "--max-pages", type=int, default=50, help="Nombre max de pages")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Nombre de threads")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Profondeur du crawl")
    parser.add_argument("-pf", "--payloads-file", default="payloads.json", help="Fichier de payloads")
    args = parser.parse_args()

    target = args.url if urlparse(args.url).scheme else "http://" + args.url
    scanner = WebVulnScanner(
        target, args.username, args.password, args.max_pages, args.threads, 
        args.depth, args.scan_all, args.use_js, args.subdomains, args.payloads_file
    )
    scanner.scan()

if __name__ == "__main__":
    main()