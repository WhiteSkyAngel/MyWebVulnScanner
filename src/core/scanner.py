# src/core/scanner.py
import requests
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
from concurrent.futures import ThreadPoolExecutor
import logging
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from .crawler import Crawler
from .report import generate_report
from ..checks.injection import check_xss, check_sql_injection
from ..checks.file_access import check_lfi_rfi, check_ssrf
from ..checks.forms import check_form_vulnerability, test_file_upload
from ..checks.headers import check_security_headers
from ..checks.api import check_api_endpoints
from ..utils.payloads import load_payloads
from ..utils.selenium import setup_selenium
from ..utils.helpers import get_page_content

# Configuration des logs
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

file_handler = logging.FileHandler('scan_logs.log', mode='w')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

logger.addHandler(console_handler)
logger.addHandler(file_handler)

class WebVulnScanner:
    def __init__(self, target_url, username=None, password=None, max_pages=50, threads=5, depth=2, 
                 scan_all=False, use_js=False, subdomains=False, payloads_file="payloads.json", 
                 chrome_binary_path=None, test_localhost=False):
        self.target_url = target_url.rstrip('/')
        self.vulnerabilities = []
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=50, pool_maxsize=50, max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        self.baseline_response = None
        self.username = username
        self.password = password
        self.max_pages = max_pages
        self.threads = min(threads, 5)
        self.depth = depth
        self.scan_all = scan_all
        self.use_js = use_js
        self.subdomains = subdomains
        self.is_local = urlparse(target_url).hostname in ['localhost', '127.0.0.1']
        self.test_localhost = test_localhost if self.is_local else False
        self.lock = threading.Lock()
        self.payloads = load_payloads(payloads_file, self.test_localhost)
        logging.info(f"Payloads chargés : {self.payloads}")
        self.driver = self.setup_driver(chrome_binary_path) if use_js else None
        self.crawler = Crawler(self.target_url, self.max_pages, self.depth, self.subdomains, self.session)

    def setup_driver(self, chrome_binary_path=None):
        """Configure et retourne un driver Selenium avec Chrome."""
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        if chrome_binary_path:
            options.binary_location = chrome_binary_path
        else:
            options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        driver.requests_session = session

        return driver

    def crawl_website(self):
        """Parcourt le site pour collecter les URLs à scanner."""
        return self.crawler.crawl()

    def scan_page(self, url):
        """Scanne une page pour détecter des vulnérabilités."""
        logging.info(f"Scanning {url}")
        try:
            content = get_page_content(url, self.session, self.driver if self.use_js else None)
            if not content:
                logging.warning(f"Aucun contenu récupéré pour {url}")
                return

            soup = BeautifulSoup(content, 'html.parser')
            if not soup:
                logging.error(f"Échec de parsing HTML pour {url}")
                return

            baseline = self.get_baseline(url)

            if self.scan_all:
                check_xss(url, soup, self.session, self.payloads.get("XSS", []), self.vulnerabilities, self.lock)
                check_sql_injection(url, soup, self.session, self.payloads.get("SQLi", []), self.vulnerabilities, self.lock)
                check_lfi_rfi(url, soup, self.session, self.payloads.get("LFI", []), self.payloads.get("RFI", []), self.vulnerabilities, self.lock)
                check_ssrf(url, self.session, self.payloads.get("SSRF", []), self.vulnerabilities, self.lock)
                check_security_headers(url, self.session, self.vulnerabilities, self.lock)
                check_form_vulnerability(url, soup, self.session, self.payloads, self.vulnerabilities, self.lock, baseline)
                test_file_upload(url, self.session, self.vulnerabilities, self.lock)
                if self.driver:
                    check_api_endpoints([url], self.session, self.driver, self.payloads, self.vulnerabilities, self.lock)

        except Exception as e:
            logging.error(f"Erreur lors du scan de {url}: {e}", exc_info=True)

    def scan(self):
        """Lance le scan complet du site web."""
        print(f"Scan de {self.target_url} en cours...")
        if self.use_js and not self.driver:
            print("Avertissement : Selenium n'est pas disponible, passage en mode sans JS.")
            self.use_js = False

        urls_to_scan = self.crawl_website() if self.scan_all else {self.target_url}
        self.baseline_response = self.get_baseline(self.target_url)
        if self.username and self.password:
            self.login(self.target_url)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.scan_page, urls_to_scan)

        if self.driver:
            try:
                self.driver.quit()
                logging.info("Driver Selenium fermé avec succès")
            except Exception as e:
                logging.error(f"Erreur lors de la fermeture du driver: {e}")

        print(f"\n{len(self.vulnerabilities)} vulnérabilités détectées." if self.vulnerabilities 
              else "\nAucune vulnérabilité détectée.")
        try:
            generate_report(self.target_url, self.vulnerabilities)
            logging.info("Rapport généré avec succès")
        except Exception as e:
            logging.error(f"Erreur lors de la génération du rapport: {e}")

    def login(self, login_url):
        """Tente une connexion avec les identifiants fournis."""
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
        """Récupère les formulaires d'une page."""
        try:
            content = get_page_content(url, self.session, self.driver if self.use_js else None)
            soup = BeautifulSoup(content, 'html.parser')
            return soup.find_all('form')
        except requests.RequestException:
            return []

    def get_baseline(self, url):
        """Récupère une réponse de référence pour comparaison."""
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

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m src.core.scanner <url> [-all] [-js]")
    else:
        base_url = sys.argv[1]
        all_pages = "-all" in sys.argv
        js_analysis = "-js" in sys.argv
        scanner = WebVulnScanner(base_url, scan_all=all_pages, use_js=js_analysis)
        scanner.scan()