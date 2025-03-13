# src/core/crawler.py
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import logging
from ..utils.helpers import get_page_content

class Crawler:
    def __init__(self, target_url, max_pages, depth, subdomains, session):
        self.target_url = target_url.rstrip('/')  # Nettoie l'URL de base
        self.max_pages = max_pages
        self.depth = depth
        self.subdomains = subdomains
        self.session = session

    def crawl(self):
        """Parcourt le site et retourne un ensemble d'URLs valides."""
        urls = {self.target_url}  # Ensemble pour éviter les doublons
        visited = set()
        parsed_base = urlparse(self.target_url)
        base_domain = parsed_base.netloc
        current_depth = 0

        while urls and current_depth <= self.depth and len(visited) < self.max_pages:
            current_depth += 1
            urls_to_process = urls.copy()
            urls.clear()
            for url in urls_to_process:
                if url in visited:
                    continue
                visited.add(url)
                logging.info(f"Visiting: {url}")
                try:
                    content = get_page_content(url, self.session, None)
                    if not content:
                        continue
                    soup = BeautifulSoup(content, 'html.parser')
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href'].strip()
                        # Ignore les liens invalides ou malformés
                        if not href or href.startswith(('#', 'javascript:', 'mailto:', ',')):
                            continue
                        full_url = urljoin(url, href)  # Normalise l'URL
                        # Nettoie les barres obliques multiples
                        full_url = re.sub(r'/{2,}', '/', full_url.split('://', 1)[-1])
                        full_url = f"{urlparse(full_url).scheme}://{full_url}" if urlparse(full_url).scheme else f"http://{full_url}"
                        parsed_full = urlparse(full_url)
                        # Vérifie si l'URL appartient au domaine ou sous-domaine
                        if (parsed_full.netloc == base_domain) or (self.subdomains and base_domain in parsed_full.netloc):
                            if full_url not in visited and full_url not in urls:
                                urls.add(full_url)
                except Exception as e:
                    logging.error(f"Erreur lors du crawl de {url}: {e}")
        return visited
