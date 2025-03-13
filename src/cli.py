# src/cli.py
import argparse
from urllib.parse import urlparse
from .core.scanner import WebVulnScanner

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
    parser.add_argument("--chrome-path", help="Chemin vers le binaire Chrome (optionnel)")
    args = parser.parse_args()

    target = args.url if urlparse(args.url).scheme else "http://" + args.url
    scanner = WebVulnScanner(
        target, args.username, args.password, args.max_pages, args.threads, 
        args.depth, args.scan_all, args.use_js, args.subdomains, args.payloads_file,
        chrome_binary_path=args.chrome_path  # Passage du chemin
    )
    scanner.scan()

if __name__ == "__main__":
    main()