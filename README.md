# 🚀 MyWebVulnScanner - Scanner de Vulnérabilités Web

![MyWebVulnScanner](https://img.shields.io/badge/WebVulnScanner-Security_Tool-blueviolet?style=for-the-badge&logo=github)

**MyWebVulnScanner** est un outil open-source automatisé conçu pour détecter les vulnérabilités web courantes sur des sites web. Il est destiné aux développeurs, testeurs de sécurité et passionnés souhaitant analyser la sécurité de leurs applications web.


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🔥 Fonctionnalités

✅ **Détection de vulnérabilités** : XSS, SQL Injection, LFI/RFI, SSRF, CSRF, IDOR, etc.  
✅ **Support multi-threads** : Analyse rapide avec exécution parallèle.  
✅ **Rendu JavaScript** : Compatible avec les sites dynamiques via Selenium.  
✅ **Rapport détaillé** : Génère un rapport JSON des vulnérabilités détectées.  
✅ **Extensible** : Facile à personnaliser avec de nouveaux payloads et tests.  

---

## 📅 Fonctionnalités à venir

Le projet est en développement actif. Voici les améliorations prévues :

🚀 **Nouveaux tests** : Détection de vulnérabilités **XXE** (XML External Entity), **désérialisation non sécurisée**, et erreurs de configuration **CORS**.  
🚀 **Payloads améliorés** : Ajout de **payloads SSRF** et **payloads dynamiques** adaptés au contexte des champs.  
🚀 **Couverture étendue** : Crawl des **ressources JavaScript/AJAX** et scan des **sous-domaines**.  
🚀 **Expérience utilisateur** : Interface **CLI plus riche**, rapport visuel **HTML**, et **progression en temps réel**.  
🚀 **Optimisations** : Gestion avancée des **erreurs réseau** et **cache des réponses** pour accélérer les scans.  

---

## 📌 Prérequis

- 🔹 **Python 3.8+**
- 🔹 **Google Chrome** (pour le rendu JavaScript avec Selenium)

---

## ⚡ Installation

1. **Clonez le dépôt** :
   ```bash
   git clone https://github.com/WhiteSkyAngel/MyWebVulnScanner.git
   cd MyWebVulnScanner
   ```

2. **Installez les dépendances** :
   ```bash
   pip install -r requirements.txt
   ```

3. **Vérifiez l’installation** :
   ```bash
   python -m src.core.scanner --help
   ```

---

## 🎯 Utilisation

Lancez le scanner avec la commande suivante :

```bash
python -m src.core.scanner <URL> [OPTIONS]
```

### 🎛️ Options

- `-all` : Scanne toutes les pages détectées sur le site (par défaut : uniquement l’URL fournie).
- `-js` : Active le rendu JavaScript avec Selenium pour les sites dynamiques.

### ⚙️ Exemples

- **Scan simple d’une page** :
  ```bash
  python -m src.core.scanner http://example.com
  ```
- **Scan complet avec JavaScript** :
  ```bash
  python -m src.core.scanner http://www.chezgiusy.ch -all -js
  ```

📌 *Les résultats sont enregistrés dans `scan_report.json` dans le répertoire courant.*

---

## 📂 Structure du projet

```
my_web_vuln_scanner/
├── src/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py       # Classe principale MyWebVulnScanner
│   │   ├── crawler.py      # Logique de crawl
│   │   └── report.py       # Génération de rapports
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── injection.py    # Tests SQLi, XSS, Command Injection
│   │   ├── file_access.py  # Tests LFI, RFI, SSRF
│   │   ├── forms.py        # Tests liés aux formulaires (CSRF, IDOR, etc.)
│   │   ├── headers.py      # Vérification des en-têtes de sécurité
│   │   └── api.py          # Tests des endpoints API
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── payloads.py     # Gestion des payloads
│   │   ├── selenium.py     # Configuration et gestion de Selenium
│   │   └── helpers.py      # Fonctions utilitaires (get_page_content, etc.)
│   └── cli.py              # Point d'entrée avec argparse
├── payloads.json           # Fichier de payloads
├── requirements.txt        # Dépendances
└── README.md               # Documentation
```

---

## 📜 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.


---

## 👨‍💻 Auteur

**WhiteSkyAngel** - [GitHub](https://github.com/WhiteSkyAngel)

---

## 💡 Remerciements

Inspiré par les outils de sécurité open-source et la communauté de la cybersécurité.