# src/utils/selenium.py
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
import logging
import os

def setup_selenium(chrome_binary_path=None):
    """
    Configure Selenium avec ChromeDriver.
    :param chrome_binary_path: Chemin optionnel vers le binaire de Chrome si non standard.
    :return: Instance du WebDriver ou None si erreur.
    """
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # Exécution sans interface graphique
    options.add_argument('--disable-gpu')

    # Si un chemin personnalisé est fourni, l'utiliser
    if chrome_binary_path and os.path.exists(chrome_binary_path):
        options.binary_location = chrome_binary_path
        logging.info(f"Utilisation du binaire Chrome personnalisé : {chrome_binary_path}")
    else:
        # Vérifier les emplacements par défaut sous Windows
        default_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ]
        for path in default_paths:
            if os.path.exists(path):
                options.binary_location = path
                logging.info(f"Binaire Chrome trouvé à : {path}")
                break
        else:
            logging.warning("Binaire Chrome non trouvé dans les emplacements par défaut. Spécifiez-le manuellement avec --chrome-path.")

    try:
        driver = webdriver.Chrome(
            service=ChromeService(ChromeDriverManager().install()),
            options=options
        )
        return driver
    except Exception as e:
        logging.error(f"Erreur lors de la configuration de Selenium : {e}")
        print("Erreur : Impossible de lancer Selenium. Assurez-vous que Chrome est installé ou spécifiez son chemin avec --chrome-path.")
        return None