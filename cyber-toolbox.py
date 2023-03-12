#!/usr/bin/env python

# Importe les bibliothèques nécessaires
import ipaddress
import re
import shutil
import socket
import sys
import time
import configparser
import nmap
import requests
import os
import platform
import subprocess
import threading
import googlesearch
import datetime
import pandas as pd
from os.path import basename
from dateutil.parser import parse
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from netaddr import IPAddress
from prettytable import PrettyTable

# Permet d'avoir des couleurs
from colorama import init

init()

#### Flag ####

flag = """

         █████╗ ██╗   ██╗██████╗ ███████╗██████╗ 
        ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
        ██║  ╚═╝ ╚████╔╝ ██████╦╝█████╗  ██████╔╝
        ██║  ██╗  ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
        ╚█████╔╝   ██║   ██████╦╝███████╗██║  ██║
         ╚════╝    ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

████████╗ █████╗  █████╗ ██╗     ██████╗  █████╗ ██╗  ██╗
╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔══██╗██╔══██╗╚██╗██╔╝
   ██║   ██║  ██║██║  ██║██║     ██████╦╝██║  ██║ ╚███╔╝ 
   ██║   ██║  ██║██║  ██║██║     ██╔══██╗██║  ██║ ██╔██╗ 
   ██║   ╚█████╔╝╚█████╔╝███████╗██████╦╝╚█████╔╝██╔╝╚██╗
   ╚═╝    ╚════╝  ╚════╝ ╚══════╝╚═════╝  ╚════╝ ╚═╝  ╚═╝
"""

#### Variables ####

again = "true"
ORANGE = '\033[0;33m'  # Orange for print
GREEN = '\033[0;92m'  # Green for print
NC = '\033[0m'  # No Color for print

name_task = "CyberToolbox"

system = platform.system()
pathFolderConf = ""
if system == "Linux":
    pathFolderConf = os.path.join(os.getenv("HOME"), 'CyberToolbox')
elif system == "Windows":
    pathFolderConf = os.path.join(os.getenv("USERPROFILE"), 'CyberToolbox')

pathFileConf = os.path.join(pathFolderConf, 'fileConf.conf')
cheminCompletFichier = os.path.realpath(__file__)
newPathFileScript = os.path.join(pathFolderConf, basename(cheminCompletFichier))

timeSchuduler = ""
oliveTime = ""
Param = "autoscan"

#### Menus ####

help = """
      Commandes      |                 Descriptions                    
=============================================================================
        help         |     Affiche le menu d'aide contextuel
        recon        |     Effectue une reconnaissance du réseau
        scan         |     Effectue un scan actif sur une IP
        autoscan     |     Ajoute un scan en tâche planifiée qui effectue un scan quotidien
        cvss         |     Effectue une recherche en fonction du CVSS
        dorks        |     Effectue une recherche dorks sur un domaine
        clear        |     Efface l'invité de commande
        exit         |     Permet de quitter le script
"""

scan_type = """
    Commandes   |                      Descriptions                    
=============================================================================
        1       |        Scan rapide (only ports, no details, no CVE)
        2       |        Scan intermédiaire (details ports + CVE)
        3       |        Scan intense (intermédiaire en plus fiable)
"""

dorks_type = """
    Commandes   |                      Descriptions                    
=============================================================================
        1       |      Recherche une page admin
        2       |      Recherche une page d'authentification
        3       |      Recherche un document sensible de type pdf
        4       |      Recherche une vulnérabilité sur le site web
        5       |      Recherche un type de fichier spécifique sur le site
"""

autoscan_type = """
Vous avez déjà une tâche planifiée "Cyber-Toolbox".


    Commandes   |                      Descriptions                    
=============================================================================
        1       |        Modifier la tâche planifiée
        2       |        Supprimer la tâche
        3       |        Retourner au Menu Principal
"""


#### Fonctions ####

def convert_to_crontab_time(time_str):
    # Sépare les heures, minutes et secondes
    hours, minutes, seconds = time_str.split(':')

    # Assure que les heures, minutes et secondes sont valides
    if not (0 <= int(hours) < 24 and 0 <= int(minutes) < 60 and 0 <= int(seconds) < 60):
        raise ValueError("Invalid time value.")

    # Formate la chaîne de caractères selon la syntaxe Crontab
    return f"{int(seconds)} {int(minutes)} {int(hours)} * * *"

def check_time_format(input_str):
    try:
        hours, minutes, seconds = map(int, input_str.split(':'))
        if 0 <= hours <= 23 and 0 <= minutes <= 59 and 0 <= seconds <= 59:
            return True
        else:
            return False
    except ValueError:
        return False

def get_ip_address(domain):
    try:
        ip_address = "0.0.0.0"
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return "a.a.a.a"

def validate_ip_address(address):

    match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", address)

    if bool(match) is False:
        return False

    for part in address.split("."):
        if int(part) < 0 or int(part) > 255:
            return False

    return True


def validate_ports(range):
    match = re.match(r"^(\d{1,5})\-(\d{1,5})$", range)

    if bool(match) is False:
        return False

    for part in range.split("-"):
        if int(part) < 0 or int(part) > 49151:
            return False

    return True


def export_prettytable(namefile, table):
    num = 0
    file = namefile + ".csv"
    for num in range(100):
        if os.path.exists(file):
            num = num + 1
            num_str = str(num)
            file = namefile + "_(" + num_str + ").csv"
        else:
            table.to_csv(file, index=False, header=True)
            break
    print(
        f"\nLe fichier{GREEN} {file} {NC}est maintenant disponible dans le dossier {GREEN}" + os.getcwd() + f"{NC}.\n")


def export_pdf(file_name, df):
    file = file_name + ".pdf"
    for num in range(100):
        if os.path.exists(file):
            num = num + 1
            num_str = str(num)
            file = file_name + "_(" + num_str + ").pdf"
        else:
            doc = SimpleDocTemplate(file, pagesize=letter)
            break

    # Titre du PDF (titre dans l'onglet chrome par exemple)
    doc.title = "Rapport automatique"

    # Styles des champs du PDF
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    body_style = styles["Normal"]
    body_style = ParagraphStyle(name="subtitle", fontSize=10, leading=14)
    subtitle_style = ParagraphStyle(name="subtitle", fontSize=14, leading=18)
    espace = Spacer(1, 14)

    # Title PDF
    text_title = "Rapport d'Audit de Sécurité"
    title = Paragraph(text_title, title_style)
    elements = [title]
    elements.append(espace)

    # Subtitle PDF
    text_subtitle = "Introduction"
    subtitle = Paragraph(text_subtitle, subtitle_style)
    elements.append(subtitle)
    elements.append(espace)

    # Body PDF
    text_body = "Ce rapport d'audit de sécurité a été réalisé pour évaluer les vulnérabilités potentielles de votre système d'information. L'objectif de cet audit était de déterminer si le système était sécurisé contre les menaces externes, telles que les attaques de pirates informatiques, les tentatives d'intrusion et les vulnérabilités système."
    body = Paragraph(text_body, body_style)
    elements.append(body)
    elements.append(espace)

    # Body PDF
    text_body = "Pour réaliser cet audit de sécurité, nous avons effectué une analyse du système d'information, en utilisant une combinaison de techniques automatisées."
    body = Paragraph(text_body, body_style)
    elements.append(body)
    elements.append(espace)

    # Subtitle PDF
    text_subtitle = "Recommandations"
    subtitle = Paragraph(text_subtitle, subtitle_style)
    elements.append(subtitle)
    elements.append(espace)

    # Body PDF
    text_body = "Pour corriger les vulnérabilités potentielles identifiées, nous recommandons les actions suivantes :"
    body = Paragraph(text_body, body_style)
    elements.append(body)
    text_body = "• Appliquer les mises à jour de sécurité recommandées pour les systèmes et les applications utilisés."
    body = Paragraph(text_body, body_style)
    elements.append(body)
    text_body = "• Utiliser les protocoles de sécurité adéquats pour éviter les attaques de type man-in-the-middle."
    body = Paragraph(text_body, body_style)
    elements.append(body)
    text_body = "• Faire attention aux informations publiées par vos noms de domaines."
    body = Paragraph(text_body, body_style)
    elements.append(body)
    elements.append(espace)

    # Subtitle PDF
    text_subtitle = "Résultats"
    subtitle = Paragraph(text_subtitle, subtitle_style)
    elements.append(subtitle)
    elements.append(espace)

    table_data = [df.columns.tolist()] + df.values.tolist()
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('BOX', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('HRULES', (0, 1), (-1, -1), 1, colors.grey),
    ]))
    # Ajouter les éléments au document et générer le PDF
    elements.append(table)
    elements.append(espace)
    doc.build(elements)

    print(
        f"\nLe fichier{GREEN} {file} {NC}est maintenant disponible dans le dossier {GREEN}" + os.getcwd() + f"{NC}.\n")


def loading():
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    print("")
    while not stop_thread:
        for frame in frames:
            time.sleep(0.1)
            print(f"{message_charg} {frame}", end='\r')


### Active Scan ###

def active_scan():
    print(f"Toolbox/scan >>> Saisir l\'adresse IP ou le nom de domaine de la machine cible")
    adresseIPorDNS = input(f"Toolbox/scan >>> ")

    ip_address = get_ip_address(adresseIPorDNS)

    # Vérifie si l'entrée est une IP valide
    if validate_ip_address(ip_address):

        # Crée un objet nmap.PortScanner pour scanner l'adresse IP
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments='-sn')

        # Vérifie si l'host est en ligne
        online_hosts = nm.all_hosts()
        if ip_address in online_hosts:

            print(f"Toolbox/scan >>> Saisir la range des ports. Exemple -> 0-49151 (default is top 1000 ports used)")
            range_port = input("Toolbox/scan >>> ") or ""
            # Modifie les arguments en fonction des ports voulu
            if validate_ports(range_port) or range_port == "":
                if range_port != "":
                    range_port = " -p" + range_port

                # Modifie le type de scan
                print(scan_type + f"\nToolbox/scan >>> Choisir le type de scan (default is 2)")
                scan_choice = input("Toolbox/scan >>> ") or "2"

                match scan_choice:
                    case '1':
                        nmap_arguments = "-O -T5" + range_port
                        type_scan = "rapide"
                    case '2':
                        nmap_arguments = "-A -T5" + range_port
                        type_scan = "intermédiaire"
                    case '3':
                        nmap_arguments = "-A -T4" + range_port
                        type_scan = "intense"

                # Configure le message avec le chargement
                global message_charg
                message_charg = "Scan " + type_scan + " de " + ip_address + " en cours"

                # Execute le chargement en attendant la fin du scan
                global stop_thread
                stop_thread = False
                t = threading.Thread(target=loading)
                t.start()

                # Execute le scan
                nm.scan(ip_address, arguments=nmap_arguments)

                # Récupère les ports ouverts et leurs informations
                open_ports = nm[ip_address]["tcp"].keys()
                port_info = {}
                for port in open_ports:
                    port_info[port] = {
                        "service": nm[ip_address]["tcp"][port]["product"],
                        "version": nm[ip_address]["tcp"][port]["version"],
                        "name": nm[ip_address]["tcp"][port]["name"],
                        "cpe": nm[ip_address]["tcp"][port]["cpe"]
                    }

                # Récupère les informations sur l'OS
                sys_matches = nm[ip_address]["osmatch"]
                sys_matches.sort(key=lambda x: x['accuracy'], reverse=True)
                sys = sys_matches[0]
                sys_name = sys['name']
                sys_accuracy = sys['accuracy']

                # Créer un dictionnaire avec les données pour le tableau
                data = {'Port': [],
                        'Protocole': [],
                        'Nom du service': [],
                        'Version': [],
                        'CVE': [],
                        'CVSS': []}

                # Créer le tableau à partir du dictionnaire
                table = pd.DataFrame(data)
                location = 1

                # Permet d'éviter les virgules dans l'affichage des ports
                table["Port"] = table["Port"].astype(int)

                # Ajoute les ports ouverts, leurs informations et les CVE associées dans le tableau
                for port, info in port_info.items():
                    error_api = False
                    nb_cve = 0
                    cvss = ["N/A"]
                    name_cve = ["Aucune CVE trouvée"]
                    # Vérifie si une donnée CPE est disponible (vulnérabilité) afin d'effectuer une recherche CVE
                    if info["cpe"] != "":
                        cpe_split = info["cpe"].split(":")
                        # Exclu les recherche sur "linux" et sur "windows" afin d'éviter les CVEs inutiles sur le kernel
                        if "linux" not in cpe_split:
                            if "windows" not in cpe_split:
                                # Envoyez une requête à l'API de NVD avec le CPE
                                response = requests.get(
                                    f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={info["cpe"]}')
                                if response.status_code == 200:
                                    # Récupérez la liste des vulnérabilités dans le résultat de la recherche
                                    cves = response.json()['result']['CVE_Items']
                                    # Pour chaque vulnérabilité, récupère son identifiant et sa description
                                    for cve in cves:
                                        # Récupère le score CVSS
                                        if 'baseMetricV3' in cve['impact']:
                                            cvss_score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
                                        elif 'baseMetricV2' in cve['impact']:
                                            cvss_score = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
                                        else:
                                            cvss_score = 0
                                        if cvss_score > 7.5:
                                            nb_cve = nb_cve + 1
                                            cvss.append(cvss_score)
                                            cve = cve["cve"]["CVE_data_meta"]["ID"]
                                            # Decommenter la ligne ci dessous si on souhaite avoir les liens des CVEs à la place du numéro de CVE
                                            # cve = "https://nvd.nist.gov/vuln/detail/" + cve
                                            name_cve.append(cve)
                                            # name_cve.append(cve["cve"]["CVE_data_meta"]["ID"])
                                            # Incrémente le tableau avec les informations des ports avec CVE
                                            if nb_cve == 1:
                                                table.loc[location] = [port, info["name"], info["service"],
                                                                       info["version"], name_cve[1], cvss[1]]
                                                location = location + 1
                                            else:
                                                # Si plusieurs CVE, ajoute l'un après l'autre
                                                for i in range(1, nb_cve):
                                                    table.loc[location] = ["-", "-", "-", "-", name_cve[i + 1],
                                                                           cvss[i + 1]]
                                                    location = location + 1
                                else:
                                    error_api = True
                    else:
                        # Incrémente le tableau avec les informations des ports sans CVE
                        table.loc[location] = [port, info["name"], info["service"], info["version"], name_cve[0],
                                               cvss[0]]
                        location = location + 1

                # Créer une instance de la classe PrettyTable pour formater le tableau pandas
                pt = PrettyTable()
                pt.field_names = table.columns
                for row in table.itertuples():
                    pt.add_row(row[1:])
                pt.align = 'c'

                # Stop le chargement
                stop_thread = True
                t.join()

                # Affiche le tableau avec les données du scan
                print(f"Les ports ouverts et les informations associées de {GREEN}" + ip_address + f"{NC} sont :\n")
                print(pt)

                # Affiche un message en cas d'erreur pour l'API de NVD (check CVEs)
                if error_api == True:
                    print(
                        f"{ORANGE}Error {response.status_code} pour l'API de NVD. Impossible de vérifier les CVEs.{NC}\n")

                # Affiche l'OS
                print(
                    f"\nLe système d'exploitation de {GREEN}" + ip_address + f"{NC} est {GREEN}" + sys_name + f".{NC} Fiabilité : {GREEN}" + sys_accuracy + f"%{NC}.\n")

                # Export CSV de la sortie du scan
                print(f"Toolbox/scan >>> Exporter les informations dans un fichier CSV ? (csv/pdf/no)")
                export = input("Toolbox/scan >>> ") or "n"
                if export == "csv":
                    namefile = "scan_actif_" + ip_address
                    export_prettytable(namefile, table)
                elif export == "pdf":
                    namefile = "scan_actif_" + ip_address
                    export_pdf(namefile, table)
                else:
                    print(f"\nVous avez choisi de ne pas exporter les données.\n")
            # Message d'erreur en cas de données incorrectes
            else:
                print(f"\n{ORANGE}Error : Range incorrecte !{NC}\n")
        # Message d'erreur en cas de données incorrectes
        else:
            print(f"\n{ORANGE}Error : La machine est down !{NC}\n")
    # Message d'erreur en cas de données incorrectes
    else:
        print(f"\n{ORANGE}Error : Adresse IP incorrecte !{NC}\n")


### lunch Auto Active Scan ###

def createFileConfig(pathFile):
    try:
        os.mkdir(pathFolderConf)
    except:
        i = 1

    # Création d'un nouveau fichier dans le dossier pour les parametres
    if os.path.isfile(pathFile):
        i = 1
    else:
        initFileConfig(pathFile)


def initFileConfig(pathFile):
    config = configparser.ConfigParser()
    config['DEFAULT'] = {'range_port': '0-1000',
                         'type_scan': '-O -T5',
                         'export': 'pdf'}
    with open(pathFile, 'w') as configfile:
        config.write(configfile)


def modifFileConfig(pathFile, range_port, type_scan, export):
    config = configparser.ConfigParser()
    config['DEFAULT'] = {'range_port': range_port,
                         'type_scan': type_scan,
                         'export': export}
    with open(pathFile, 'w') as configfile:
        config.write(configfile)


def readFileConfig(pathFile, param):
    config = configparser.ConfigParser()
    config.read(pathFile)
    return config['DEFAULT'][param]


def autoscan():
    # Valeur à récuperer dans le fichier de configuration
    ip_address = socket.gethostbyname(socket.gethostname())
    range_port = readFileConfig(pathFileConf, "range_port")
    type_scan = readFileConfig(pathFileConf, "type_scan")
    export = readFileConfig(pathFileConf, "export")

    # Crée un objet nmap.PortScanner pour scanner l'adresse IP
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sn')

    # Modifie les arguments en fonction des ports voulu
    if validate_ports(range_port) or range_port == "":
        if range_port != "":
            range_port = " -p" + range_port

        nmap_arguments = type_scan + range_port
        
        # Execute le scan
        nm.scan(ip_address, arguments=nmap_arguments)

        # Récupère les ports ouverts et leurs informations
        open_ports = nm[ip_address]["tcp"].keys()
        port_info = {}
        for port in open_ports:
            port_info[port] = {
                "service": nm[ip_address]["tcp"][port]["product"],
                "version": nm[ip_address]["tcp"][port]["version"],
                "name": nm[ip_address]["tcp"][port]["name"],
                "cpe": nm[ip_address]["tcp"][port]["cpe"]
            }

        # Récupère les informations sur l'OS
        sys_matches = nm[ip_address]["osmatch"]
        sys_matches.sort(key=lambda x: x['accuracy'], reverse=True)
        sys = sys_matches[0]
        sys_name = sys['name']
        sys_accuracy = sys['accuracy']

        # Créer un dictionnaire avec les données pour le tableau
        data = {'Port': [],
                'Protocole': [],
                'Nom du service': [],
                'Version': [],
                'CVE': [],
                'CVSS': []}

        # Créer le tableau à partir du dictionnaire
        table = pd.DataFrame(data)
        location = 1

        # Permet d'éviter les virgules dans l'affichage des ports
        table["Port"] = table["Port"].astype(int)

        # Ajoute les ports ouverts, leurs informations et les CVE associées dans le tableau
        for port, info in port_info.items():
            error_api = False
            nb_cve = 0
            cvss = ["N/A"]
            name_cve = ["Aucune CVE trouvée"]
            # Vérifie si une donnée CPE est disponible (vulnérabilité) afin d'effectuer une recherche CVE
            if info["cpe"] != "":
                cpe_split = info["cpe"].split(":")
                # Exclu les recherche sur "linux" et sur "windows" afin d'éviter les CVEs inutiles sur le kernel
                if "linux" not in cpe_split:
                    if "windows" not in cpe_split:
                        # Envoyez une requête à l'API de NVD avec le CPE
                        response = requests.get(
                            f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={info["cpe"]}')
                        if response.status_code == 200:
                            # Récupérez la liste des vulnérabilités dans le résultat de la recherche
                            cves = response.json()['result']['CVE_Items']
                            # Pour chaque vulnérabilité, récupère son identifiant et sa description
                            for cve in cves:
                                # Récupère le score CVSS
                                if 'baseMetricV3' in cve['impact']:
                                    cvss_score = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
                                elif 'baseMetricV2' in cve['impact']:
                                    cvss_score = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
                                else:
                                    cvss_score = 0
                                if cvss_score > 7.5:
                                    nb_cve = nb_cve + 1
                                    cvss.append(cvss_score)
                                    cve = cve["cve"]["CVE_data_meta"]["ID"]
                                    # Decommenter la ligne ci dessous si on souhaite avoir les liens des CVEs à la place du numéro de CVE
                                    # cve = "https://nvd.nist.gov/vuln/detail/" + cve
                                    name_cve.append(cve)
                                    # name_cve.append(cve["cve"]["CVE_data_meta"]["ID"])
                                    # Incrémente le tableau avec les informations des ports avec CVE
                                    if nb_cve == 1:
                                        table.loc[location] = [port, info["name"], info["service"],
                                                               info["version"], name_cve[1], cvss[1]]
                                        location = location + 1
                                    else:
                                        # Si plusieurs CVE, ajoute l'un après l'autre
                                        for i in range(1, nb_cve):
                                            table.loc[location] = ["-", "-", "-", "-", name_cve[i + 1],
                                                                   cvss[i + 1]]
                                            location = location + 1
                        else:
                            error_api = True
            else:
                # Incrémente le tableau avec les informations des ports sans CVE
                table.loc[location] = [port, info["name"], info["service"], info["version"], name_cve[0],
                                       cvss[0]]
                location = location + 1

        # Affiche un message en cas d'erreur pour l'API de NVD (check CVEs)
        if error_api == True:
            print(
                f"{ORANGE}Error {response.status_code} pour l'API de NVD. Impossible de vérifier les CVEs.{NC}\n")

        from datetime import datetime
        dt_string = datetime.now().strftime("%d-%m-%Y")

        namefile = os.path.join(pathFolderConf, "autoscan_" + dt_string + "_" + ip_address)

        if export == "csv":
            export_prettytable(namefile, table)
        elif export == "pdf":
            export_pdf(namefile, table)
        else:
            print(f"\nVous avez choisi de ne pas exporter les données.\n")
    # Message d'erreur en cas de données incorrectes
    else:
        print(f"\n{ORANGE}Error : Range incorrecte !{NC}\n")


def writeAutoscan(reWrite):

    print(f"Toolbox/autoscan >>> Création de la tâche planifiée")
    type_scan = ""
    export = ""
    time = ""

    print(f"Toolbox/autoscan >>> Saisir la range des ports. Exemple -> 0-49151 (default is top 1000 ports used)")
    range_port = input("Toolbox/autoscan >>> ") or ""
    # Modifie les arguments en fonction des ports voulu
    if validate_ports(range_port) or range_port == "":
        # Modifie le type de scan
        print(scan_type + f"\nToolbox/autoscan >>> Choisir le type de scan (default is 2)")
        scan_choice = input("Toolbox/autoscan >>> ") or "2"
        match scan_choice:
            case '1':
                type_scan = "-O -T5"
            case '2':
                type_scan = "-A -T5"
            case '3':
                type_scan = "-A -T4"

        # Export CSV de la sortie du scan
        print(f"Toolbox/autoscan >>> Exporter les informations dans un fichier CSV ? (csv/pdf)")
        export = input("Toolbox/autoscan >>> ") or "pdf"

        isChecked = 0
        while isChecked == 0:
            # Demande de l'heure
            print(f"Toolbox/autoscan >>> Indiquer l'heure de programmation pour la tâche (Sous la forme {ORANGE}hh:mm:ss{NC})")
            time = input("Toolbox/autoscan >>> ") or "10:10:10"
            if (check_time_format(time)):
                isChecked = 1

    # Message d'erreur en cas de données incorrectes
    else:
        print(f"\n{ORANGE}Error : Range incorrecte !{NC}\n")

    print(f"Toolbox/autoscan >>> Copie du script en local et création d'un dossier dédié\n{GREEN}")
    createFileConfig(pathFileConf)
    cpFileScript(1)
    modifFileConfig(pathFileConf, range_port, type_scan, export)
    print(f"{NC}")

    if reWrite == 1:
        deleteTask()

    return time

def deleteTask():
    try:
        if platform.system() == "Windows":
            subprocess.call('schtasks /delete /tn "' + name_task + '" /f', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\nTâche Windows supprimée avec succès.\n")
        elif platform.system() == "Linux":
            os.system('crontab -l | grep -v "' + newPathFileScript + ' ' + Param + '" | crontab -')
            print(f"\nTâche Linux supprimée avec succès.\n")
        else:
            print(f"\nOS non supporté.\n")
    except:
        print(f"\nErreur lors de la suppression de la tâche planifiée.\n")

def createTask():

    if platform.system() == "Windows":

        commande = 'schtasks /query /tn "' + name_task + '"'  # votre commande cmd à exécuter

        output = subprocess.run(commande, capture_output=True).stdout.decode(errors='replace')

        if output.strip() != "":
            # Si la tâche est présente, demande un choix à l'user
            print(autoscan_type + f"\nToolbox/autoscan >>> Faite votre choix (Par default : 3")
            autoscan_choice = input("Toolbox/autoscan >>> ") or "3"
            match autoscan_choice:
                case '1':
                    # Modifier
                    try:
                        timeSchuduler = writeAutoscan(1)
                        os.system('schtasks /create /sc daily /tn "' + name_task + '" /tr "powershell py ' + newPathFileScript + '  ' + Param + '" /st ' + timeSchuduler + '')
                        print("")
                    except:
                        print(f"\nErreur lors de la création de la tâche planifiée.\n")
                case '2':
                    cpFileScript(0)
                    deleteTask()
        else:
            try:
                timeSchuduler = writeAutoscan(0)
                os.system('schtasks /create /sc daily /tn "' + name_task + '" /tr "powershell py ' + newPathFileScript + '  ' + Param + '" /st ' + timeSchuduler + '')
                print("")
            except:
                print(f"\nErreur lors de la création de la tâche planifiée.\n")


    elif platform.system() == "Linux":
        output = subprocess.run('crontab -l | grep "' + newPathFileScript + '  ' + Param + '"', capture_output=True).stdout.decode(errors='replace')
        if output.strip() != "":
            # Si la tâche est présente, demande un choix à l'user
            print(autoscan_type + f"\nToolbox/autoscan >>> Faite votre choix (Par default : 3)")
            autoscan_choice = input("Toolbox/autoscan >>> ") or "3"
            match autoscan_choice:
                case '1':
                    # Modifier
                    try:
                        # Sous Linux, on utilise `crontab` pour créer une tâche planifiéee
                        timeSchuduler = writeAutoscan(1)
                        os.system('(crontab -l ; echo "' + convert_to_crontab_time(timeSchuduler) + ' py ' + newPathFileScript + '  ' + Param + '") | sort - | uniq - | crontab -')
                        print(f"\nCréation de la tâche Linux avec succès.\n")
                    except:
                        print(f"\nErreur lors de la création de la tâche planifiée.\n")
                case '2':
                    # Supprimer
                    cpFileScript(0)
                    deleteTask()
        else:
            print("La tâche n'existe pas.")
            try:
                # Sous Linux, on utilise `crontab` pour créer une tâche planifiéee
                timeSchuduler = writeAutoscan(0)
                os.system('(crontab -l ; echo "' + convert_to_crontab_time(timeSchuduler) + ' py ' + newPathFileScript + '  ' + Param + '") | sort - | uniq - | crontab -')
                print(f"\nCréation de la tâche Linux avec succès.\n")
            except:
                print(f"\nErreur lors de la création de la tâche planifiée.\n")

    else:
        print(f"\nOS non supporté.\n")

def cpFileScript(state):
    if state == 1:
        print(cheminCompletFichier)
        print(pathFolderConf)
        shutil.copy(os.path.realpath(__file__), os.path.join(pathFolderConf, ""))
    else:
        shutil.rmtree(pathFolderConf)

### Reconnaissance ###

def recon():
    system = platform.system()

    if system == "Linux":
        # Exécute la commande "ip route" pour récupérer l'adresse IP et le masque de sous-réseau
        output = subprocess.run(["ip", "route"], capture_output=True).stdout.decode(errors='replace')
        lines = output.split("\n")
        for line in lines:
            if "link" in line:
                # Sépare l'adresse IP et le masque de sous-réseau
                parts = line.split()
                network = parts[0]
                subnet = network.strip().split('/')
                ip_address = subnet[0]
                mask = subnet[1]
                print(f"\nAdresse réseau : {network}")
                break

    elif system == "Windows":
        # Exécute la commande "ipconfig" pour récupérer l'adresse IP et le masque de sous-réseau
        # Voir pour utiliser la commande route print pour être sur de l'IP
        output = subprocess.run(["ipconfig"], capture_output=True).stdout.decode(errors='replace')
        lines = output.split("\n")
        for line in lines:
            if "IPv4" in line:
                # Sépare l'adresse IP
                parts = line.split()
                ip_address = parts[-1]
            if "Masque" in line:
                # Sépare le masque de sous-réseau
                parts = line.split()
                subnet_mask = parts[-1]

        # Déterminer le réseau à partir de l'adresse IP et du masque de sous-réseau
        mask = IPAddress(subnet_mask).netmask_bits()
        ip_network = ipaddress.IPv4Network(f'{ip_address}/{mask}', strict=False)
        ip_network = str(ip_network.network_address)
        network = str(ip_network) + "/" + str(mask)

        # Affiche le réseau concerné
        print(f"\nAdresse réseau : {ip_network}")
        print(f"Masque de sous-réseau : {subnet_mask}")

    else:
        print("Système d'exploitation non supporté.")
        return

    # Ajoute le message comme variable global
    global message_charg
    message_charg = "Scan du réseau " + network + " en cours"

    # Execute le chargement en attendant la fin du scan
    global stop_thread
    stop_thread = False
    t = threading.Thread(target=loading)
    t.start()

    # Utiliser nmap pour effectuer un scan du réseau
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-O -T5 -F')

    # Créer un dictionnaire avec les données pour le tableau
    data = {'IP': [],
            'Hostname': [],
            'Système d\'exploitation': []}

    # Créer le tableau à partir du dictionnaire
    table = pd.DataFrame(data)
    location = 1

    # Pour chaque hôte détecté
    for host in nm.all_hosts():
        # On récupère le hostname
        hostname = nm[host].hostname()
        osmatch_list = sorted(nm[host]['osmatch'], key=lambda x: x['accuracy'], reverse=True)
        # On récupère le système d'exploitation
        for osmatch in osmatch_list[:1]:
            os = osmatch['name'] + " (" + str(osmatch['accuracy']) + "%)"
        # On ajoute les données dans le tableau
        table.loc[location] = [host, hostname, os]
        location = location + 1

    # Créer une instance de la classe PrettyTable pour formater le tableau pandas
    pt = PrettyTable()
    pt.field_names = table.columns
    for row in table.itertuples():
        pt.add_row(row[1:])
    pt.align = 'c'

    # Stop le chargement
    stop_thread = True
    t.join()

    # Affiche le tableau avec les données du scan
    print(f"La reconnaissance du réseau {GREEN}" + network + f"{NC} donne les informations suivantes :\n")
    print(pt)

    print(f"\nToolbox/reconnaissance >>> Exporter les informations dans un fichier CSV ? (csv/pdf/no)")
    export = input(f"Toolbox/reconnaissance >>> ") or "n"
    # Export CSV de la sortie du scan
    if export == "csv":
        namefile = "reconnaissance_" + str(ip_address) + "-" + str(mask)
        export_prettytable(namefile, table)
    elif export == "pdf":
        namefile = "reconnaissance_" + str(ip_address) + "-" + str(mask)
        export_pdf(namefile, table)
    else:
        print(f"\nVous avez choisi de ne pas exporter les données.\n")


### WIKI CVSS ###

def cvss():
    # URL de l'API NVD
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Demander à l'utilisateur le score minimum voulu
    print(f"Toolbox/cvss >>> Entrez le score minimum pour votre recherche (entre 0 et 10)")
    score_min = float(input("Toolbox/cvss >>> "))

    # Demander à l'utilisateur l'intervalle de temps depuis la publication de la CVE
    print(f"Toolbox/cvss >>> Depuis combien de temps en jours pour la publication des CVE (30 jours max)")
    interval = int(input("Toolbox/cvss >>> "))
    if interval > 30:
        print(f"\n{ORANGE}Error : 30 jours maximum !{NC}\n")
        return

    # Calculer la date limite correspondant à l'intervalle de temps donné
    limit_date = datetime.datetime.now() - datetime.timedelta(days=interval)

    # Formater la date limite sous forme de chaîne de caractères pour l'inclure dans la requête API
    start_date = limit_date.strftime("%Y-%m-%dT%H:%M:%SZ")

    date = datetime.datetime.now()
    end_date = date.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Effectuer la requête API avec les paramètres donnés
    response = requests.get(url, params={"resultsPerPage": 2000, "pubStartDate": start_date, "pubEndDate": end_date})

    # vérifie si la requête a réussi
    if response.status_code == 200:
        # Créer un dictionnaire avec les données pour le tableau
        data_table = {'Date de publication': [],
                      'CVE': [],
                      'CVSS': [],
                      'Liens': []
                      }
        # Créer le tableau à partir du dictionnaire
        table = pd.DataFrame(data_table)
        location = 1
        data = response.json()
        counter = 0
        for cve in data['vulnerabilities']:
            counter += 1
            cve_id = cve["cve"]["id"]
            date_pub = cve['cve']['published']
            date_pub = parse(date_pub)
            date_pub = date_pub.strftime('%d %B %Y, %H:%M:%S')
            # value = cve["cve"]["descriptions"]
            # description = value[0]['value']
            # vérifie si le score basemetricV3 existe
            if "cvssMetricV31" in cve["cve"]["metrics"]:
                score = cve["cve"]["metrics"]["cvssMetricV31"]
                cvss_data = score[0]['cvssData']
                base_score = float(cvss_data['baseScore'])
            elif "cvssMetricV3" in cve["cve"]["metrics"]:
                score = cve["cve"]["metrics"]["cvssMetricV3"]
                cvss_data = score[0]['cvssData']
                base_score = float(cvss_data['baseScore'])
            elif "cvssMetricV2" in cve["cve"]["metrics"]:
                score = cve["cve"]["metrics"]["cvssMetricV2"]
                cvss_data = score[0]['cvssData']
                base_score = float(cvss_data['baseScore'])
            else:
                score = "none"
            if score != "none":
                if base_score >= score_min:
                    link = "https://nvd.nist.gov/vuln/detail/" + cve_id
                    table.loc[location] = [date_pub, cve_id, base_score, link]
                    location = location + 1

        # Créer une instance de la classe PrettyTable pour formater le tableau pandas
        pt = PrettyTable()
        pt.field_names = table.columns
        for row in table.itertuples():
            pt.add_row(row[1:])
        pt.align = 'c'

        # Affiche le tableau avec les données du scan
        print(f"\nLa recherche des CVEs pour le score de {GREEN}" + str(score_min) + f"{NC} depuis {GREEN}" + str(
            interval) + f"{NC} jours donne les informations suivantes :\n")
        print(pt)

        print(f"\nToolbox/cvss >>> Exporter les informations dans un fichier CSV ? (csv/pdf/no)")
        export = input(f"Toolbox/cvss >>> ") or "n"
        # Export CSV de la sortie du scan
        if export == "csv":
            namefile = "cvss_" + str(score_min) + "-" + str(interval) + "j"
            export_prettytable(namefile, table)
        elif export == "pdf":
            namefile = "cvss_" + str(score_min) + "-" + str(interval) + "j"
            export_pdf(namefile, table)
        else:
            print(f"\nVous avez choisi de ne pas exporter les données.\n")
    else:
        print("La requête a échoué avec le code d'erreur", response.status_code)


### DORKS ###

def dorks():
    # Créer un dictionnaire avec les données pour le tableau
    data = {'Site': [],
            'URLs': []}

    # Créer le tableau à partir du dictionnaire
    table = pd.DataFrame(data)

    print(f"Toolbox/dorks >>> Saisir un nom de domaine (example.com)")
    domain = input("Toolbox/dorks >>> ")
    if not "." in domain:
        print(f"\n{ORANGE}Domaine invalide !{NC}\n")
        return

    print(dorks_type)

    print(f"Toolbox/dorks >>> Saisir votre choix (default is 1)")
    choice = input("Toolbox/dorks >>> ") or "1"
    choice = int(choice)
    if choice < 1 or choice > 5:
        print(f"\n{ORANGE}Choix invalide !{NC}\n")
        return

    if choice == 1:
        query = "site:" + domain + " inurl:admin"
    elif choice == 2:
        query = "site:" + domain + " inurl:login"
    elif choice == 3:
        query = "site:" + domain + " filetype:pdf sensitive"
    elif choice == 4:
        query = "site:" + domain + " intitle:index.of \"Parent Directory\" -inurl:html -inurl:htm -inurl:php"
    elif choice == 5:
        print(f"Toolbox/dorks >>> Choisir un type de fichier (pdf, doc, xls, ...)")
        file_type = input("Toolbox/dorks >>> ")
        if not file_type:
            print(f"\n{ORANGE}Le type de fichier ne peut pas être vide !{NC}\n")
            return
        query = "site:" + domain + " filetype:" + file_type

    # Ajoute le message comme variable global
    global message_charg
    message_charg = "Recherche google dorks en cours"

    # Execute le chargement en attendant la fin du scan
    global stop_thread
    stop_thread = False
    t = threading.Thread(target=loading)
    t.start()

    print(f"\nRequête google dorks : {GREEN}" + query + f"{NC}")
    counter = 0
    requ = 0
    for results in googlesearch.search(query, tld="com", lang="en", num=int(20), start=0, stop=None, pause=2):
        counter = counter + 1
        table.loc[counter] = [counter, results]
        time.sleep(0.2)
        requ += 1
        if requ >= int(20):
            break

    # Créer une instance de la classe PrettyTable pour formater le tableau pandas
    pt = PrettyTable()
    pt.field_names = table.columns
    for row in table.itertuples():
        pt.add_row(row[1:])
    pt.align = 'c'

    # Stop le chargement
    stop_thread = True
    t.join()

    # Affiche le tableau avec les données du google dorks
    print(f"La recherche Google Dorks donne les informations suivantes :\n")
    print(pt)

    print(f"\nToolbox/dorks >>> Exporter les informations dans un fichier CSV ? (csv/pdf/no)")
    export = input(f"Toolbox/dorks >>> ") or "n"
    # Export CSV de la sortie recherche google dorks
    if export == "csv":
        namefile = "dorks_" + str(domain)
        export_prettytable(namefile, table)
    elif export == "pdf":
        namefile = "dorks_" + str(domain)
        export_pdf(namefile, table)
    else:
        print(f"\nVous avez choisi de ne pas exporter les données.\n")


#### Main script ####

try:
    if sys.argv[1] == "autoscan":
        autoscan()
    else:
        print(f"\n{ORANGE}Le parametre entré est incorrect !{NC}\n")
except:
    print(flag)
    print("\nUtiliser l'option \"help\" pour avoir plus d'informations sur les commandes.\n")

    while again == "true":
        # Choix de l'option
        option = input("Toolbox >>> ")

        # Action en fonction de l'option
        match option:
            case 'help' | '?':
                print(help)
            case 'recon':
                recon()
            case 'scan':
                active_scan()
            case 'CVSS' | 'cvss':
                cvss()
            case 'dorks':
                dorks()
            case 'autoscan':
                createTask()
            case 'clear' | 'ci':
                os.system('cls' if os.name == 'nt' else 'clear')
            case 'exit' | 'quit' | 'end':
                print(f"\n{GREEN}Aurevoir, à bientot !{NC}\n")
                break
            case '':
                pass
            case other:
                print("\nCommande inconnue...\n")
