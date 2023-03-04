#!/usr/bin/env python

# Importe les bibliothèques nécessaires
import ipaddress
import re
import time
import nmap
import requests
import os
import platform
import subprocess
import threading
import googlesearch
import pandas as pd
from netaddr import IPAddress
from prettytable import PrettyTable

# Permet d'avoir des couleurs
from colorama import init
init()

#### Flag ####

flag="""

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

again="true"
ORANGE='\033[0;33m' # Orange for print
GREEN='\033[0;92m' # Green for print
NC='\033[0m' # No Color for print

#### Menus ####

help = """
      Commandes      |                 Descriptions                    
=============================================================================
        help         |     Affiche le menu d'aide contextuel
        recon        |     Effectue une reconnaisance du réseau
        scan         |     Effectue un scan actif sur une IP
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

dorks_type="""
    Commandes   |                      Descriptions                    
=============================================================================
        1       |      Recherche une page admin
        2       |      Recherche une page d'authentification
        3       |      Recherche un document sensible de type pdf
        4       |      Recherche une vulnérabilité sur le site web
        5       |      Recherche un type de fichier spécifique sur le site
"""

#### Fonctions ####

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
        if int(part) < 0 or int(part) > 49151 :
            return False

    return True

def export_prettytable(namefile,table):
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
        print(f"\nLe fichier{GREEN} {file} {NC}est maintenant disponible dans le dossier {GREEN}" + os.getcwd() + f"{NC}.\n")

def loading():
        frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        print("")
        while not stop_thread:
                for frame in frames:
                        time.sleep(0.1)
                        print(f"{message_charg} {frame}", end='\r')

### Active Scan ###

def active_scan():
        
        print(f"Toolbox/scan >>> Saisir l\'adresse IP de la machine cible")
        ip_address = input(f"Toolbox/scan >>> ")

        # Vérifie si l'entrée est une IP
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
                                nm.scan(ip_address, arguments = nmap_arguments)

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
                                                                response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={info["cpe"]}')
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
                                                                                        cvss_score=0
                                                                                if cvss_score > 7.5:
                                                                                        nb_cve = nb_cve + 1
                                                                                        cvss.append(cvss_score)
                                                                                        cve = cve["cve"]["CVE_data_meta"]["ID"]
                                                                                        cve = "https://nvd.nist.gov/vuln/detail/" + cve
                                                                                        name_cve.append(cve)
                                                                                        #name_cve.append(cve["cve"]["CVE_data_meta"]["ID"])
                                                                                        # Incrémente le tableau avec les informations des ports avec CVE
                                                                                        if nb_cve == 1:
                                                                                                table.loc[location] = [port, info["name"], info["service"], info["version"], name_cve[1], cvss[1]]
                                                                                                location = location + 1
                                                                                        else:
                                                                                                # Si plusieurs CVE, ajoute l'un après l'autre
                                                                                                for i in range(1, nb_cve):
                                                                                                        table.loc[location] = ["--", "--", "--", "--", name_cve[i+1], cvss[i+1]]
                                                                                                        location = location + 1
                                                                else:
                                                                        error_api = True
                                        else:
                                                # Incrémente le tableau avec les informations des ports sans CVE
                                                table.loc[location] = [port, info["name"], info["service"], info["version"], name_cve[0], cvss[0]]
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
                                        print(f"{ORANGE}Error {response.status_code} pour l'API de NVD. Impossible de vérifier les CVEs.{NC}\n")
                                
                                # Affiche l'OS
                                print(f"\nLe système d'exploitation de {GREEN}" + ip_address + f"{NC} est {GREEN}"+ sys_name + f".{NC} Fiabilité : {GREEN}" + sys_accuracy + f"%{NC}.\n")

                                # Export CSV de la sortie du scan
                                print(f"Toolbox/scan >>> Exporter les informations dans un fichier CSV ? (y/n)")
                                export = input("Toolbox/scan >>> ") or "n"
                                if export == "y" or export == "Y":
                                        namefile = "scan_actif_" + ip_address
                                        export_prettytable(namefile,table)
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

### Reconnaissance ###

def reconnaissance():

        system = platform.system()

        if system == "Linux":
                # Exécute la commande "ip route" pour récupérer l'adresse IP et le masque de sous-réseau
                output = subprocess.run(["ip", "route"], capture_output=True).stdout.decode(errors='replace')
                lines = output.split("\n")
                for line in lines:
                        if "src" in line:
                                # Sépare l'adresse IP et le masque de sous-réseau
                                parts = line.split()
                                network = parts[0]
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

        print(f"\nToolbox/reconnaissance >>> Exporter les informations dans un fichier CSV ? (y/n)")
        export = input(f"Toolbox/reconnaissance >>> ") or "n"
        # Export CSV de la sortie du scan
        if export == "y" or export == "Y":
                namefile = "reconnaissance_" + str(ip_address) + "-" + str(mask)
                export_prettytable(namefile,table)
        else:
                print(f"\nVous avez choisi de ne pas exporter les données.\n")

### WIKI CVSS ###

def cvss():
        print("WIKI CVSS")

### WIKI CVSS ###

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
        counter=0
        requ=0
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

        print(f"\nToolbox/dorks >>> Exporter les informations dans un fichier CSV ? (y/n)")
        export = input(f"Toolbox/dorks >>> ") or "n"
        # Export CSV de la sortie recherche google dorks
        if export == "y" or export == "Y":
                namefile = "dorks_" + str(domain)
                export_prettytable(namefile,table)
        else:
                print(f"\nVous avez choisi de ne pas exporter les données.\n")

#### Main script ####

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
                        reconnaissance()
                case 'scan':
                        active_scan()
                case 'CVSS' | 'cvss':
                        cvss()       
                case 'dorks':
                        dorks()
                case 'clear':
                        os.system('cls' if os.name == 'nt' else 'clear')
                case 'exit' | 'quit' | 'end':
                        break
                case '':
                        pass
                case other:
                        print("\nCommande inconnue...\n")