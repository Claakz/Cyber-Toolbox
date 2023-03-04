"""
import requests
import datetime

# URL de l'API NVD
url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

# Demander à l'utilisateur le score minimum voulu
score_min = float(input("Entrez le score minimum voulu : "))

# Demander à l'utilisateur l'intervalle de temps depuis la publication de la CVE
interval = int(input("Entrez l'intervalle de temps en jours depuis la publication de la CVE : "))

# Calculer la date limite correspondant à l'intervalle de temps donné
limit_date = datetime.datetime.now() - datetime.timedelta(days=interval)

# Formater la date limite sous forme de chaîne de caractères pour l'inclure dans la requête API
limit_date_str = limit_date.strftime("%Y-%m-%d")

print(limit_date_str)

# Effectuer la requête API avec les paramètres donnés
response = requests.get(url, params={'start': limit_date_str})

# Vérifier que la réponse est valide
if response.status_code == 200:
    # Décoder le contenu de la réponse
    data = response.json()

    # Afficher les informations de chaque CVE retournée
    for cve in data['result']['CVE_Items']:
        baseScore = cve['baseScore']
        if 'baseMetricV3' in baseScore:
            score = baseScore['baseMetricV3']['cvssV3']['baseScore']
        elif 'baseMetricV2' in baseScore:
            score = baseScore['baseMetricV2']['cvssV2']['baseScore']
        else:
            score = 0
        if score >= score_min:
            pass
        print("- CVE :", cve['cve']['CVE_data_meta']['ID'])
        print("  Score :", score)
        print("  Date de publication :", cve['publishedDate'])
else:
    # Afficher un message d'erreur si la réponse n'est pas valide
    print("La requête API a échoué avec le code d'erreur", response.status_code)
"""

import requests
import json
import datetime

# URL de l'API NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Demander à l'utilisateur le score minimum voulu
score_min = float(input("Entrez le score minimum voulu : "))

# Demander à l'utilisateur l'intervalle de temps depuis la publication de la CVE
interval = int(input("Entrez l'intervalle de temps en jours depuis la publication de la CVE : "))

# Calculer la date limite correspondant à l'intervalle de temps donné
limit_date = datetime.datetime.now() - datetime.timedelta(days=interval)

# Formater la date limite sous forme de chaîne de caractères pour l'inclure dans la requête API
start_date = limit_date.strftime("%Y-%m-%dT%H:%M:%SZ")

date = datetime.datetime.now()
end_date = date.strftime("%Y-%m-%dT%H:%M:%SZ")

print(start_date)

# Effectuer la requête API avec les paramètres donnés
response = requests.get(url, params={"resultsPerPage": 2000, "pubStartDate": start_date, "pubEndDate": end_date})

# vérifie si la requête a réussi
if response.status_code == 200:
    data = response.json()
    counter = 0
    for cve in data['vulnerabilities']:
        counter += 1
        cve_id = cve["cve"]["id"]
        print(cve_id)
        date_pub = cve['cve']['published']
        print(date_pub)

        # vérifie si le score basemetricV3 existe
        if "cvssMetricV31" in cve["cve"]["metrics"]:
            score = cve["cve"]["metrics"]["cvssMetricV31"]
            
            print(base_scores)
            print("CVE ID:", cve_id, "| Score:", base_score,"| Date:", cve['cve']['published'])
            break
        elif "cvssMetricV3" in cve["cve"]["metrics"]:
            score = cve["cve"]["metrics"]["cvssMetricV3"]["cvssData"]["baseScore"]
            print("CVE ID:", cve_id, "| Score:", score,"| Date:", cve['cve']['published'])
        elif "cvssMetricV2" in cve["cve"]["metrics"]:
            score = cve["cve"]["metrics"]["cvssMetricV2"]["cvssData"]["baseScore"]
        else:
            score = "none"
        if score != "none":
            print("CVE ID:", cve_id, "| Score: ", score,"| Date:", cve['cve']['published'])
else:
    print("La requête a échoué avec le code d'erreur", response.status_code)
    