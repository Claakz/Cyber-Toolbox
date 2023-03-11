# 🛡️ Toolbox cybersécurité - Purple Team 🛡️

![image](https://user-images.githubusercontent.com/118543986/224441814-d50ca187-66a7-46cb-8eb4-45bb616af9cb.png)

La **Cyber-Toolbox** est une boîte à outils qui regroupe plusieurs outils pour aider dans la reconnaissance et la recherche de vulnérabilités sur un réseau.

# Installation

Pour utiliser la **Cyber-Toolbox**, il est necessaire d'installer :

* **Python 3.x**
* **Nmap**

Ci-dessous, les étapes en fonction de l'OS.

## Prérequis : Linux

Installation des prérequis pour utiliser la **Cyber-Toolbox** sur **Linux** :

* **Python 3.x** : peut être installé en utilisant la commande suivante :

    ```bash
    sudo apt-get update
    sudo apt-get install python3

* **Nmap** : peut être installé en utilisant la commande suivante :

    ```bash
    sudo apt-get install nmap

## Prérequis : Windows

Installation des prérequis pour utiliser la **Cyber-Toolbox** sur **Windows** :

* **Python 3.x** : peut être téléchargé à partir du site web officiel Python à l'adresse suivante :

    [Téléchargement de "Python3.x"](https://www.python.org/downloads/windows/)
    
❗❗❗❗  Attention, il faut selectionner **"Add python.exe to PATH"** lors de l'installation de **Python**  ❗❗❗❗
  
* **Nmap** : peut être téléchargé à partir du site web officiel Nmap à l'adresse suivante **(utiliser la version 7.92, il y a un bug dans la 7.93)** :

    [Téléchargement de "Nmap"](https://nmap.org/download.html#windows)
    

## Cyber-Toolbox : Linux

1. Ouvrir un terminal
2. Cloner le dépôt GitHub avec la commande suivante :

    ```bash
    git clone https://github.com/Claakz/Cyber-Toolbox

3. Se rendre dans le dossier **Cyber-Toolbox** avec la commande :

    ```bash
    cd Cyber-Toolbox
    
4. Installer les dépendances nécessaires avec la commande suivante :

    ```bash
    pip install -r requirements.txt
    
## Cyber-Toolbox : Windows

1. Télécharger le dépôt GitHub en cliquant sur le bouton "Download ZIP".
2. Extraire le fichier ZIP.
3. Ouvrir un invite de commande.
4. Se rendre dans le dossier **Cyber-Toolbox** avec la commande suivante :

    ```cmd
    cd C:\chemin\vers\Cyber-Toolbox
    
Installer les dépendances nécessaires avec la commande suivante :

    pip install -r requirements.txt
    
# Commandes de la toolbox

La **Cyber-Toolbox** propose plusieurs options pour effectuer des actions sur un réseau. Voici la liste des commandes disponibles :

* `help`: Affiche le menu d'aide contextuel
* `recon`: Effectue une reconnaissance du réseau
* `scan`: Effectue un scan actif sur une adresse IP
* `autoscan`: Ajoute un scan en tâche planifiée qui effectue un scan quotidien
* `cvss`: Effectue une recherche en fonction du CVSS
* `dorks`: Effectue une recherche de dorks sur un domaine
* `clear`: Efface l'invite de commande
* `exit`: Permet de quitter le script

Pour lancer une commande, il suffit de taper la commande dans l'invite de commande et d'appuyer sur Entrée. Par exemple, pour lancer la commande d'aide, tapez :

    help



# Utilisation de la toolbox

Il existe une **vidéo complète** de quelque minutes permettant de comprendre le fonctionnement de **manière détaillé** :

<br>

[Lien pour la vidéo youtube sur la "Cyber-Toolbox"](https://www.youtube.com/watch?v=Zw7UzdesU3E)

<br>

Sinon, voici un **exemple rapide** de chaque fonctionnalité sous Windows (le fonctionnement est similaire sur Linux) :

### Commandes - help
<br>

![help](https://user-images.githubusercontent.com/118543986/224515232-35fab2c1-dd75-43b0-b2cc-06c54bd94309.gif)

<br>

### Reconnaissance - recon
<br>
<br>

![recon](https://user-images.githubusercontent.com/118543986/224475465-d75ee334-4699-42a8-9428-0ffe84e597dc.gif)

<br>

### Scan actif - scan
<br>
<br>

**Dans le cadre de la démonstration, la durée du scan est réduite (environ 2-3 minutes).**

![scan](https://user-images.githubusercontent.com/118543986/224515698-50f1a23f-720e-414c-bb83-c71fb3cfc9f7.gif)

<br>

### Scan en tâche planifiée - autoscan
<br>
<br>

![autoscan](https://user-images.githubusercontent.com/118543986/224516531-d8c9b17c-0d6e-4b0f-9d74-8ba163197f25.gif)

### Wiki CVSS - cvss
<br>
<br>

GIF

<br>

### Requête google dorks - dorks
<br>
<br>

GIF

<br>

### Effacer l'invité de commande - clear
<br>
<br>

![clear](https://user-images.githubusercontent.com/118543986/224516822-a0186d0a-296c-45ec-89d4-b3049f84757b.gif)

<br>

### Quitter - exit
<br>
<br>

![exit](https://user-images.githubusercontent.com/118543986/224516672-ad7c2cbd-fd8c-4771-b7e3-5020e971cd97.gif)

<br>

# Contribution

Toute contribution à l'amélioration de cette **Cyber-Toolbox** est la bienvenue. Si vous trouvez des bugs ou si vous souhaitez ajouter une fonctionnalité, n'hésitez pas à créer une Pull Request.

# Licence

Ce projet est sous licence **GNU General Public License v3.0**. Veuillez consulter le fichier LICENSE pour plus d'informations.
