# Cyber-Toolbox

La Cyber-Toolbox est une boîte à outils qui regroupe plusieurs outils pour aider dans la reconnaissance et la recherche de vulnérabilités sur un réseau.

# Installation

Pour utiliser la "Cyber-Toolbox", il est necessaire d'installer :

* Python 3.x
* Nmap

Ci-dessous, les étapes en fonction de l'OS.

### Prérequis : Linux

Installation des prérequis pour utiliser la Cyber-Toolbox sur Linux :

* Python 3.x : peut être installé en utilisant la commande suivante :

    ```bash
    sudo apt-get update
    sudo apt-get install python3

* Nmap : peut être installé en utilisant la commande suivante :

    ```bash
    sudo apt-get install nmap

### Prérequis : Windows

Installation des prérequis pour utiliser la Cyber-Toolbox sur Windows :

* Python 3.x : peut être téléchargé à partir du site web officiel Python à l'adresse suivante :

  ```bash
  https://www.python.org/downloads/windows/
  
* Nmap : peut être téléchargé à partir du site web officiel Nmap à l'adresse suivante :

    ```bash
    https://nmap.org/download.html#windows

<br>

### Cyber-Toolbox : Linux

<br>

1. Ouvrir un terminal
2. Cloner le dépôt GitHub avec la commande suivante :

    ```bash
    git clone https://github.com/username/Cyber-Toolbox.git

3. Se rendre dans le dossier Cyber-Toolbox avec la commande :

    ```bash
    cd Cyber-Toolbox
    
4. Installer les dépendances nécessaires avec la commande suivante :

    ```bash
    pip install -r requirements.txt
    
### Cyber-Toolbox : Windows

1. Télécharger le dépôt GitHub en cliquant sur le bouton "Download ZIP".
2. Extraire le fichier ZIP.
3. Ouvrir un invite de commande.
4. Se rendre dans le dossier Cyber-Toolbox avec la commande suivante :

    ```cmd
    cd C:\chemin\vers\Cyber-Toolbox
    
Installer les dépendances nécessaires avec la commande suivante :

    ```cmd
    pip install -r requirements.txt
    
## Utilisation de la toolbox

La Cyber-Toolbox propose plusieurs options pour effectuer des actions sur un réseau. Voici la liste des commandes disponibles :

* `help`: Affiche le menu d'aide contextuel
* `recon`: Effectue une reconnaissance du réseau
* `scan`: Effectue un scan actif sur une adresse IP
* `cvss`: Effectue une recherche en fonction du CVSS
* `dorks`: Effectue une recherche de dorks sur un domaine
* `clear`: Efface l'invite de commande
* `exit`: Permet de quitter le script

Pour lancer une commande, il suffit de taper la commande dans l'invite de commande et d'appuyer sur Entrée. Par exemple, pour lancer la commande d'aide, tapez :

    ```bash
    help

Contribution

Toute contribution à l'amélioration de cette Cyber-Toolbox est la bienvenue. Si vous trouvez des bugs ou si vous souhaitez ajouter une fonctionnalité, n'hésitez pas à créer une Pull Request.

Licence

Ce projet est sous licence MIT. Veuillez consulter le fichier LICENSE pour plus d'informations.
