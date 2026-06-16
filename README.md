# TP PoC Crypto, Sujet 10, Zero-Knowledge Proof avec Schnorr

## Auteur

Mohammed FRIOUICHEN - M2 AL

## Sujet choisi

**Sujet 10, Implémentation d'un protocole d'authentification Zero-Knowledge**

L'objectif de cette preuve de concept est d'implémenter le protocole de Schnorr, puis de montrer les propriétés et limites attendues dans le sujet :

- authentification interactive entre Alice et Bob via socket local ;
- version non interactive avec transformation de Fiat-Shamir ;
- rejet d'une preuve réutilisée sur un message modifié ;
- simulation d'un transcript valide sans connaître la clé privée ;
- récupération de la clé privée en cas de réutilisation du nonce `r`.

## Contenu du dépôt

```txt
.
├── common.py            # Paramètres publics, fonctions de groupe, JSON socket
├── generate_keys.py     # Génération de la clé privée d'Alice et de la clé publique
├── bob.py               # Programme Bob, vérificateur interactif via socket
├── alice.py             # Programme Alice, prouveur interactif via socket
├── fiat_shamir.py       # Version non interactive, signer et vérifier une preuve
├── attacks.py           # Rejeu, simulation, récupération de clé si nonce réutilisé
├── README.md            # Documentation et analyse
├── .gitignore
└── LICENSE
```

## Prérequis

- Python 3.10 ou supérieur
- Aucune dépendance externe

Vérifier la version de Python :

```bash
python --version
```

## Installation

Cloner le dépôt, puis se placer dans le dossier du projet :

```bash
git clone https://github.com/MedFrio/poc-zero-knowledge-schnorr.git
cd poc-zero-knowledge-schnorr
```

Le projet utilise uniquement la bibliothèque standard Python. Aucune installation de package n'est nécessaire.

## Utilisation

### 1. Générer les clés

```bash
python generate_keys.py
```

Cette commande crée :

- `alice_private.json`, la clé privée connue uniquement par Alice ;
- `public_key.json`, la clé publique publiée et utilisée par Bob.

### 2. Tester Schnorr interactif avec Alice et Bob

Terminal 1, lancer Bob :

```bash
python bob.py
```

Terminal 2, lancer Alice :

```bash
python alice.py
```

Sortie attendue côté Bob :

```txt
[+] Tour 1 validé
[+] Alice est authentifiée
```

Sortie attendue côté Alice :

```txt
[+] Tour 1 accepté par Bob
[+] Authentification terminée avec succès
```

### 3. Tester un imposteur

Terminal 1 :

```bash
python bob.py
```

Terminal 2 :

```bash
python alice.py --impostor
```

Alice utilise une mauvaise clé privée. Bob doit refuser l'authentification.

### 4. Lancer plusieurs tours

```bash
python bob.py --rounds 30
```

Puis dans un autre terminal :

```bash
python alice.py --rounds 30
```

Plus le nombre de tours augmente, plus la probabilité qu'un imposteur passe par hasard devient négligeable.

### 5. Tester Fiat-Shamir, version non interactive

Générer une preuve autonome :

```bash
python fiat_shamir.py sign "accès autorisé le 01/01/2026" --out proof.json
```

Vérifier la preuve :

```bash
python fiat_shamir.py verify proof.json
```

Tester la même preuve avec un message modifié :

```bash
python fiat_shamir.py tamper proof.json "accès autorisé le 02/01/2026"
```

Résultat attendu :

```txt
[-] Preuve invalide après modification du message
```

### 6. Lancer les démonstrations d'attaques

```bash
python attacks.py
```

Le script montre :

- le rejet d'une preuve Fiat-Shamir si le message change ;
- la simulation d'un transcript valide sans connaître la clé privée ;
- la récupération de la clé privée si le même nonce `r` est réutilisé deux fois.

## Principe du protocole de Schnorr

On travaille dans un groupe modulo `p`, avec un générateur public `g` d'ordre `q`.

Alice possède une clé privée :

```txt
x
```

Elle publie la clé publique :

```txt
Y = g^x mod p
```

Bob connaît seulement `Y`.

### Étape 1, commitment

Alice choisit un nonce aléatoire `r` et calcule :

```txt
R = g^r mod p
```

Elle envoie `R` à Bob.

### Étape 2, challenge

Bob choisit un challenge aléatoire `c` et l'envoie à Alice.

### Étape 3, réponse

Alice calcule :

```txt
s = r + c*x mod q
```

Elle envoie `s` à Bob.

### Vérification

Bob vérifie :

```txt
g^s = R * Y^c mod p
```

Pourquoi cela fonctionne :

```txt
g^s = g^(r + c*x)
    = g^r * g^(c*x)
    = R * (g^x)^c
    = R * Y^c
```

Si Alice ne connaît pas `x`, elle ne peut pas calculer une réponse valide après avoir reçu le challenge de Bob.

## Version non interactive avec Fiat-Shamir

Dans la version interactive, Bob choisit `c`. Avec Fiat-Shamir, Bob est remplacé par une fonction de hachage :

```txt
c = SHA256(R || message) mod q
```

Alice peut donc produire seule une preuve autonome :

```txt
(message, R, s, Y)
```

Le vérificateur recalcule `c` à partir de `R` et du message, puis vérifie la même équation :

```txt
g^s = R * Y^c mod p
```

Cette transformation lie la preuve au message. Une preuve valide pour `message 1` devient invalide pour `message 2`.

## Attaque 1, rejeu

Un attaquant intercepte une preuve valide pour :

```txt
accès autorisé le 01/01/2026
```

Il essaie de la réutiliser pour :

```txt
accès autorisé le 02/01/2026
```

La vérification échoue, car le challenge dépend du message. Si le message change, le challenge change aussi.

## Attaque 2, simulation zero-knowledge

Le script `attacks.py` montre qu'il est possible de produire un transcript valide sans connaître `x`, si l'on choisit d'abord `c` et `s`, puis que l'on calcule :

```txt
R = g^s / Y^c mod p
```

Le transcript `(R, c, s)` passe la vérification, même si le simulateur ne connaît pas la clé privée. Cela illustre l'intuition zero-knowledge : les transcripts observés ne révèlent pas directement le secret `x`.

Important : ce transcript simulé ne permet pas de tromper Bob dans le protocole interactif réel, car dans ce cas Bob choisit le challenge après avoir reçu `R`.

## Attaque 3, réutilisation du nonce r

Si Alice réutilise le même nonce `r` pour deux challenges différents :

```txt
s1 = r + c1*x mod q
s2 = r + c2*x mod q
```

Alors :

```txt
s1 - s2 = (c1 - c2) * x mod q
```

Donc :

```txt
x = (s1 - s2) / (c1 - c2) mod q
```

Le script `attacks.py` force cette situation et récupère effectivement la clé privée.

## Ce que prouve la PoC

Cette PoC montre que :

- Alice peut prouver à Bob qu'elle connaît `x` sans révéler `x` ;
- Bob peut vérifier cette preuve avec seulement la clé publique `Y` ;
- la version Fiat-Shamir permet de produire une preuve vérifiable plus tard ;
- une preuve Fiat-Shamir est liée au message ;
- les transcripts ne révèlent pas directement le secret ;
- la sécurité dépend fortement de l'unicité du nonce `r`.
