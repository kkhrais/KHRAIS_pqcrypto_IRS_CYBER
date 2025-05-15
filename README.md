
# Projet : Échange de clé hybride RSA + Kyber (post-quantique)

Ce projet illustre un échange de clés hybride, combinant :
🔹 RSA (cryptographie classique, basée sur la factorisation)
🔹 Kyber (algorithme post-quantique, résistant aux attaques des ordinateurs quantiques)

L’objectif est de générer une clé secrète commune en tirant parti des avantages des deux méthodes.

---

## Prérequis

Python 3.8 ou supérieur, avec les bibliothèques suivantes :

### Installation avec `pip` :

```bash
pip install cryptography
pip install pycryptodome
pip install kyber-py
```

### Ou via un fichier `requirements.txt` :

Créer un fichier `requirements.txt` contenant :

```
cryptography
pycryptodome
kyber-py
```

Puis lancer :

```bash
pip install -r requirements.txt
```

---

## Fichier principal

Le script principal est :

```bash
khrais_IRS_cyber.py
```

Pour exécuter le script :

```bash
python khrais_IRS_cyber.py
```

---

## Fonctionnement du protocole

1. **Alice** génère deux paires de clés :
   - Une paire RSA (cryptographie classique)
   - Une paire ML-KEM 512 (Kyber post-quantique)

2. **Bob** :
   - Encapsule une clé symétrique avec la clé publique RSA → `k₁`
   - Encapsule une autre clé avec la clé publique Kyber → `k₂`
   - Dérive une clé hybride `K` à partir de `k₁` et `k₂` à l’aide d’un KDF (HKDF)

3. **Alice** :
   - Décapsule `k₁` et `k₂` avec ses clés privées
   - Dérive également la clé hybride `K`

4. **Vérification** :
   - Comparaison des clés finales pour confirmer le succès du protocole

---

## Documentations utilisées pour mon code
 
  https://csrc.nist.gov/projects/post-quantum-cryptography
- Documentation de la bibliothèque Python `cryptography`  
  https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF
- Documentation de `kyber-py` (binding Python de ML-KEM / Kyber)  
  https://pypi.org/project/kyber-py/
- Documentation de `pycryptodome`  
  https://www.pycryptodome.org/

---

## Explications mathématiques

- **RSA** :
  - Chiffrement : \( c_1 = k_1^e \mod n \)
  - Déchiffrement : \( k_1 = c_1^d \mod n \)

- **Kyber (ML-KEM)** :
  - Repose sur le problème LWE (Learning With Errors)
  - La clé symétrique \( k_2 \) est dérivée d’un message aléatoire chiffré via LWE, puis haché : \( k_2 = H(m) \)

- **KDF (HKDF)** :
  - Une fonction de dérivation basée sur HMAC-SHA256
  - Permet d’obtenir une clé finale robuste et unifiée : \( K = \text{HKDF}(k_1 \| k_2) \)