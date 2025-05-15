from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from kyber_py.ml_kem import ML_KEM_512
from Crypto.Random import get_random_bytes

# ------------------------
# 1. Génération des clés RSA (KEM classique)
# ------------------------
# RSA repose sur la difficulté de la factorisation d'entiers : 
# Encapsulation : c₁ = k₁^e mod n
# Décapsulation : k₁ = c₁^d mod n
def rsa_keygen():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return public_key, private_key

def rsa_encapsulate(public_key):
    k1 = get_random_bytes(32)  # Génère une clé symétrique aléatoire de 256 bits
    c1 = public_key.encrypt(
        k1,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return c1, k1

def rsa_decapsulate(ciphertext, private_key):
    k1 = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return k1

# ------------------------
# 2. KEM post-quantique basé sur Kyber (ML-KEM-512)
# ------------------------
# Kyber repose sur le problème LWE (Learning With Errors) :
# - pk = (A, b = As + e)
# - encapsulation : (c, k₂) dérivé d’un message aléatoire chiffré avec LWE
# - décapsulation : récupération de k₂ ≈ H(m)
def kyber_keygen():
    ek, dk = ML_KEM_512.keygen()
    return ek, dk

def kyber_encapsulate(ek):
    key, ct = ML_KEM_512.encaps(ek)
    return ct, key

def kyber_decapsulate(ct, dk):
    key = ML_KEM_512.decaps(dk, ct)
    return key

# ------------------------
# 3. KDF (Key Derivation Function) : fusion des deux clés k₁ et k₂
# ------------------------
# On utilise HKDF (basé sur HMAC-SHA256) pour dériver une clé finale K :
# K = HKDF(k₁ || k₂)
def derive_hybrid_key(k1, k2):
    combined_key = k1 + k2 if isinstance(k1, bytes) and isinstance(k2, bytes) else b''
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"hybrid key derivation"
    )
    return hkdf.derive(combined_key)

# ------------------------
# 4. Simulation du protocole hybride complet
# ------------------------

if __name__ == "__main__":
    print("=== Échange de clé hybride RSA + Kyber (ML-KEM-512) ===")

    # Étape 1 : Alice génère ses paires de clés
    print("\n--- Génération des clés (Alice) ---")
    pk_rsa, sk_rsa = rsa_keygen()
    ek_kyber, dk_kyber = kyber_keygen()
    print("Les paires de clés RSA et Kyber ont été générées avec succès.")

    # Étape 2 : Bob encapsule deux clés symétriques
    print("\n--- Encapsulation des clés (Bob) ---")
    c1_rsa, k1_bob = rsa_encapsulate(pk_rsa)
    c2_kyber, k2_bob = kyber_encapsulate(ek_kyber)
    print(f"Clé RSA encapsulée (hex) : {k1_bob.hex()}")
    print(f"Clé Kyber encapsulée (hex) : {k2_bob.hex()}")
    print("Encapsulation des clés réussie.")

    # Étape 3 : Bob dérive une clé hybride à partir des deux clés symétriques
    K_bob = derive_hybrid_key(k1_bob, k2_bob)
    print(f"\nClé hybride dérivée par Bob (hex) : {K_bob.hex()}")

    # Étape 4 : Alice décapsule les deux clés symétriques
    print("\n--- Décapsulation des clés (Alice) ---")
    k1_alice = rsa_decapsulate(c1_rsa, sk_rsa)
    k2_alice = kyber_decapsulate(c2_kyber, dk_kyber)
    print(f"Clé RSA décapsulée (hex) : {k1_alice.hex()}")
    print(f"Clé Kyber décapsulée (hex) : {k2_alice.hex()}")
    print("Décapsulation des clés réussie.")

    # Étape 5 : Alice dérive également la clé hybride
    K_alice = derive_hybrid_key(k1_alice, k2_alice)
    print(f"\nClé hybride dérivée par Alice (hex) : {K_alice.hex()}")

    # Étape 6 : Vérification que les deux parties ont bien dérivé la même clé
    print("\n--- Vérification ---")
    print(f"Clés RSA identiques : {'Oui' if k1_bob == k1_alice else 'Non'}")
    print(f"Clés Kyber identiques : {'Oui' if k2_bob == k2_alice else 'Non'}")
    print(f"Clé finale identique : {'Oui' if K_bob == K_alice else 'Non'}")

    if K_bob == K_alice:
        print("\nÉchange de clé hybride réalisé avec succès.")
    else:
        print("\nErreur : les clés finales ne correspondent pas.")
        if k1_bob != k1_alice:
            print("- Échec de décapsulation RSA")
        if k2_bob != k2_alice:
            print("- Échec de décapsulation Kyber")
