#!/usr/bin/env python3
"""
Fonctions communes pour la preuve de concept Schnorr.

Le TP demande de montrer un protocole d'authentification Zero-Knowledge.
Cette implémentation utilise le groupe multiplicatif modulo p, avec p = 2q + 1
et g un générateur du sous-groupe d'ordre q.

Ce groupe est suffisant pour une PoC pédagogique. Il ne doit pas être utilisé
tel quel en production.
"""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path
from typing import Any

# Paramètres publics du groupe.
# p est un nombre premier sûr, q = (p - 1) / 2 est premier.
P = 43215001105282531082389342439
Q = 21607500552641265541194671219

# g = 2^2 mod p appartient au sous-groupe d'ordre q.
G = 4

PRIVATE_KEY_FILE = Path("alice_private.json")
PUBLIC_KEY_FILE = Path("public_key.json")


def validate_group_parameters() -> None:
    """
    Vérifie les propriétés minimales des paramètres publics.
    """
    if (P - 1) // 2 != Q:
        raise ValueError("Paramètres invalides : q doit valoir (p - 1) / 2.")
    if pow(G, Q, P) != 1:
        raise ValueError("Paramètres invalides : g n'appartient pas au sous-groupe.")
    if G in (0, 1):
        raise ValueError("Paramètres invalides : g ne doit pas être trivial.")


def public_key_from_private(private_key: int) -> int:
    """
    Calcule la clé publique Y = g^x mod p.
    """
    if not 1 <= private_key < Q:
        raise ValueError("La clé privée doit être comprise entre 1 et q - 1.")
    return pow(G, private_key, P)


def hash_to_challenge(commitment: int, message: bytes) -> int:
    """
    Calcule le challenge Fiat-Shamir c = SHA256(R || message) mod q.

    Les entiers sont encodés avec une longueur fixe pour éviter les ambiguïtés.
    """
    commitment_bytes = commitment.to_bytes((P.bit_length() + 7) // 8, "big")
    digest = hashlib.sha256(commitment_bytes + message).digest()
    challenge = int.from_bytes(digest, "big") % Q
    return challenge or 1


def verify_transcript(public_key: int, commitment: int, challenge: int, response: int) -> bool:
    """
    Vérifie l'équation de Schnorr : g^s = R * Y^c mod p.
    """
    left = pow(G, response % Q, P)
    right = (commitment * pow(public_key, challenge % Q, P)) % P
    return left == right


def mod_inverse(value: int, modulus: int = Q) -> int:
    """
    Calcule l'inverse modulaire de value modulo modulus.
    """
    return pow(value % modulus, -1, modulus)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: Path, data: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def load_private_key(path: Path = PRIVATE_KEY_FILE) -> int:
    data = load_json(path)
    return int(data["x"])


def load_public_key(path: Path = PUBLIC_KEY_FILE) -> int:
    data = load_json(path)
    return int(data["Y"])


def send_json_line(connection: socket.socket, payload: dict[str, Any]) -> None:
    """
    Envoie un objet JSON terminé par un saut de ligne.
    """
    raw_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    connection.sendall(raw_payload)


def recv_json_line(file_object: Any) -> dict[str, Any]:
    """
    Lit une ligne JSON depuis un socket converti en fichier.
    """
    raw_line = file_object.readline()
    if not raw_line:
        raise ConnectionError("Connexion fermée par l'autre programme.")
    if isinstance(raw_line, bytes):
        raw_line = raw_line.decode("utf-8")
    return json.loads(raw_line)
