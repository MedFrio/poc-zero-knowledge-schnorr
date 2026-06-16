#!/usr/bin/env python3
"""
Démonstrations des attaques et propriétés demandées dans le sujet 10.

1. Rejeu : une preuve Fiat-Shamir valide pour un message échoue si le message change.
2. Simulation : génération d'un transcript valide sans connaître la clé privée x.
3. Réutilisation du nonce r : récupération effective de la clé privée.
"""

from __future__ import annotations

import secrets

from common import (
    G,
    P,
    Q,
    hash_to_challenge,
    load_private_key,
    mod_inverse,
    public_key_from_private,
    validate_group_parameters,
    verify_transcript,
)
from fiat_shamir import sign_message, verify_proof


def demonstrate_replay_attack(private_key: int) -> None:
    print("=== Attaque 1 : rejeu avec message modifié ===")

    original_message = "accès autorisé le 01/01/2026"
    replayed_message = "accès autorisé le 02/01/2026"

    proof = sign_message(original_message, private_key)
    valid_original = verify_proof(proof)

    modified_proof = dict(proof)
    modified_proof["message"] = replayed_message
    valid_replayed = verify_proof(modified_proof)

    print(f"Message original valide : {valid_original}")
    print(f"Même preuve sur message modifié valide : {valid_replayed}")
    print("Conclusion : le rejeu échoue car le challenge dépend du message.")
    print()


def demonstrate_simulation(public_key: int) -> None:
    print("=== Attaque 2 : simulation zero-knowledge ===")

    challenge = secrets.randbelow(Q - 1) + 1
    response = secrets.randbelow(Q - 1) + 1

    # On construit R à l'envers :
    # R = g^s / Y^c mod p
    commitment = (pow(G, response, P) * mod_inverse(pow(public_key, challenge, P), P)) % P

    is_valid = verify_transcript(
        public_key=public_key,
        commitment=commitment,
        challenge=challenge,
        response=response,
    )

    print(f"Transcript simulé valide : {is_valid}")
    print(f"R = {commitment}")
    print(f"c = {challenge}")
    print(f"s = {response}")
    print("Conclusion : un transcript valide peut être simulé sans connaître x.")
    print()


def demonstrate_nonce_reuse(private_key: int) -> None:
    print("=== Attaque 3 : réutilisation du nonce r ===")

    public_key = public_key_from_private(private_key)
    nonce = secrets.randbelow(Q - 1) + 1
    commitment = pow(G, nonce, P)

    message_1 = b"message 1"
    message_2 = b"message 2"

    challenge_1 = hash_to_challenge(commitment, message_1)
    challenge_2 = hash_to_challenge(commitment, message_2)

    if challenge_1 == challenge_2:
        raise RuntimeError("Challenges identiques, relancez la démonstration.")

    response_1 = (nonce + challenge_1 * private_key) % Q
    response_2 = (nonce + challenge_2 * private_key) % Q

    numerator = (response_1 - response_2) % Q
    denominator = (challenge_1 - challenge_2) % Q
    recovered_private_key = (numerator * mod_inverse(denominator, Q)) % Q

    print(f"Transcript 1 valide : {verify_transcript(public_key, commitment, challenge_1, response_1)}")
    print(f"Transcript 2 valide : {verify_transcript(public_key, commitment, challenge_2, response_2)}")
    print(f"Clé privée récupérée correctement : {recovered_private_key == private_key}")
    print(f"x original  = {private_key}")
    print(f"x récupéré  = {recovered_private_key}")
    print("Conclusion : réutiliser r compromet immédiatement la clé privée.")
    print()


def main() -> int:
    validate_group_parameters()

    try:
        private_key = load_private_key()
    except FileNotFoundError:
        print("Erreur : alice_private.json introuvable. Lancez d'abord python generate_keys.py.")
        return 2

    public_key = public_key_from_private(private_key)

    demonstrate_replay_attack(private_key)
    demonstrate_simulation(public_key)
    demonstrate_nonce_reuse(private_key)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
