#!/usr/bin/env python3
"""
Version non interactive de Schnorr avec transformation de Fiat-Shamir.

Le challenge c n'est plus envoyé par Bob. Il est calculé par hachage :
c = SHA256(R || message) mod q.

La preuve produite est autonome : message, R, s, Y.
"""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path

from common import (
    G,
    P,
    Q,
    hash_to_challenge,
    load_json,
    load_private_key,
    public_key_from_private,
    save_json,
    validate_group_parameters,
    verify_transcript,
)


def sign_message(message: str, private_key: int) -> dict[str, str]:
    """
    Produit une preuve non interactive pour un message.
    """
    nonce = secrets.randbelow(Q - 1) + 1
    commitment = pow(G, nonce, P)
    challenge = hash_to_challenge(commitment, message.encode("utf-8"))
    response = (nonce + challenge * private_key) % Q
    public_key = public_key_from_private(private_key)

    return {
        "message": message,
        "R": str(commitment),
        "s": str(response),
        "Y": str(public_key),
    }


def verify_proof(proof: dict[str, str]) -> bool:
    """
    Vérifie une preuve non interactive.
    """
    message = proof["message"]
    commitment = int(proof["R"])
    response = int(proof["s"])
    public_key = int(proof["Y"])

    challenge = hash_to_challenge(commitment, message.encode("utf-8"))
    return verify_transcript(public_key, commitment, challenge, response)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Schnorr non interactif avec Fiat-Shamir.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="Signer un message.")
    sign_parser.add_argument("message", help="Message à signer.")
    sign_parser.add_argument("--out", default="proof.json", help="Fichier de sortie.")

    verify_parser = subparsers.add_parser("verify", help="Vérifier une preuve.")
    verify_parser.add_argument("proof_file", help="Fichier JSON contenant la preuve.")

    tamper_parser = subparsers.add_parser(
        "tamper",
        help="Tester la même preuve avec un autre message.",
    )
    tamper_parser.add_argument("proof_file", help="Fichier JSON contenant la preuve.")
    tamper_parser.add_argument("new_message", help="Message modifié.")

    return parser.parse_args()


def main() -> int:
    validate_group_parameters()
    args = parse_arguments()

    if args.command == "sign":
        private_key = load_private_key()
        proof = sign_message(args.message, private_key)
        save_json(Path(args.out), proof)
        print(f"[+] Preuve générée dans {args.out}")
        return 0

    if args.command == "verify":
        proof = load_json(Path(args.proof_file))
        is_valid = verify_proof(proof)
        print("[+] Preuve valide" if is_valid else "[-] Preuve invalide")
        return 0 if is_valid else 1

    if args.command == "tamper":
        proof = load_json(Path(args.proof_file))
        proof["message"] = args.new_message
        is_valid = verify_proof(proof)
        print("[+] Preuve valide" if is_valid else "[-] Preuve invalide après modification du message")
        return 0 if is_valid else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
