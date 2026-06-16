#!/usr/bin/env python3
"""
Alice, prouveur du protocole de Schnorr interactif.

Alice connaît la clé privée x. Pour chaque tour :
1. elle choisit un nonce secret r,
2. elle envoie R = g^r à Bob,
3. elle reçoit le challenge c,
4. elle répond s = r + c*x mod q.
"""

from __future__ import annotations

import argparse
import secrets
import socket

from common import G, P, Q, load_private_key, recv_json_line, send_json_line, validate_group_parameters


def run_client(host: str, port: int, rounds: int, impostor: bool) -> bool:
    validate_group_parameters()

    if impostor:
        private_key = secrets.randbelow(Q - 1) + 1
        print("[!] Mode imposteur activé : Alice utilise une mauvaise clé privée")
    else:
        private_key = load_private_key()

    with socket.create_connection((host, port), timeout=10) as connection:
        reader = connection.makefile("r", encoding="utf-8", newline="\n")

        for round_index in range(1, rounds + 1):
            nonce = secrets.randbelow(Q - 1) + 1
            commitment = pow(G, nonce, P)

            send_json_line(
                connection,
                {
                    "type": "commitment",
                    "round": round_index,
                    "R": str(commitment),
                },
            )

            challenge_message = recv_json_line(reader)
            if challenge_message.get("type") != "challenge":
                raise ValueError("Message inattendu, challenge attendu.")

            challenge = int(challenge_message["c"])
            response = (nonce + challenge * private_key) % Q

            send_json_line(
                connection,
                {
                    "type": "response",
                    "round": round_index,
                    "s": str(response),
                },
            )

            result_message = recv_json_line(reader)
            if result_message.get("type") != "round_result":
                raise ValueError("Message inattendu, résultat attendu.")

            if not bool(result_message["valid"]):
                print(f"[-] Refusé par Bob au tour {round_index}")
                return False

            print(f"[+] Tour {round_index} accepté par Bob")

    print("[+] Authentification terminée avec succès")
    return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Alice, prouveur Schnorr interactif.")
    parser.add_argument("--host", default="127.0.0.1", help="Adresse de Bob.")
    parser.add_argument("--port", type=int, default=5000, help="Port de Bob.")
    parser.add_argument("--rounds", type=int, default=1, help="Nombre de tours Schnorr.")
    parser.add_argument(
        "--impostor",
        action="store_true",
        help="Utilise une fausse clé privée pour démontrer l'échec.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if args.rounds <= 0:
        print("Erreur : --rounds doit être supérieur à 0.")
        return 2

    try:
        return 0 if run_client(args.host, args.port, args.rounds, args.impostor) else 1
    except FileNotFoundError:
        print("Erreur : alice_private.json introuvable. Lancez d'abord python generate_keys.py.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
