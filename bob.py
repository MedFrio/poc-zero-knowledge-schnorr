#!/usr/bin/env python3
"""
Bob, vérificateur du protocole de Schnorr interactif.

Bob ne connaît pas la clé privée x. Il connaît seulement la clé publique Y.
Il attend une connexion locale d'Alice, envoie un challenge aléatoire c,
puis vérifie la réponse s reçue.
"""

from __future__ import annotations

import argparse
import secrets
import socket

from common import (
    P,
    Q,
    load_public_key,
    recv_json_line,
    send_json_line,
    validate_group_parameters,
    verify_transcript,
)


def run_server(host: str, port: int, rounds: int) -> bool:
    validate_group_parameters()
    public_key = load_public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(1)

        print(f"[+] Bob écoute sur {host}:{port}")
        print(f"[+] Tours demandés : {rounds}")
        print("[+] En attente d'Alice...")

        connection, address = server_socket.accept()
        with connection:
            print(f"[+] Connexion reçue depuis {address[0]}:{address[1]}")
            reader = connection.makefile("r", encoding="utf-8", newline="\n")

            for round_index in range(1, rounds + 1):
                commitment_message = recv_json_line(reader)
                if commitment_message.get("type") != "commitment":
                    raise ValueError("Message inattendu, commitment attendu.")

                commitment = int(commitment_message["R"])
                if not 1 <= commitment < P:
                    raise ValueError("Commitment invalide.")

                challenge = secrets.randbelow(Q - 1) + 1
                send_json_line(
                    connection,
                    {
                        "type": "challenge",
                        "round": round_index,
                        "c": str(challenge),
                    },
                )

                response_message = recv_json_line(reader)
                if response_message.get("type") != "response":
                    raise ValueError("Message inattendu, response attendu.")

                response = int(response_message["s"])
                is_valid = verify_transcript(
                    public_key=public_key,
                    commitment=commitment,
                    challenge=challenge,
                    response=response,
                )

                send_json_line(
                    connection,
                    {
                        "type": "round_result",
                        "round": round_index,
                        "valid": is_valid,
                    },
                )

                if not is_valid:
                    print(f"[-] Échec au tour {round_index}")
                    print("[-] Alice n'est pas authentifiée")
                    return False

                print(f"[+] Tour {round_index} validé")

            print("[+] Alice est authentifiée")
            return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bob, vérificateur Schnorr interactif.")
    parser.add_argument("--host", default="127.0.0.1", help="Adresse locale d'écoute.")
    parser.add_argument("--port", type=int, default=5000, help="Port local d'écoute.")
    parser.add_argument("--rounds", type=int, default=1, help="Nombre de tours Schnorr.")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    if args.rounds <= 0:
        print("Erreur : --rounds doit être supérieur à 0.")
        return 2

    try:
        return 0 if run_server(args.host, args.port, args.rounds) else 1
    except FileNotFoundError:
        print("Erreur : public_key.json introuvable. Lancez d'abord python generate_keys.py.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
