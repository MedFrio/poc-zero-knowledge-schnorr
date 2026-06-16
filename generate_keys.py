#!/usr/bin/env python3
"""
Génère une paire de clés pour la PoC Schnorr.

Alice conserve alice_private.json.
Bob utilise uniquement public_key.json.
"""

from __future__ import annotations

import secrets

from common import (
    G,
    P,
    Q,
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
    public_key_from_private,
    save_json,
    validate_group_parameters,
)


def main() -> int:
    validate_group_parameters()

    private_key = secrets.randbelow(Q - 1) + 1
    public_key = public_key_from_private(private_key)

    save_json(
        PRIVATE_KEY_FILE,
        {
            "description": "Clé privée de démonstration pour Alice. Ne pas publier.",
            "x": str(private_key),
        },
    )
    save_json(
        PUBLIC_KEY_FILE,
        {
            "description": "Clé publique publiée par Alice pour Bob.",
            "p": str(P),
            "q": str(Q),
            "g": str(G),
            "Y": str(public_key),
        },
    )

    print("[+] Clés générées")
    print(f"[+] Fichier privé Alice : {PRIVATE_KEY_FILE}")
    print(f"[+] Fichier public Bob   : {PUBLIC_KEY_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
