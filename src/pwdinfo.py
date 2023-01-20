#!/usr/bin/env python3
"""get info of a password"""

import sys
from getpass import getpass

from password_strength import PasswordStats  # type: ignore

__version__: str = "0.0.1"
__author__: str = "Ari Archer <ari.web.xyz@gmail.com>"


def main() -> int:
    """entry/main function"""

    password = getpass("(password (hidden)) ")

    if not password.strip():
        sys.stderr.write("password cannot be empty\n")
        return 1

    stats = PasswordStats(password)

    INFO = {
        "entropy bits": stats.entropy_bits,
        "length": stats.length,
        "letters": stats.letters,
        "letters (lowercase)": stats.letters_lowercase,
        "letters (uppercase)": stats.letters_uppercase,
        "numbers": stats.numbers,
        "special characters": stats.special_characters,
        "alphabet": "".join(stats.alphabet),
        "alphabet length": stats.alphabet_cardinality,
        "alphabet combinations (in hex)": hex(stats.combinations),
        "total sequences": stats.sequences_length,
        "strength": stats.strength(),
        "weakness": stats.weakness_factor,
        "total strength": (1 - stats.weakness_factor) * stats.strength(),
    }

    for item, value in INFO.items():
        print(f"{item:40s}{value}")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"
    sys.exit(main())
