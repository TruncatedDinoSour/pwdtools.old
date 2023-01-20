#!/usr/bin/env python3
"""get info of a password using zxcvbn"""

import sys
from getpass import getpass

import zxcvbn  # type: ignore
from password_strength import PasswordStats  # type: ignore

__version__: str = "0.0.1"
__author__: str = "Ari Archer <ari.web.xyz@gmail.com>"


SCORE_STRINGS: dict[int, str] = {
    0: "very bad",
    1: "bad",
    2: "not good",
    3: "good",
    4: "strong",
}


def filter_zxcvbn_crack_key(key: str) -> str:
    return key.removeprefix("offline_").removeprefix("online_")


def log(message: str, header: str = "WARNING") -> None:
    sys.stderr.write(f" * {header}: {message}\n")


def main() -> int:
    """Entry/main function"""

    password = getpass("(password (hidden)) ")

    if not password.strip():
        sys.stderr.write("password cannot be empty\n")
        return 1

    pwd_stats = PasswordStats(password)
    zxcvbn_stats = zxcvbn.zxcvbn(password)

    INFO = {
        "entropy bits": pwd_stats.entropy_bits,
        "length": pwd_stats.length,
        "letters": pwd_stats.letters,
        "letters (lowercase)": pwd_stats.letters_lowercase,
        "letters (uppercase)": pwd_stats.letters_uppercase,
        "numbers": pwd_stats.numbers,
        "special characters": pwd_stats.special_characters,
        "alphabet": "".join(pwd_stats.alphabet),
        "alphabet length": pwd_stats.alphabet_cardinality,
        "alphabet combinations (in hex)": hex(pwd_stats.combinations),
        "total sequences": pwd_stats.sequences_length,
        "strength": pwd_stats.strength(),
        "weakness": pwd_stats.weakness_factor,
        "total strength": (1 - pwd_stats.weakness_factor) * pwd_stats.strength(),
        "rating": SCORE_STRINGS.get(zxcvbn_stats["score"], str(zxcvbn_stats["score"])),
        "would take guesses": zxcvbn_stats["guesses"],
    }

    for key, value in zxcvbn_stats["crack_times_display"].items():
        INFO[
            f"crack time ({filter_zxcvbn_crack_key(key)})"
        ] = f"{zxcvbn_stats['crack_times_seconds'][key]} seconds ({value})"

    for item, value in INFO.items():
        print(f"{item:45s}{value}")

    sys.stderr.write("\n")

    if warn := zxcvbn_stats.get("warning"):
        log(warn)

    for suggestion in zxcvbn_stats["feedback"]["suggestions"]:
        log(suggestion, "SUGGESTION")

    return 0


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"
    sys.exit(main())
