#!/usr/bin/env python3
"""password generator"""

import secrets
import string
import sys
from optparse import OptionParser, make_option

from password_strength import PasswordStats  # type: ignore
from plumbum.commands.processes import ProcessExecutionError  # type: ignore
from pyfzf import FzfPrompt  # type: ignore
from pyperclip import PyperclipException  # type: ignore
from pyperclip import copy as copy_clipboard  # type: ignore

__version__: str = "0.0.4"
__author__: str = "Ari Archer <ari.web.xyz@gmail.com>"
SYS_RANDOM: secrets.SystemRandom = secrets.SystemRandom()


PWD_OPTIONS = OptionParser(
    option_list=[
        make_option(
            "-c",
            "--charset",
            action="store",
            type="string",
            dest="charset",
            help="specify a list of allowed characters",
            default=string.printable.strip(),
        ),
        make_option(
            "-u",
            "--unicode",
            action="store_true",
            dest="allow_unicode",
            help="allow for unicode to appear in passwords",
            default=False,
        ),
        make_option(
            "-U",
            "--unicode-range",
            action="store",
            dest="unicode_range",
            type="str",
            help="specify the unicode range, format: min,max",
            default="1,256",
        ),
        make_option(
            "-C",
            "--copy",
            action="store_true",
            dest="clipboard",
            help="copy the generated password to clipboard",
            default=False,
        ),
        make_option(
            "-i",
            "--interactive",
            action="store_true",
            dest="interactive",
            help="let user pick passwords from a menu",
            default=False,
        ),
        make_option(
            "-t",
            "--interactive-count",
            action="store",
            dest="interactive_count",
            type="int",
            help="how many passwords to generate in interactive mode",
            default=10,
        ),
        make_option(
            "-l",
            "--length",
            action="store",
            dest="length",
            type="int",
            help="max password length",
            default=SYS_RANDOM.randint(250, 5000),
        ),
        make_option(
            "-L",
            "--limit",
            action="store",
            dest="recursion_limit",
            type="int",
            help="set max recursion limit",
        ),
        make_option(
            "-s",
            "--min-strength",
            action="store",
            type="float",
            dest="min_strength",
            help="minimum password strength in float, 0.01 = 1%",
            default=0.95,
        ),
        make_option(
            "-E",
            "--min-entropy",
            action="store",
            type="float",
            dest="min_entropy",
            help="minimum password entropy in float",
            default=1500.0,
        ),
        make_option(
            "-M",
            "--no-modify",
            action="store_false",
            dest="allow_modify",
            help="if password is too weak, don't modify the configuration to make it stronger",
            default=True,
        ),
        make_option(
            "-D",
            "--debug",
            action="store_true",
            dest="debug",
            help="enable debug mode",
            default=False,
        ),
        make_option(
            "-e",
            "--end",
            action="store",
            dest="end",
            help="delimeter to end output with",
            type="str",
            default="\n",
        ),
        make_option(
            "-S",
            "--shuffle",
            action="store",
            dest="shuffle",
            help="how many times to shuffle the password",
            type="int",
            default=10,
        ),
    ],
    version=__version__,
    description="Generate strong and secure passwords",
).parse_args()[0]


def eprint(msg: str) -> None:
    """print to stderr"""

    sys.stderr.write(f"{msg}\n")


def dprint(msg: str) -> None:
    """print a debug message"""

    if not PWD_OPTIONS.debug:
        return

    eprint(f"[DEBUG] {msg}")


def generate_password() -> str:
    """generate and return a password"""

    dprint(f"generating new password of length of {PWD_OPTIONS.length}")

    if PWD_OPTIONS.allow_unicode:
        dprint("unicode mode = on")

        unicode_min, unicode_max = map(int, PWD_OPTIONS.unicode_range.split(",", 1))
        generated_password = "".join(
            chr(code)
            for code in (
                SYS_RANDOM.randint(unicode_min, unicode_max)
                for _ in range(PWD_OPTIONS.length)
            )
        )
    else:
        generated_password = "".join(
            SYS_RANDOM.choices(PWD_OPTIONS.charset, k=PWD_OPTIONS.length)
        )

    dprint(f"shuffling password {PWD_OPTIONS.shuffle} times")

    _pw: list[str] = list(generated_password)
    for _ in range(PWD_OPTIONS.shuffle):
        SYS_RANDOM.shuffle(_pw)
    generated_password = "".join(_pw)

    dprint("password generated. calculating statistics...")

    p_stats = PasswordStats(generated_password)
    p_strength = (1 - p_stats.weakness_factor) * p_stats.strength()

    dprint(
        f"generated new password. strength = {p_strength} out of \
{PWD_OPTIONS.min_strength} required, length = {len(generated_password)} \
out of {PWD_OPTIONS.length} and entropy = {p_stats.entropy_bits} out of \
{PWD_OPTIONS.min_entropy} required"
    )

    if PWD_OPTIONS.allow_modify:
        dprint("modifying config...")
        PWD_OPTIONS.length += int(
            (p_stats.entropy_bits * p_strength) // p_stats.length
            + SYS_RANDOM.randint(2, 30)
        )
        PWD_OPTIONS.charset += SYS_RANDOM.choice(PWD_OPTIONS.charset)

    return (
        generated_password
        if p_strength >= PWD_OPTIONS.min_strength
        and p_stats.entropy_bits >= PWD_OPTIONS.min_entropy
        else generate_password()
    )


def main() -> int:
    """entry/main function"""

    dprint(f"{PWD_OPTIONS.__dict__ = }")

    if PWD_OPTIONS.interactive:
        dprint("interactive mode = on")
        dprint(f"generating {PWD_OPTIONS.interactive_count} passwords")

        try:
            password: str = FzfPrompt().prompt(  # type: ignore
                (generate_password() for _ in range(PWD_OPTIONS.interactive_count))
            )[0]
        except ProcessExecutionError:
            eprint("fzf exited unexpectedly")
            return 1
    else:
        dprint("generating password")
        password = generate_password()

    if PWD_OPTIONS.clipboard:
        dprint("copying password to clipboard")

        try:
            copy_clipboard(password)
        except PyperclipException as err:
            eprint(f"failed to copy to clipboard: {err}")
            return 1

        dprint("copied password to clipboard")
    else:
        dprint("outputing password")
        print(
            password,
            end=PWD_OPTIONS.end.encode("raw_unicode_escape").decode("unicode_escape"),
        )

    dprint(f"{PWD_OPTIONS.__dict__ = }")

    return 0


if __name__ == "__main__":
    dprint(f"version {__version__}")

    if PWD_OPTIONS.recursion_limit is not None:
        dprint(
            f"setting recursion limit {sys.getrecursionlimit()} -> {PWD_OPTIONS.recursion_limit}"
        )

        try:
            sys.setrecursionlimit(PWD_OPTIONS.recursion_limit)
        except OverflowError:
            eprint("the set limit via -L is too large")
            sys.exit(1)

    dprint("asserting main()")
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    dprint("running main()")

    ret: int = 0

    try:
        ret = main()
    except (RecursionError, MemoryError):
        eprint("too much recursion, try passing the -L flag with a higher/lower number")
        ret = 1

    sys.exit(ret)
