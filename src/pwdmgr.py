#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""password manager"""

import base64
import bz2
import csv
import os
import secrets
import sys
from enum import Enum, auto
from getpass import getpass
from io import BufferedWriter, StringIO
from shutil import rmtree
from threading import Thread
from time import sleep as sleep_secs
from typing import IO, Any, Callable, NoReturn
from warnings import filterwarnings as filter_warnings

import pyperclip  # type: ignore
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from plumbum.commands.processes import ProcessExecutionError  # type: ignore
from pyfzf import FzfPrompt  # type: ignore

__version__: str = "0.0.2"
__author__: str = "Ari Archer <ari.web.xyz@gmail.com>"


KDF_ALGORITHM: hashes.SHA512 = hashes.SHA512()
KDF_LENGTH: int = 32
CC_TIMER: int = 30
KDF_ITERATIONS: int = 384_000

GLOBAL_STATES: dict[str, Any] = {
    "db-changed": False,
    "cc-timer": 0,
}
PASSWORD_STRUCT: tuple[str, ...] = (
    "name",
    "url",
    "note",
    "username",
    "password",
)


def encrypt(
    plaintext: bytes, password: str, salt: bytes | None = None
) -> tuple[bytes, bytes]:
    """symetric salted encryption"""

    if salt is None:
        # the salt used to be between 0.5 and 1 KB, for
        # security, since pwdtools v1.2 it's between 2 and
        # 4 KB

        salt = secrets.token_bytes(secrets.SystemRandom().randint(2048, 8192))

    kdf: PBKDF2HMAC = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS
    )
    key: bytes = kdf.derive(password.encode("utf-8"))

    return (
        Fernet(base64.urlsafe_b64encode(key)).encrypt(plaintext),
        salt,
    )


def decrypt(ciphertext: bytes, password: str, salt: bytes) -> bytes:
    """symetric salted decryption"""

    kdf: PBKDF2HMAC = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt, iterations=KDF_ITERATIONS
    )
    key: bytes = kdf.derive(password.encode("utf-8"))

    return Fernet(base64.urlsafe_b64encode(key)).decrypt(ciphertext)


def clear_sc() -> None:
    """clear the screen"""

    print("\033[H\033[J", end="")


def cc_timer_reset() -> None:
    """reset clear clipboard timer"""

    elog(f"Clearing your clipboard after {CC_TIMER} seconds")
    GLOBAL_STATES["cc-timer"] = CC_TIMER


def clear_cb(screen: bool = True) -> None:
    """clear the clipboard"""

    try:
        pyperclip.copy("")  # type: ignore
    except pyperclip.PyperclipException:
        if screen:
            clear_sc()

    GLOBAL_STATES["cc-timer"] = 0

    if screen:
        log("cleared your clipboard")


def log(m: str, s: IO[str] = sys.stdout) -> None:
    """Log message"""

    print(f"  {m}", file=s)


def elog(m: str) -> None:
    """log an error message"""

    log(f"attention: {m}", sys.stderr)


def cexit(code: int = 0) -> NoReturn:
    """exit clearing the users clipboard"""

    clear_cb(False)
    sys.exit(code)


def ferr(m: str) -> NoReturn:
    """fatal error"""

    elog(m)
    cexit(1)


def yn(q: str, d: str = "y") -> bool:
    """yes / no question"""

    d = d[0].lower()

    try:
        return (input(f"  {q} ? {'[y/n]'.replace(d, d.upper())} ") + d)[
            0
        ].lower() == "y"
    except (KeyboardInterrupt, EOFError):
        return d == "y"


def pw(prompt: str) -> str:
    """get password / hidden input"""

    try:
        return getpass(f"  {prompt}: ")
    except (EOFError, KeyboardInterrupt):
        ferr("\rfailed reading the password")


def eepw(data: str, password: str, salt: bytes) -> str:
    """encrypt, compress and encode given input"""

    return base64.b85encode(
        bz2.compress(encrypt(data.encode(), password, salt)[0])
    ).decode()


def epw(prompt: str, password: str, salt: bytes) -> str:
    """wrapper for eepw() to read from stdin"""

    return eepw(pw(prompt), password, salt)


def pwe(enc: str, password: str, salt: bytes) -> str:
    """decrypt, compress and encode given input with a given password and salt"""

    try:
        return decrypt(bz2.decompress(base64.b85decode(enc)), password, salt).decode()
    except OSError as e:
        ferr(
            f"potentially invalid BZ2 compressed data at password decryption, \
error: {e.__class__.__name__}: {e}"
        )
    except (InvalidSignature, InvalidToken):
        ferr(
            "invalid password entry password, cryptography token/signature \
and/or salt"
        )


def iinput(prompt: str, force: bool = False) -> str:
    """wrapper for input() with an optional forcing of a value"""

    data: str = ""

    while not data:
        data = input(f"  {prompt}: ")

        if not force:
            break

    return data


def verify_path(file_path: str) -> str:
    """verify if a path is valid"""

    if len(file_path) > 192:
        ferr(f"file path {file_path!r} is longer than 192 characters")

    if os.path.exists(file_path):
        elog(f"{file_path!r} already exists")

        if yn(f" * Overwrite {file_path!r}"):
            if os.path.isdir(file_path):
                rmtree(file_path)
            else:
                os.remove(file_path)
        else:
            cexit(0)

    return file_path


def mk_spath(name: str, ext: str) -> str:
    """makes a secure path"""

    return verify_path(f"{name}.{ext}".replace("/", ""))


def print_doc_comment(fun: Callable[..., Any]) -> None:
    """print doc comment and the function name"""

    log(
        f"{fun.__name__[4:]:10s} \
{fun.__doc__ or 'no help provided'}"
    )


def print_obj_cmd_help(o: object, args: tuple[str, ...]) -> None:
    """print an object's command help ( optionally selected help )"""

    if args:
        for arg in args:
            cmd_fn: Callable[..., Any] | None = getattr(o, f"cmd_{arg}", None)

            if cmd_fn is None:
                elog(f"warning : no help for {arg!r}")
                continue

            print_doc_comment(cmd_fn)
    else:
        for fun in dir(o):
            if not fun.startswith("cmd_"):
                continue

            print_doc_comment(getattr(o, fun))


def change_db(fun: Callable[..., Any] | None = None, *args: Any) -> None:
    """change the database"""

    if fun is not None:
        fun(*args)

    GLOBAL_STATES["db-changed"] = True


def to_clipboard_or_out(data: str) -> None:
    """copy data to clipboard or output it"""

    try:
        pyperclip.copy(data)  # type: ignore
        log("copied to clipboard")
        cc_timer_reset()
    except pyperclip.PyperclipException:
        if yn("cannot copy data to clipboard, would you like to display it instead"):
            print(data)


def parsed_to_csv(
    file: BufferedWriter, parsed_data: list[list[str]], password: str, salt: bytes
) -> None:
    """export a parsed database to csv"""

    with StringIO() as csv_out:
        log("parsing data")

        w = csv.writer(csv_out)
        w.writerows(parsed_data)

        csv_out.seek(0)

        log("compressing and encrypting the database")

        file.write(
            encrypt(
                bz2.compress(csv_out.read().encode()),
                password,
                salt,
            )[0]
        )


def map_to_db(
    enc_function: Callable[[str, str, bytes], str],
    password: str,
    salt: bytes,
    parsed_data: list[list[str]],
) -> list[list[str]]:
    return list(
        map(
            lambda entry: entry[:3]
            + list(map(lambda p: enc_function(p, password, salt), entry[3:])),
            parsed_data,
        )
    )


class DatabaseCommandAction(Enum):
    DB_COMMIT = auto()
    DB_CLOSE = auto()


class DatabaseCommandParser:
    """database mode commands"""

    def _pick_entry(self, data: list[list[str]]) -> int:
        """pick an entry from a database"""

        try:
            return int(
                FzfPrompt()  # type: ignore
                .prompt(
                    (
                        f"{idx} :: {' | '.join(repr(ent[eidx]) for eidx in range(3))}"
                        for idx, ent in enumerate(data)
                    ),
                    "--prompt='pick an entry : '",
                )[0]
                .split(" ", maxsplit=1)[0]
            )
        except ProcessExecutionError:
            return self._pick_entry(data)
        except ValueError:
            ferr("picked an invalid index value")

    def _pick_entry_field(self) -> int:
        """pick an entry field from an entry"""

        try:
            return int(
                FzfPrompt()  # type: ignore
                .prompt(
                    (f"{idx} | {name}" for idx, name in enumerate(PASSWORD_STRUCT)),
                    "--prompt='pick an entry field : '",
                )[0]
                .split(" ", maxsplit=1)[0]
            )
        except ProcessExecutionError:
            return self._pick_entry_field()
        except ValueError:
            ferr("picked an invalid index value")

    def cmd_help(self, args: tuple[str, ...], **_) -> None:
        """print help : help [cmds...]"""

        print_obj_cmd_help(self, args)

    def cmd_entry(
        self,
        password: str,
        salt: bytes,
        parsed_data: list[list[str]],
        args: tuple[str, ...],
    ) -> None:
        """add a new entry to the database : entry <entry name...>"""

        if not args:
            elog("entry : missing <entry name...>")
            return

        change_db(
            parsed_data.append,
            [
                " ".join(args),
                iinput("entry URL"),
                iinput("entry note"),
                epw("entry username", password, salt),
                epw("entry password", password, salt),
            ],
        )

    def cmd_commit(self, **_) -> DatabaseCommandAction:
        """commit to the database: commit"""

        return DatabaseCommandAction.DB_COMMIT

    def cmd_ls(self, parsed_data: list[list[str]], **_) -> None:
        """list entries in your database : ls"""

        for entry in parsed_data:
            log(
                f"""{entry[0]}:
    URL:        {entry[1]}
    note:       {entry[2]}
"""
            )

    def cmd_close(self, **_) -> DatabaseCommandAction:
        """close the database : close"""

        return DatabaseCommandAction.DB_CLOSE

    def cmd_clear(self, **_) -> None:
        """clear the screen : clear"""

        clear_sc()

    def cmd_show(
        self, password: str, salt: bytes, parsed_data: list[list[str]], **_
    ) -> None:
        """show entry in full : show"""

        if not parsed_data:
            elog("no entries to show")
            return

        entry: list[str] = parsed_data[self._pick_entry(parsed_data)]

        for eidx, ent in enumerate(entry):
            content: str = ent

            if eidx > 2:
                content = pwe(ent, password, salt)

            log(f"{PASSWORD_STRUCT[eidx].capitalize():10s} {content}")

    def cmd_cp(
        self, password: str, salt: bytes, parsed_data: list[list[str]], **_
    ) -> None:
        """copy data from an entry to clipboard : cp"""

        if not parsed_data:
            elog("no entries so can't copy anything")
            return

        entry: list[str] = parsed_data[self._pick_entry(parsed_data)]
        field: int = self._pick_entry_field()

        data: str = entry[field]

        if field > 2:
            data = pwe(data, password, salt)

        to_clipboard_or_out(data)

    def cmd_rm(self, parsed_data: list[list[str]], **_) -> None:
        """remove an entry from the database : rm"""

        if not parsed_data:
            elog("cannot remove any entries from an empty database")
            return

        del parsed_data[self._pick_entry(parsed_data)]
        change_db()

    def cmd_ed(
        self, password: str, salt: bytes, parsed_data: list[list[str]], **_
    ) -> None:
        """edit an entry in the database : ed"""

        if not parsed_data:
            elog("no entries in the database to edit")
            return

        entry: list[str] = parsed_data[self._pick_entry(parsed_data)]
        field: int = self._pick_entry_field()

        input_fn: Callable[[str], str] = iinput

        if field > 2:
            input_fn = lambda prompt: epw(prompt, password, salt)
        elif field > 0:
            input_fn = lambda prompt: iinput(prompt)
        elif field == 0:
            input_fn = lambda prompt: iinput(prompt, True)

        entry[field] = input_fn(f"editing {PASSWORD_STRUCT[field]!r} for {entry[0]!r}")
        change_db()

    def cmd_cc(self, **_) -> None:
        """clear clipboard : cc"""

        clear_cb()

    def cmd_change(self, **_) -> None:
        """mark the database as changed, but don't change anything : change"""

        change_db()

    def cmd_export(
        self,
        password: str,
        salt: bytes,
        parsed_data: list[list[str]],
        args: tuple[str, ...],
    ) -> None:
        """export the password database to csv : export <out file>"""

        if not args:
            elog("export : missing <out file>")
            return
        elif not yn("export the database to csv", "n"):
            return

        verify_path(args[0])

        log("decrypting the database ...")

        new_parsed_data: list[list[str]] = [list(PASSWORD_STRUCT)] + map_to_db(
            pwe, password, salt, parsed_data
        )

        log(f"writing to {args[0]!r} ...")

        with open(args[0], "w") as csv_out:
            csv.writer(csv_out).writerows(new_parsed_data)
            log(f"database {csv_out.name!r} successfully exported")

    def cmd_import(
        self,
        password: str,
        salt: bytes,
        parsed_data: list[list[str]],
        args: tuple[str, ...],
    ) -> None:
        """import a csv database : import <in file>"""

        if not args:
            elog("import : missing <in file>")
            return
        elif not os.path.exists(args[0]):
            elog(f"export {args[0]!r} does not exist")
            return
        elif not yn("are you sure you want to import this database", "n"):
            return

        merge: bool = yn("do you want to merge rather than overwrite the database")

        log("parsing the export")

        with open(args[0], "r") as export:
            d: tuple[dict[str, str], ...] = tuple(csv.DictReader(export))

        if not d:
            elog("empty export is not valid")
            return

        log("checking fields")
        elog(f"found fields : {', '.join(d[0].keys())}")

        needed_fields: list[str | None] = []

        field: str | None
        for field in PASSWORD_STRUCT:
            if field not in d[0]:
                afield: str | None = None

                while afield is None or (afield != "" and afield not in d[0]):
                    afield = input(
                        f"field to represent {field!r} ( empty for none ) : "
                    )

                field = afield or None

            needed_fields.append(field)

        log("encrypting export ...")

        new_parsed_data: list[list[str]] = []

        for entry in d:
            pw: list[str] = []

            for fidx, nfield in enumerate(needed_fields):
                if nfield is None:
                    pw.append("" if fidx <= 3 else pwe("", password, salt))
                    continue

                if fidx >= 3:
                    entry[nfield] = eepw(entry[nfield], password, salt)

                pw.append(entry[nfield])

            new_parsed_data.append(pw)

        log("writing the export ...")

        if not merge:
            log("clearing the database ...")
            parsed_data.clear()

        change_db(parsed_data.extend, new_parsed_data)


class CommandParser:
    """home mode commands"""

    def cmd_help(self, *args: str) -> None:
        """print help : help [cmds...]"""

        print_obj_cmd_help(self, args)

    def cmd_new(self, *args: str) -> None:
        """make a new database : new <database name>"""

        if not args:
            elog("new : missing database name")
            return

        datb_path: str = mk_spath(args[0], "pdb")
        salt_path: str = mk_spath(args[0], "slt")

        log(f"making database {datb_path}({salt_path})")

        password: str = pw("database password")

        if not password and not yn(
            "are you sure you want to create a database with an empty password"
        ):
            while not password:
                password = pw("database password (required)")

        log(f"compressing and encrypting the database {datb_path!r}")

        bz2.BZ2File(datb_path, "w").close()

        with open(datb_path, "rb") as db:
            encrypted, salt = encrypt(db.read(), password)

        with open(datb_path, "wb") as dbe:
            dbe.write(encrypted)

        log(f"writting the database salt to {salt_path!r}")

        with open(salt_path, "wb") as saltf:
            saltf.write(salt)

        print(
            f"""
  done making a new database, make sure to:

    - keep {datb_path!r} safe
      * its your database, you will not have your passwords
        if you lose it
      * even though the database is basically ascii text
        i would not suggest opening it and/or editing it
        as it can mess it up
    - keep {salt_path!r} safe
      * it's just as important as your password, you
        will not be able to unlock your database without it
      * never open it in any text editor and/or word processor
        and save it because the file might get messed up
        meaning you will never unlock your database ever again"""
        )

    def cmd_open(self, *args: str) -> bool | None:
        """open a database : open <database path> <database salt path>"""

        if len(args) < 2:
            elog("open : missing <database path> and/or <database salt path>")
            return False

        password: str = pw("database password")

        log("reading the salt")

        try:
            with open(args[1], "rb") as saltf:
                salt: bytes = saltf.read()
        except FileNotFoundError:
            elog(f"salt file {args[1]!r} does not exist")
            return False

        log("decrypting and decompressing the database")

        try:
            with open(args[0], "rb") as db:
                db_data: bytes = bz2.decompress(decrypt(db.read(), password, salt))
        except FileNotFoundError:
            elog(f"database {args[0]!r} does not exist")
            return False
        except OSError as e:
            elog(
                f"potentially invalid BZ2 compressed data in database decryption, \
error: {e.__class__.__name__}: {e}"
            )
            return False
        except (InvalidSignature, InvalidToken):
            elog(
                "invalid database password, cryptography token/signature \
and/or salt"
            )
            return False

        log("making a command parser")
        parser: DatabaseCommandParser = DatabaseCommandParser()

        log("parsing database data")
        db_data_parsed: list[list[str]] = list(csv.reader(StringIO(db_data.decode())))

        log("database has been opened")

        while True:
            print()

            try:
                cmd: list[str] = (
                    input(
                        f" [{GLOBAL_STATES['cc-timer']}] \
{'*' if GLOBAL_STATES['db-changed'] else ''}{args[0]}({args[1]})> "
                    )
                    .strip()
                    .split()
                )
            except EOFError:
                print()

                if GLOBAL_STATES["db-changed"]:
                    elog("exiting without saving any changes")

                break
            except KeyboardInterrupt:
                print()
                continue

            if not cmd:
                continue

            cmd_fn: Callable[
                ...,
                DatabaseCommandAction | None,
            ] | None = getattr(parser, f"cmd_{cmd[0]}", None)

            if cmd_fn is None:
                elog(f"{cmd[0]}: command not found")
                continue

            match cmd_fn(  # type: ignore
                password=password, salt=salt, parsed_data=db_data_parsed, args=cmd[1:]
            ):
                case None:
                    pass

                case DatabaseCommandAction.DB_COMMIT:
                    if not GLOBAL_STATES["db-changed"]:
                        elog(
                            "no changes to commit, try the `change` command, \
perhaps?"
                        )
                        continue

                    log("committing to database")

                    with open(args[0], "wb") as db:
                        parsed_to_csv(db, db_data_parsed, password, salt)

                    GLOBAL_STATES["db-changed"] = False

                case DatabaseCommandAction.DB_CLOSE:
                    if GLOBAL_STATES["db-changed"] and not yn(
                        "you did not commit the recent changes, discard them"
                    ):
                        continue

                    GLOBAL_STATES["db-changed"] = False
                    break

                case _:
                    elog("unknown DatabaseCommandAction")

        return None

    def cmd_clear(self, *_: str) -> None:
        """clear the screen : clear"""

        clear_sc()

    def cmd_exit(self, *_: str) -> None:
        """exit the REPL : exit"""

        cexit(0)

    def cmd_cc(self, *_: str) -> None:
        """clear clipboard : cc"""

        clear_cb()


def main() -> int:
    """entry/main function"""

    run_main: bool = True
    ret: int = 0

    # we only need to set readline up in local ctx

    from readline import parse_and_bind, set_history_length

    parse_and_bind("tab: complete")
    set_history_length(-1)

    parser: CommandParser = CommandParser()

    # automatic clipboard clearing

    def cc_thread() -> None:
        """automatically clear clipboard ( daemon thread target function )"""

        while True:
            sleep_secs(1)

            if GLOBAL_STATES["cc-timer"] <= 0:
                continue

            GLOBAL_STATES["cc-timer"] -= 1

            if GLOBAL_STATES["cc-timer"] <= 0:
                clear_cb(False)

    elog("starting the automatic clipboard clearing daemon thread")
    Thread(target=cc_thread, daemon=True).start()

    if len(sys.argv) > 2:
        ret: int = 0 if parser.cmd_open(*sys.argv[1:]) is None else 1

        if len(sys.argv) == 3:
            run_main = False

    while run_main:
        print()

        try:
            cmd: list[str] = input(f" [{GLOBAL_STATES['cc-timer']}]> ").strip().split()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue

        if not cmd:
            continue

        cmd_fn: Callable[..., Any] | None = getattr(parser, f"cmd_{cmd[0]}", None)

        if cmd_fn is None:
            elog(f"{cmd[0]}: command not found")
            continue

        cmd_fn(*cmd[1:])

    clear_cb()
    return ret


if __name__ == "__main__":
    assert main.__annotations__.get("return") is int, "main() should return an integer"

    filter_warnings("error", category=Warning)
    sys.exit(main())
