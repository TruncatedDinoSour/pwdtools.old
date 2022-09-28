# Pwdtools

> Password tools for generating, checking and rating passwords

# Requirements

-   Python 3.8 or higher
-   Linux or any other UNIX operating system
-   Python password-strength -- https://pypi.org/project/password-strength/
-   Python plumbum -- https://pypi.org/project/plumbum/
-   Python pyfzf -- https://pypi.org/project/pyfzf/
-   Python pyperclip -- https://pypi.org/project/pyperclip/
-   Python support for the `secrets` lib
-   GNU coreutils (or an `install` utility) -- https://www.gnu.org/software/coreutils/
-   Optionally `man` utility for `man` pages -- https://www.nongnu.org/man-db/
-   Python zxcvbn -- https://pypi.org/project/zxcvbn/
-   Python cryptography -- https://pypi.org/project/cryptography/

# Installation

## Manual

```bash
python3 -m pip install --user -r requirements.txt
sudo sh ./setup.sh
```

## Environment variables

-   `PREFIX` -- Where to install the tools and resources to [`/usr/local/`]
-   `BINDIR` -- The binary directory to which to install tools to [`$PREFIX/bin/`]
-   `MANPREFIX` -- Where to install man pages to [`$PREFIX/share/man/`]
-   `I_MAN` -- Do you want to install man pages [`false`]
-   `I_DEVMAN` -- Do you want to install development man pages [`false`]

## Packages

-   Linux
    -   Gentoo linux: [app-admin/pwdtools::dinolay](https://ari-web.xyz/gentooatom/app-admin/pwdtools)

# Tools

-   `pwdgen` -- Generate strong passwords
-   `pwdinfo` -- Check password information
-   `pwdzxc` -- Get realistic password information using zxcvbn
-   `pwdmgr` -- Password manager

# Flags

-   `pwdgen`

```
Pass in the `-h` or `--help` flag(s) to the utility
or see the man page
```

-   `pwdinfo`

```
None or see the man page
```

-   `pwdzxc`

```
None or see the man page
```

-   `pwdmgr`

```
See the man page
```
