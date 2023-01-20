# Pwdtools

> Password tools for generating, checking and rating passwords

# Requirements

-   python 3.10 or higher
-   linux or any other UNIX operating system
-   python support for the `secrets` lib
-   GNU coreutils (or an `install` utility) -- https://www.gnu.org/software/coreutils/
-   optionally `man` utility for `man` pages -- https://www.nongnu.org/man-db/
-   everything from `requirements.txt`

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
