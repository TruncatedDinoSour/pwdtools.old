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
chmod a+rx ./setup.sh
sudo ./setup.sh
```

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
