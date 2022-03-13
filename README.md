# Pwdtools

> Password tools for generating, checking and rating passwords

# Requirements

- Python 3.8 or higher
- Linux or any other UNIX operating system
- Python password-strength -- https://pypi.org/project/password-strength/
- Python pyfzf -- https://pypi.org/project/pyfzf/
- Python pyperclip -- https://pypi.org/project/pyperclip/
- Python support for the `secrets` lib
- GNU coreutils (or an `install` utility) -- https://www.gnu.org/software/coreutils/
- Optionally `man` utility for `man` pages -- https://www.nongnu.org/man-db/

# Installation

## Manual

```bash
python3 -m pip install --user -r requirements.txt
chmod a+rx ./setup.sh
sudo ./setup.sh
```

## Packages

- Linux
  - Gentoo linux: [app-admin/pwdtools::dinolay](https://ari-web.xyz/gentooatom/app-admin/pwdtools)

# Tools

- `pwdgen` -- Generate strong passwords
- `pwdinfo` -- Check password information

# Flags

- `pwdgen`

```
Pass in the `-h` or `--help` flag(s) to the utility
or see the man page
```

- `pwdinfo`

```
None or see the man page
```
