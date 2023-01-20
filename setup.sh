#!/usr/bin/env sh

[ "$DEBUG" ] && set -x
set -e

main() {
    PREFIX="${PREFIX:-/usr/local}"
    BINDIR="${DESTDIR}${BINDIR:-${PREFIX}/bin}"
    MANPREFIX="${DESTDIR}${MANPREFIX:-${PREFIX}/share/man}"

    printf "PREFIX: %s\tBINDIR: %s\tMANPREFIX: %s\n" "$PREFIX" "$BINDIR" "$MANPREFIX"

    install -d "$PREFIX"

    if [ "$I_MAN" ]; then
        install -d "$BINDIR"
        (command -v man >/dev/null && install -d "${MANPREFIX}/man1") || true
    fi

    for script in src/*.py; do
        sc_base="$(basename "$script" .py)"

        echo "installing '$script'"
        install -Dm755 "$script" "$BINDIR/$sc_base"

        if [ "$I_MAN" ]; then
            man_page="$sc_base.1"
            local_man_page="doc/man/$man_page"

            if [ -f "$local_man_page" ] && [ -d "$MANPREFIX" ] && command -v man >/dev/null; then
                echo "installing man page : $man_page"

                install -Dm0644 "$local_man_page" "${MANPREFIX}/man1/$man_page"
                mandb -qf "${MANPREFIX}/man1/$man_page"
            fi
        fi
    done

    if [ "$I_DEVMAN" ]; then
        echo "installing dev manuals"

        (command -v man >/dev/null && install -d "${MANPREFIX}/man5") || true

        for man5 in doc/extra/man/*; do
            man5_page="$(basename "$man5")"
            echo "installing : $man5_page"

            install -Dm0644 "$man5" "${MANPREFIX}/man5/$man5_page"
            mandb -qf "${MANPREFIX}/man5/$man5_page"
        done
    fi
}

main "$@"
