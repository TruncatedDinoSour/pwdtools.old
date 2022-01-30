#!/usr/bin/env sh

[ "$DEBUG" ] && set -x
set -e

main() {
    PREFIX="${PREFIX:-/usr/local}"
    BINDIR="${DESTDIR}${BINDIR:-${PREFIX}/bin}"
    MANPREFIX="${DESTDIR}${MANPREFIX:-${PREFIX}/share/man}"

    printf "PREFIX: %s\tBINDIR: %s\tMANPREFIX: %s\n" "$PREFIX" "$BINDIR" "$MANPREFIX"

    install -d "$BINDIR"
    (command -v man >/dev/null && install -d "${MANPREFIX}/man1/$man_page") || true

    for script in src/*; do
        echo "Installing '$script'"
        install -Dm755 "$script" "$BINDIR"

        man_page="$(basename "$script").1"
        local_man_page="doc/$man_page"

        if [ -f "$local_man_page" ] && [ -d "$MANPREFIX" ] && command -v man >/dev/null; then
            echo "Installing man page: $man_page"

            install -Dm0644 "$local_man_page" "${MANPREFIX}/man1/$man_page"
            mandb -qf "${MANPREFIX}/man1/$man_page"
        fi
    done
}

main "$@"
