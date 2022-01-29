#!/usr/bin/env sh

set -xe

main() {
    PREFIX="${PREFIX:-/usr/local}"
    BINDIR="${DESTDIR}${BINDIR:-${PREFIX}/bin}"

    printf "PREFIX: %s\tBINDIR: %s\n" "$PREFIX" "$BINDIR"

    mkdir -p "${BINDIR}"
    for script in src/*; do
        echo "Installing '$script'"
        install -Dm755 "$script" "${BINDIR}"
    done
}

main "$@"
