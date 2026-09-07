#!/bin/sh
set -eu

usage() {
    printf '%s\n' \
        'Usage: ./install.sh [INSTALL_DIR] [BIN_DIR]' \
        '' \
        '  INSTALL_DIR  Project and private virtual-environment location.' \
        '               Default: ~/.local/share/qualys-qid-vulnerabilities' \
        '  BIN_DIR      Directory for the qid command.' \
        '               Default: ~/.local/bin'
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

SOURCE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INSTALL_DIR=${1:-"$HOME/.local/share/qualys-qid-vulnerabilities"}
BIN_DIR=${2:-"$HOME/.local/bin"}

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    printf '%s\n' 'Error: qid requires Python 3.12 or newer.' >&2
    exit 1
fi

# Resolve existing directories, while also supporting a new relative target.
if [ -d "$INSTALL_DIR" ]; then
    INSTALL_DIR=$(CDPATH= cd -- "$INSTALL_DIR" && pwd)
else
    case "$INSTALL_DIR" in
        /*) : ;;
        *) INSTALL_DIR=$(pwd)/$INSTALL_DIR ;;
    esac
fi
case "$BIN_DIR" in
    /*) : ;;
    *) BIN_DIR=$(pwd)/$BIN_DIR ;;
esac

mkdir -p "$INSTALL_DIR" "$BIN_DIR"

# Copy only the files needed to operate the tool. Existing .env is retained so
# reinstalling updates code without overwriting credentials.
cp -R "$SOURCE_DIR/src" "$INSTALL_DIR/"
cp -R "$SOURCE_DIR/config" "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/man"
cp "$SOURCE_DIR/man/qualys-qid-vulnerabilities.1" "$INSTALL_DIR/man/"
cp "$SOURCE_DIR/pyproject.toml" "$SOURCE_DIR/.env.example" "$INSTALL_DIR/"

if [ ! -e "$INSTALL_DIR/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
fi
chmod 600 "$INSTALL_DIR/.env"

if [ ! -x "$INSTALL_DIR/.venv/bin/python" ]; then
    python3 -m venv "$INSTALL_DIR/.venv"
fi

# Keep the installed project location in the launcher rather than depending
# on the caller's working directory or Python's site-packages layout.
LAUNCHER="$INSTALL_DIR/qid"
cat > "$LAUNCHER" <<EOF
#!/bin/sh
set -eu
export QID_PROJECT_ROOT='$INSTALL_DIR'
export PYTHONPATH='$INSTALL_DIR/src'\${PYTHONPATH:+:\$PYTHONPATH}
exec '$INSTALL_DIR/.venv/bin/python' -m qualys_qid_vulnerabilities.cli "\$@"
EOF
chmod 755 "$LAUNCHER"
ln -sfn "$LAUNCHER" "$BIN_DIR/qid"

printf '\nInstalled qid.\n'
printf 'Project files: %s\n' "$INSTALL_DIR"
printf 'Command:       %s/qid\n' "$BIN_DIR"
printf '\nNext steps:\n'
printf '  1. Edit %s/.env and set your Qualys gateway and credentials.\n' "$INSTALL_DIR"
printf '  2. Review %s/config/runtime.toml if you need non-secret overrides.\n' "$INSTALL_DIR"
printf '  3. Run: qid --help\n'
case ":${PATH:-}:" in
    *:"$BIN_DIR":*) : ;;
    *)
        printf '\n%s is not currently on PATH. Add it, then open a new shell:\n' "$BIN_DIR"
        printf '  export PATH="%s:\$PATH"\n' "$BIN_DIR"
        ;;
esac
