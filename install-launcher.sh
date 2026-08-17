#!/usr/bin/env bash
#
# Adds "markcleanse" to the applications menu and puts a shortcut on the Desktop.
# Run once:  bash install-launcher.sh
# Undo:      bash install-launcher.sh --remove

set -u

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/256x256/apps"
DESKTOP_FILE="$APPS/markcleanse.desktop"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"

if [ "${1:-}" = "--remove" ]; then
    rm -f "$DESKTOP_FILE" "$ICONS/markcleanse.png" "$DESKTOP_DIR/markcleanse.desktop"
    update-desktop-database "$APPS" >/dev/null 2>&1
    echo "removed the markcleanse launcher"
    exit 0
fi

mkdir -p "$APPS" "$ICONS"

# The launcher script itself must be executable for a double-click to offer
# "Run in Terminal" in Nemo.
chmod +x "$HERE/Start markcleanse.sh" "$HERE/markcleanse.sh" 2>/dev/null

if [ ! -f "$HERE/markcleanse.png" ]; then
    python3 "$HERE/tools/make_icon.py" "$HERE/markcleanse.png" >/dev/null 2>&1
fi
cp -f "$HERE/markcleanse.png" "$ICONS/markcleanse.png" 2>/dev/null

cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=markcleanse
GenericName=AI Provenance Forensics
Comment=Check files for AI provenance, hidden watermarks and forged credentials
Exec=bash "$HERE/Start markcleanse.sh"
Path=$HERE
Icon=markcleanse
Terminal=true
Categories=Utility;
Keywords=AI;forensics;metadata;C2PA;watermark;provenance;
StartupNotify=true
EOF
chmod +x "$DESKTOP_FILE"

if [ -d "$DESKTOP_DIR" ]; then
    cp -f "$DESKTOP_FILE" "$DESKTOP_DIR/markcleanse.desktop"
    chmod +x "$DESKTOP_DIR/markcleanse.desktop"
    # Cinnamon/Nemo shows an "untrusted launcher" prompt without this.
    gio set "$DESKTOP_DIR/markcleanse.desktop" metadata::trusted true 2>/dev/null
    touch "$DESKTOP_DIR/markcleanse.desktop"
fi

update-desktop-database "$APPS" >/dev/null 2>&1
gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1

echo "markcleanse launcher installed:"
echo "  menu entry : $DESKTOP_FILE"
[ -d "$DESKTOP_DIR" ] && echo "  desktop    : $DESKTOP_DIR/markcleanse.desktop"
echo "  or run     : \"$HERE/Start markcleanse.sh\""
echo
echo "Remove it later with:  bash \"$HERE/install-launcher.sh\" --remove"
