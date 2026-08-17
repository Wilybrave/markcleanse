#!/usr/bin/env bash
#
# Double-click me.
#
# Starts the markcleanse web UI and opens it in the browser. Nemo will offer
# "Run in Terminal" — pick that, and this window becomes the stop button.
#
# Everything stays on this machine: the server binds to 127.0.0.1 only, and
# dropped files are scanned in memory and never written to disk.

set -u

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$HERE" || exit 1

printf '\033[1m markcleanse \033[0m — AI provenance & watermark forensics\n\n'

if ! command -v python3 >/dev/null 2>&1; then
    echo "  python3 is not installed. On Mint:  sudo apt install python3"
    echo
    read -r -p "  Press Enter to close..." _
    exit 1
fi

# If it is already running, just open another tab rather than starting a second
# copy — double-clicking a launcher twice is a normal thing to do.
#
# But only reuse a server running THIS directory. If a second copy of the
# project is already serving in the launcher's port range, reusing it silently
# opens the wrong app: the right launcher, the wrong code, and features that
# were added here appear to be missing.
for port in $(seq 8420 8439); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        exec 3<&- 2>/dev/null
        info=$(curl -fsS "http://127.0.0.1:$port/api/info" 2>/dev/null) || continue
        root=$(printf '%s' "$info" | sed -n 's/.*"root": *"\([^"]*\)".*/\1/p')
        if [ "$root" = "$HERE" ]; then
            echo "  Already running on http://127.0.0.1:$port/ — opening it."
            xdg-open "http://127.0.0.1:$port/" >/dev/null 2>&1 &
            sleep 1
            exit 0
        fi
        echo "  Note: another markcleanse is serving port $port from:"
        echo "        ${root:-unknown}"
        echo "        Starting this one separately."
        echo
    fi
done

echo "  Starting… your browser will open in a moment."
echo "  Close this window (or press Ctrl-C) to stop."
echo

python3 web/serve.py --open
status=$?

echo
if [ $status -ne 0 ]; then
    echo "  markcleanse exited with status $status"
    read -r -p "  Press Enter to close..." _
fi
