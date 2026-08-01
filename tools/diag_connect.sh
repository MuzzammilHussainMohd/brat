#!/bin/bash
# Connection diagnostic for `brat impersonate`.
#
# Answers one question with hard evidence: when a central connects to our
# rogue peripheral, what actually happens - at the HCI layer, at BlueZ's
# D-Bus layer, and inside BRAT?
#
# Those three can disagree, and which one is silent tells you where the
# problem is:
#   - no HCI connection event      -> the central never actually connected
#   - HCI yes, D-Bus no            -> BlueZ is not surfacing the connection
#   - D-Bus yes, BRAT no           -> BRAT's connection watch is broken
#
# Usage:  sudo bash tools/diag_connect.sh
# Then connect with nRF Connect when prompted.

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=/tmp/brat_diag
rm -rf "$OUT"; mkdir -p "$OUT"

WINDOW="${1:-45}"

echo "=========================================================="
echo " BRAT connection diagnostic"
echo " Window: ${WINDOW}s"
echo "=========================================================="
echo

# ── HCI layer ────────────────────────────────────────────────────────────────
btmon > "$OUT/hci.txt" 2>&1 &
BTMON_PID=$!

# ── BlueZ D-Bus layer ────────────────────────────────────────────────────────
cat > "$OUT/dbus_probe.py" <<'PY'
import asyncio, sys, time
from dbus_fast import BusType
from dbus_fast.aio import MessageBus

async def main(window):
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    intro = await bus.introspect("org.bluez", "/")
    obj = bus.get_proxy_object("org.bluez", "/", intro)
    mgr = obj.get_interface("org.freedesktop.DBus.ObjectManager")
    seen, t0 = set(), time.time()
    while time.time() - t0 < window:
        managed = await mgr.call_get_managed_objects()
        cur = set()
        for path, ifaces in managed.items():
            p = ifaces.get("org.bluez.Device1")
            if not p:
                continue
            c = p.get("Connected")
            if bool(getattr(c, "value", c)):
                a = p.get("Address")
                cur.add(str(getattr(a, "value", a) or path))
        for a in cur - seen:
            print(f"[+{time.time()-t0:5.1f}s] D-BUS: connected {a}", flush=True)
        for a in seen - cur:
            print(f"[+{time.time()-t0:5.1f}s] D-BUS: disconnected {a}", flush=True)
        seen = cur
        await asyncio.sleep(0.5)

asyncio.run(main(float(sys.argv[1])))
PY
"$HERE/venv/bin/python3" "$OUT/dbus_probe.py" "$WINDOW" > "$OUT/dbus.txt" 2>&1 &
DBUS_PID=$!

# ── BRAT itself ──────────────────────────────────────────────────────────────
"$HERE/venv/bin/brat" impersonate \
    --profile example_wearable --name BRAT-DIAG \
    --confirm --yes --duration "$WINDOW" > "$OUT/brat.txt" 2>&1 &
BRAT_PID=$!

sleep 4
echo "  >>> CONNECT NOW with nRF Connect to 'BRAT-DIAG' <<<"
echo "      (browse its services, tap a READ, then disconnect)"
echo
for i in $(seq $((WINDOW - 4)) -5 1); do printf "\r      %ss remaining " "$i"; sleep 5; done
echo; echo

wait $BRAT_PID 2>/dev/null
wait $DBUS_PID 2>/dev/null
sleep 1
kill $BTMON_PID 2>/dev/null; wait $BTMON_PID 2>/dev/null

# ── Report ───────────────────────────────────────────────────────────────────
echo "=========================================================="
echo " 1. HCI LAYER - did a link-layer connection happen?"
echo "=========================================================="
grep -E "LE Connection Complete|LE Enhanced Connection Complete|Disconnect Complete" \
     -A3 "$OUT/hci.txt" 2>/dev/null | grep -E "Complete|Address:|Status:|Role:" | head -20 \
  || echo "  (none seen)"
if ! grep -qE "LE (Enhanced )?Connection Complete" "$OUT/hci.txt" 2>/dev/null; then
    echo "  >> NO CONNECTION REACHED THE CONTROLLER."
fi

echo
echo "=========================================================="
echo " 2. BLUEZ D-BUS LAYER - did BlueZ report it?"
echo "=========================================================="
[ -s "$OUT/dbus.txt" ] && cat "$OUT/dbus.txt" || echo "  (nothing reported)"

echo
echo "=========================================================="
echo " 3. BRAT - what did the tool itself see?"
echo "=========================================================="
grep -E "Central connected|Central disconnected|READ|WRITE|central connected:|frames" \
     "$OUT/brat.txt" 2>/dev/null | head -20 || echo "  (nothing)"

echo
echo "Full logs in $OUT/  (hci.txt, dbus.txt, brat.txt)"
