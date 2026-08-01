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
# Usage:  sudo bash tools/diag_connect.sh [SECONDS] [PROFILE] [ADAPTER]
# Then connect with nRF Connect when prompted. Note that nRF Connect caches
# stale scan results - rescan, do not tap an entry left over from a previous
# run, or the connection silently goes nowhere.

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=/tmp/brat_diag
rm -rf "$OUT"; mkdir -p "$OUT"

WINDOW="${1:-45}"
PROFILE="${2:-example_wearable}"
ADAPTER="${3:-}"
[ -n "$ADAPTER" ] && ADAPTER_ARG="--adapter $ADAPTER" || ADAPTER_ARG=""
SESSION="$OUT/session.json"

echo "=========================================================="
echo " BRAT connection diagnostic"
echo " Window: ${WINDOW}s   Profile: ${PROFILE}   Adapter: ${ADAPTER:-default}"
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
    --profile "$PROFILE" --name BRAT-DIAG $ADAPTER_ARG \
    --session-log "$SESSION" \
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

cat > "$OUT/crosscheck.py" <<'CROSSCHECK'
import json
import sys

doc = json.load(open(sys.argv[1]))
hvn = int(sys.argv[2])
entries = doc.get("entries", [])
tx = [e for e in entries if e["direction"] == "tx"]
rx = [e for e in entries if e["direction"] == "rx"]
delivered = [e for e in tx if e.get("delivered")]
dropped = [e for e in tx if e.get("delivered") is False]

print(f"  BRAT built      : {len(tx)} outbound frame(s)")
print(f"  marked delivered: {len(delivered)}")
print(f"  marked dropped  : {len(dropped)}"
      + ("  (built, but no central had subscribed)" if dropped else ""))
print(f"  HCI transmitted : {hvn}")
print(f"  client wrote    : {len(rx)} frame(s), "
      f"{sum(1 for e in rx if e.get('frame_ok'))} decoded cleanly")

if dropped and not delivered:
    print("  >> Everything BRAT sent was dropped by BlueZ: the client never")
    print("     subscribed. See the CCCD section above - that is the blocker.")
elif delivered and hvn == 0:
    print("  >> BRAT believes it sent frames the controller never transmitted.")
    print("     That is a bless/BlueZ problem, not a profile problem.")
elif rx and not tx:
    print("  >> The client wrote to us and got nothing back. Either the profile")
    print("     has no protocol block, or no rule matches what it sent.")
CROSSCHECK

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
echo
echo "=========================================================="
echo " 4. GATT DETAIL - MTU, CCCD, and notifications on the wire"
echo "=========================================================="
# The ATT MTU decides whether a long response arrives as one notification or
# several, and whether a frame can arrive in a single write at all.
echo "-- ATT MTU --"
grep -E "Exchange MTU (Request|Response)" -A2 "$OUT/hci.txt" 2>/dev/null \
     | grep -E "MTU" | head -6 || echo "  (none seen - default 23)"

# A CCCD write is the client saying "start sending me things", and for many
# devices it is what triggers its first command. Without one, nothing
# downstream can work and every response we build is discarded by BlueZ.
echo
echo "-- Subscription (CCCD) --"
grep -E "Central subscribed" "$OUT/brat.txt" 2>/dev/null \
  || echo "  >> BRAT saw no subscription. BlueZ transmits nothing until there is one."

# The only ground truth for "did our response actually leave the controller".
echo
echo "-- Notifications transmitted --"
HVN=$(grep -cE "Handle Value Notification" "$OUT/hci.txt" 2>/dev/null || echo 0)
echo "  HCI notifications: $HVN"

echo
echo "=========================================================="
echo " 5. CROSS-CHECK - what BRAT believes vs what the radio did"
echo "=========================================================="
# A mismatch localises the fault immediately.
if [ -s "$SESSION" ]; then
    "$HERE/venv/bin/python3" "$OUT/crosscheck.py" "$SESSION" "$HVN"
else
    echo "  (no session log - BRAT may not have started; see brat.txt)"
fi

echo
echo "Full logs in $OUT/  (hci.txt, dbus.txt, brat.txt, session.json)"
echo "Draft a protocol block from what the client sent:"
echo "  brat protocol infer --session-log $SESSION"
