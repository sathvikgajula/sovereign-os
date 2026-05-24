#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# Sovereign OS — Real-time Telemetry Audit Script
# ═══════════════════════════════════════════════════════════════════════
#
# Monitors RUST_LOG=debug output for QUIC path migration sequences.
# Tracks per-CID state machine:
#   PATH_CHALLENGE sent → PATH_RESPONSE received → path validated
#
# Usage:
#   RUST_LOG=debug cargo run --bin pq-daemon 2>&1 | ./telemetry_audit.sh
#   cat sovereign_debug.log | ./telemetry_audit.sh
#
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

GREEN='\033[32m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
echo -e "${CYAN} Sovereign OS — Hydra Tunnel Telemetry Monitor${RESET}"
echo -e "${CYAN} Tracking: PATH_CHALLENGE → PATH_RESPONSE → validated${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${RESET}"
echo ""

awk '
BEGIN {
    # ANSI color codes
    GREEN  = "\033[32m"
    YELLOW = "\033[33m"
    CYAN   = "\033[36m"
    RESET  = "\033[0m"
    total  = 0
}

# Extract Connection ID from the log line using portable awk.
# Tries several common quinn log patterns.
function extract_cid(line,    cid, pos, rest, i) {
    # Pattern 1: cid=<value>
    pos = index(line, "cid=")
    if (pos > 0) {
        rest = substr(line, pos + 4)
        cid = ""
        for (i = 1; i <= length(rest); i++) {
            c = substr(rest, i, 1)
            if (c == " " || c == "," || c == "]" || c == ")") break
            cid = cid c
        }
        if (cid != "") return cid
    }
    # Pattern 2: CID=<value> or CID:<value>
    pos = index(line, "CID")
    if (pos > 0) {
        rest = substr(line, pos + 3)
        # Skip = or :
        if (substr(rest, 1, 1) == "=" || substr(rest, 1, 1) == ":") rest = substr(rest, 2)
        cid = ""
        for (i = 1; i <= length(rest); i++) {
            c = substr(rest, i, 1)
            if (c == " " || c == "," || c == "]" || c == ")") break
            cid = cid c
        }
        if (cid != "") return cid
    }
    # Pattern 3: connection=<value>
    pos = index(line, "connection=")
    if (pos > 0) {
        rest = substr(line, pos + 11)
        cid = ""
        for (i = 1; i <= length(rest); i++) {
            c = substr(rest, i, 1)
            if (c == " " || c == "," || c == "]" || c == ")") break
            cid = cid c
        }
        if (cid != "") return cid
    }
    # Pattern 4: conn_id=<value>
    pos = index(line, "conn_id=")
    if (pos > 0) {
        rest = substr(line, pos + 8)
        cid = ""
        for (i = 1; i <= length(rest); i++) {
            c = substr(rest, i, 1)
            if (c == " " || c == "," || c == "]" || c == ")") break
            cid = cid c
        }
        if (cid != "") return cid
    }
    return "default"
}

# State machine transitions per CID:
#   0 (or unset) → waiting for PATH_CHALLENGE sent
#   1            → PATH_CHALLENGE sent, waiting for PATH_RESPONSE received
#   2            → PATH_RESPONSE received, waiting for path validated

/PATH_CHALLENGE/ && /sent|sending|transmit/ {
    cid = extract_cid($0)
    if (!(cid in state) || state[cid] == 0) {
        state[cid] = 1
        printf "%s[TELEMETRY]%s CID=%s — PATH_CHALLENGE sent => awaiting RESPONSE\n", YELLOW, RESET, cid
    }
    next
}

/PATH_RESPONSE/ && /received|recv|accepted/ {
    cid = extract_cid($0)
    if (cid in state && state[cid] == 1) {
        state[cid] = 2
        printf "%s[TELEMETRY]%s CID=%s — PATH_RESPONSE received => awaiting validation\n", YELLOW, RESET, cid
    }
    next
}

/path.validated|path_validated|validated.*path|migration.*complete/ {
    cid = extract_cid($0)
    if (cid in state && state[cid] == 2) {
        state[cid] = 0
        total++
        printf "\n%s[SUCCESS] HYDRA TUNNEL RE-ANCHORED [CID: %s]%s\n\n", GREEN, cid, RESET
    }
    next
}

END {
    printf "\n%s==============================================================%s\n", CYAN, RESET
    printf "%s Telemetry Summary: %d tunnel re-anchor(s) completed.%s\n", CYAN, total, RESET
    printf "%s==============================================================%s\n", CYAN, RESET
}
'
