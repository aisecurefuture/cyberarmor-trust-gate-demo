#!/usr/bin/env bash
# CyberArmor URL Trust Gate — 15-minute self-serve demo installer.
#
# Runs entirely from prebuilt images pulled from GitHub Container Registry.
# There is NO build step and NO source code — the demo is image-only.
#
# What this does on a fresh Linux/macOS box with Docker:
#   1. Verifies prerequisites (docker, docker compose v2, curl, python3).
#   2. Generates .env from .env.example with fresh random secrets (idempotent).
#   3. Pulls the prebuilt images and starts the minimal gate stack.
#   4. Waits for the gate to become healthy.
#   5. Runs run_url_trust_gate_demo.py against four crafted attack pages.
#   6. Prints elapsed wall-clock time and next steps.
#
# Idempotent. Re-running reuses an existing .env and restarts crashed services.
# Tear down with:  ./uninstall.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
DEMO_RUNNER="$ROOT_DIR/run_url_trust_gate_demo.py"

START_TS=$(date +%s)

c_blue=$'\033[36m'; c_green=$'\033[32m'; c_yellow=$'\033[33m'; c_red=$'\033[31m'; c_reset=$'\033[0m'
step() { echo; echo "${c_blue}==>${c_reset} $*"; }
ok()   { echo "    ${c_green}ok${c_reset}: $*"; }
warn() { echo "    ${c_yellow}warn${c_reset}: $*"; }
fail() { echo "    ${c_red}fail${c_reset}: $*" >&2; }
elapsed() { local now; now=$(date +%s); local s=$(( now - START_TS )); printf "%dm%02ds" $(( s/60 )) $(( s%60 )); }

# ----------------------------------------------------------- prerequisites --
step "Checking prerequisites"
missing=()
for cmd in docker curl python3; do
  command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if (( ${#missing[@]} > 0 )); then
  fail "missing required commands: ${missing[*]}"; exit 1
fi
docker compose version >/dev/null 2>&1 || { fail "docker compose v2 plugin required"; exit 1; }
docker info >/dev/null 2>&1 || { fail "docker daemon not reachable"; exit 1; }
ok "docker, docker compose, curl, python3 available"

# ------------------------------------------------------- env file generation --
step "Generating .env (idempotent)"
if [[ -f "$ENV_FILE" ]]; then
  ok ".env already exists; leaving secrets untouched"
else
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  python3 - "$ENV_FILE" <<'PY'
import secrets, sys
path = sys.argv[1]
with open(path) as f: lines = f.readlines()
out, n = [], 0
for line in lines:
    if "=" in line and not line.lstrip().startswith("#"):
        key, _, val = line.rstrip("\n").partition("=")
        if val.strip().startswith("change-me"):
            out.append(f"{key}={secrets.token_hex(24)}\n"); n += 1; continue
    out.append(line)
with open(path, "w") as f: f.writelines(out)
print(f"replaced {n} change-me values with random secrets")
PY
  ok "wrote .env with freshly generated secrets"
fi

# --------------------------------------------------------------- pull images --
step "Pulling prebuilt images"
cd "$ROOT_DIR"
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull
ok "images pulled (elapsed: $(elapsed))"

# ----------------------------------------------------------- bring up stack --
step "Starting the URL Trust Gate stack"
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d
ok "compose up returned (elapsed: $(elapsed))"

# ------------------------------------------------------------- wait for health --
step "Waiting for gate health endpoint"
GATE_PORT="8014"
for i in $(seq 1 90); do
  if curl -fsS "http://localhost:${GATE_PORT}/health" >/dev/null 2>&1; then
    ok "url-trust-gate is healthy (after ${i}s)"; break
  fi
  if (( i == 90 )); then
    fail "url-trust-gate did not become healthy after 90s"
    fail "logs: docker compose -f $COMPOSE_FILE logs url-trust-gate detection policy"
    exit 1
  fi
  sleep 1
done

# ---------------------------------------------------------- run the demo --
step "Running URL Trust Gate live demo"
if ! python3 "$DEMO_RUNNER"; then
  fail "demo runner reported failures (elapsed: $(elapsed))"
  fail "logs: docker compose -f $COMPOSE_FILE logs detection url-trust-gate"
  exit 1
fi

# ---------------------------------------------------------- summary --
step "Demo complete (total time: $(elapsed))"
cat <<EOF

  The URL Trust Gate evaluated four crafted attack pages and one benign page,
  blocking the malicious ones and allowing the safe one.

  Try it yourself:

    • Health:
        curl -fsS http://localhost:8014/health

    • Evaluate a URL:
        curl -fsS -X POST http://localhost:8014/evaluate \\
          -H 'content-type: application/json' \\
          -d '{"url":"http://poc-test-server:8088/hidden-instruction.html","depth":"standard"}'

  Tear down:  ./uninstall.sh

EOF
