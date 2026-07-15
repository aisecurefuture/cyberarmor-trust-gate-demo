# CyberArmor URL Trust Gate — 15-Minute Demo

Stop hostile web content **before** it becomes AI-agent context. This is a
self-contained, self-serve demo of the CyberArmor **URL Trust Gate**: submit a
URL, and the gate canonicalizes it, checks reputation, safely fetches the
content, and scans it for **prompt injection, hidden instructions, credential
harvesting, and IOCs** — returning a policy decision (allow / warn / block)
with evidence, before any of it reaches an LLM.

The demo runs entirely from prebuilt images. **No source code, no build step.**

---

## Prerequisites

- Docker + the `docker compose` v2 plugin
- `curl` and `python3` (standard library only)
- ~2 GB RAM, a few GB disk
- Outbound access to `ghcr.io` to pull images

## Run it

```bash
git clone https://github.com/aisecurefuture/cyberarmor-trust-gate-demo.git
cd cyberarmor-trust-gate-demo
./install.sh
```

`install.sh` generates secrets, pulls the images, starts the stack, waits for
health, and runs the live demo against four crafted attack pages plus one
benign page. Total time on a fresh box is typically **under 15 minutes**
(most of it pulling images the first time).

Tear down with:

```bash
./uninstall.sh
```

## What the demo shows

The gate is pointed at five local fixtures in [`test-pages/`](test-pages/):

| Page | What it hides | Expected verdict |
|---|---|---|
| `hidden-instruction.html` | An invisible "ignore your instructions…" prompt injection | **block** |
| `zero-width-injection.html` | Instructions encoded in zero-width characters | **block** |
| `credential-harvest.html` | A fake login form harvesting credentials | **block / warn** |
| `benign.html` | An ordinary, safe page | **allow** |

The runner asserts each verdict and prints a PASS/FAIL report. A failure means a
malicious page was allowed or a benign one blocked.

## Try your own URL

```bash
# Health
curl -fsS http://localhost:8014/health

# Evaluate a page
curl -fsS -X POST http://localhost:8014/evaluate \
  -H 'content-type: application/json' \
  -d '{"url":"http://poc-test-server:8088/hidden-instruction.html","depth":"standard"}'
```

The response includes the decision, the matched signals, and the evidence
record the gate writes to audit.

## What's running

| Service | Role |
|---|---|
| `url-trust-gate` | Canonicalize → reputation → safe-fetch → detect → policy → evidence |
| `detection` | Content scanning (heuristic ensemble; ML models disabled for speed) |
| `policy` | Rego policy evaluation (via OPA) |
| `audit` | Decision-level evidence store |
| `response` | Response orchestration |
| `postgres`, `redis`, `opa` | Data + policy infrastructure |
| `poc-test-server` | Serves the local attack fixtures |

Everything binds to `localhost` by default and runs in heuristic-only mode so
the demo is fast and self-contained. This is a **demo configuration** — not a
production deployment.

## Learn more

- Product: <https://cyberarmor.ai/url-trust-gate>
- Docs: <https://docs.cyberarmor.ai>
- Talk to us: <https://cyberarmor.ai>

---

© CyberArmor AI, Inc. Demo images are provided for evaluation. The gate's
source is not included in this repository.
