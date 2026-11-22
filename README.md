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

This demo is pinned to image tag `2026.09.18-84a0a97`, published from the CyberArmor
monorepo and stamped with the commit it was built from:

```bash
docker inspect ghcr.io/aisecurefuture/cyberarmor-url-trust-gate:2026.09.18-84a0a97 \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

`IMAGE_TAG` is **required** — `docker-compose.yml` reads `${IMAGE_TAG:?...}`,
so compose refuses to start when it is unset instead of quietly following a
floating tag. `install.sh` sets it for you from `.env.example`. To run a
different build, change that one line. Pin it, so the demo you rehearse is the
demo you give.

Runs on **macOS (Apple Silicon or Intel), Windows, and Linux**. The service
images are `linux/amd64`; on Apple Silicon Macs they run automatically under
Docker Desktop's built-in Rosetta emulation (enabled by default) — no setup
needed. If you ever disabled it, re-enable **Settings → General → "Use Rosetta
for x86/amd64 emulation."**

## Run it

```bash
git clone https://github.com/aisecurefuture/cyberarmor-trust-gate-demo.git
cd cyberarmor-trust-gate-demo
./install.sh
```

`install.sh` generates secrets, pulls the images, starts the stack, waits for
health, and runs the live demo against three crafted attack pages plus one
benign page. Total time on a fresh box is typically **under 15 minutes**
(most of it pulling images the first time). `test-pages/` carries 16 fixtures
in all — see below for the other 12.

Tear down with:

```bash
./uninstall.sh
```

## What the demo shows

`install.sh` runs the **gating set** — four fixtures the demo asserts and fails
on:

| Page | What it contains | Asserted |
|---|---|---|
| `benign.html` | an ordinary article | **allow** |
| `hidden-instruction.html` | text inside a `display:none` element | **enforcement** (warn / redact / sandbox / block / isolate) |
| `zero-width-injection.html` | text carrying zero-width Unicode characters | **enforcement** |
| `credential-harvest.html` | a sign-in form for the fictional brand Contoso | **enforcement** |

"Enforcement" rather than "block" on purpose: the action depends on the policy
in force, and asserting a specific one would make a policy change look like a
detection failure.

### The extended set

`test-pages/` carries **16 fixtures** in all. The other 12 are submitted by:

```bash
./run_url_trust_gate_demo.py --extended
```

That run prints what the gate returned for each, and divides them into three
groups with the count of each:

- **judged** (4) — `bank-card-pin.html` (a form asking for an ATM PIN),
  `brand-impersonation.html` (off-domain brand plus a credential form), and the
  two storefronts `weight-medium/` (~0.66 MB, 24 files) and `weight-heavy/`
  (~5.6 MB, 67 files, worker and framed panel). The storefronts are the
  false-positive check: a large ordinary site must come back `allow`.
- **recorded** (5) — the four `canary-*` pages, each an ordinary article with
  one sentence hidden a different way, and `download-on-load.html`. The runner
  prints the verdict and does not judge it.
- **not enforceable in this demo** (3) — `late-signin.html`,
  `late-hidden-text.html`, `redirect-to-signin.html`. These need deep scope,
  and the demo runs no detonation worker
  (`URL_TRUST_GATE_DETONATION_DEFAULT=off`), so the gate downgrades a deep
  request to standard. A permissive verdict on these three is the
  configuration, not a miss, and the runner says so on each line.

The extended expectations come from the monorepo's own records and have **not**
been re-measured against the pinned image tag. The first run against a new tag
is the measurement.

## What this build does not do

Read this before putting it in front of anyone.

**It is heuristic-only.** `TRANSFORMERS_OFFLINE=1`, `HF_HUB_OFFLINE=1`, an
empty `/models` volume. The fine-tuned prompt-injection and output-safety
classifiers are **not in these images** and never have been. The heuristic
ensemble produces real verdicts and catches the fixtures; it is not the full
product.

**The pinned images are from 2026-09-18 and three later fixes are missing.**
`demo-images.yml` has published successfully exactly once, and cannot publish
again until GitHub Actions are restored on the `aisecurefuture` account — no
job has been scheduled there since 2026-10-04. Not in these images:

| Fix | Merged | Effect on this demo |
|---|---|---|
| #1097 wildcard CORS across fourteen services | 2026-11-19 | five of them run here: `policy`, `detection`, `audit`, `response`, `url-trust-gate` |
| #837 `secure.login.gov` blocked as credential phishing | 2026-11-07 | a real sign-in URL can come back as a block |
| #836 a sign-in page blocked for a sentence Google requires it to carry | 2026-11-03 | as above |

**So do not type a real sign-in URL into this build during a demo.** The
crafted fixtures are unaffected: `test-pages/` is bind-mounted, not baked into
the images, so a `git pull` updates them without a rebuild.

**The injection classifier is validated on English.** Other writing systems are
decided by a narrower model or reported as not checked. No detection accuracy
figure is published for this or any other CyberArmor.AI surface, by policy.

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
