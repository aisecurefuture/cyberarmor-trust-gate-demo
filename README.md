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

To run a different build, set `IMAGE_TAG` in `.env`. Pin it rather than
using `latest`, so the demo you rehearse is the demo you give.

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

## Point a browser at it

The gate is a FastAPI service, so it serves its own interactive API
documentation. Once the stack is up:

| URL | What you get |
|---|---|
| <http://localhost:8014/docs> | Swagger UI — every endpoint, with a form. Expand `POST /evaluate`, click **Try it out**, paste a URL, **Execute**, and read the verdict and evidence in the response pane. |
| <http://localhost:8014/redoc> | The same API as reference documentation |
| <http://localhost:8014/openapi.json> | The OpenAPI spec, for generating a client |

This is the quickest way to explore the gate without writing `curl` by hand.

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

## Where is the console?

Not in here, on purpose. This repository is the **engine**, packaged so you can
verify it yourself: prebuilt images, no source, no build step, and a runner that
asserts each verdict and prints PASS/FAIL. Someone evaluating a security product
should be able to satisfy themselves that the detection works before trusting
any interface built on top of it.

The product also ships operator-facing surfaces — a customer portal with the AI
risk dashboard, action graph and evidence trail, an admin console for tenants,
policy and API keys, and an MSP console for partners managing multiple tenants —
along with endpoint agents, browser and IDE extensions, and Office add-ins. None
of those are part of this demo, because none of them are needed to check whether
the gate reaches the right verdict.

If you would like to see them, <https://cyberarmor.ai> — we will walk you
through a live tenant.

## Learn more

- Product: <https://cyberarmor.ai/url-trust-gate>
- Docs: <https://docs.cyberarmor.ai>
- Talk to us: <https://cyberarmor.ai>

---

© CyberArmor AI, Inc. Demo images are provided for evaluation. The gate's
source is not included in this repository.
