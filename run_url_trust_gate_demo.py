#!/usr/bin/env python3
"""15-minute PoC demo runner for the URL Trust Gate.

Posts each crafted test URL to the running gate and prints the verdict plus a
pass/fail summary. Exits non-zero if the demo fails -- the benign page got
blocked, or a malicious page got allowed.

Run AFTER ./install.sh brings the stack up. Reads the gate's API secret from
./.env, which the installer writes.

Usage:
    ./run_url_trust_gate_demo.py
    ./run_url_trust_gate_demo.py --gate-url http://localhost:8014
    ./run_url_trust_gate_demo.py --extended     # all 16 fixtures, not just the 4
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


# In the standalone demo repo the runner and .env both live at the repo root.
ENV_FILE = Path(__file__).resolve().parent / ".env"

# Test URLs are reached over the public host network — the gate's
# safe crawler resolves the SSRF allowlist hostname `poc-test-server`
# from inside the docker network.
GATE_URL_DEFAULT = "http://localhost:8014"
TEST_BASE_URL_INTERNAL = "http://poc-test-server:8088"

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m•\033[0m"


@dataclass
class TestCase:
    name: str
    path: str
    expected_action_set: frozenset
    expected_signal: str  # human-readable description for the report


@dataclass
class ExtendedCase:
    """A fixture beyond the four the PoC gates on.

    ``expected_action_set`` empty means REPORT ONLY -- the runner prints what
    the gate said and does not judge it. ``requires`` names a capability this
    demo deliberately does not run, so the page cannot be enforced here and a
    permissive verdict is the configuration, not a miss.

    PROVENANCE OF THE EXPECTATIONS. These come from the monorepo's own records
    -- test-pages/index.html and docs/architecture/capability-status.md -- and
    have NOT been re-measured against the image set this demo pins. The first
    run against a new tag is the measurement; a wrong expectation shows up here
    as a FAIL rather than as a quiet untruth.
    """
    name: str
    path: str
    expected_action_set: frozenset
    note: str
    requires: Optional[str] = None


# Capability names this demo does not provide, and why.
UNAVAILABLE = {
    "detonation": (
        "the demo runs no detonation worker and sets "
        "URL_TRUST_GATE_DETONATION_DEFAULT=off, so the gate downgrades a deep "
        "request to standard. Script-inserted content is not in a static crawl"
    ),
    "ml-models": (
        "the demo is heuristic-only (TRANSFORMERS_OFFLINE=1, HF_HUB_OFFLINE=1, "
        "empty /models) -- the fine-tuned classifiers are not in these images"
    ),
}


EXTENDED: List[ExtendedCase] = [
    ExtendedCase(
        name="card-PIN verification form (fictional bank)",
        path="/bank-card-pin.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        note="a form asking for an ATM PIN scores credential_harvest on its own",
    ),
    ExtendedCase(
        name="payment notice for a fictional brand, with a sign-in form",
        path="/brand-impersonation.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        note="off-domain brand match plus a credential form",
    ),
    ExtendedCase(
        name="storefront, ~0.66 MB over 24 files",
        path="/weight-medium/index.html",
        expected_action_set=frozenset({"allow"}),
        note="a large ordinary site must not be flagged -- this is the false-positive check",
    ),
    ExtendedCase(
        name="storefront, ~5.6 MB over 67 files, worker + framed panel",
        path="/weight-heavy/index.html",
        expected_action_set=frozenset({"allow"}),
        note="same check at the size where a crawler budget starts to bind",
    ),
    ExtendedCase(
        name="canary -- sentence inside a display:none element",
        path="/canary-hidden-block.html",
        expected_action_set=frozenset(),
        note="safe-fetch should strip the sentence before anything scores it; "
             "this runner prints the verdict, it does not inspect the extract",
    ),
    ExtendedCase(
        name="canary -- sentence in invisible Unicode tag characters",
        path="/canary-zero-width.html",
        expected_action_set=frozenset(),
        note="as above",
    ),
    ExtendedCase(
        name="canary -- sentence inside an HTML comment",
        path="/canary-html-comment.html",
        expected_action_set=frozenset(),
        note="as above",
    ),
    ExtendedCase(
        name="canary -- sentence in white text on a white background",
        path="/canary-white-on-white.html",
        expected_action_set=frozenset(),
        note="as above",
    ),
    ExtendedCase(
        name="script starts a download with no click",
        path="/download-on-load.html",
        expected_action_set=frozenset(),
        note="outcome is recorded, not asserted",
    ),
    ExtendedCase(
        name="sign-in form a script builds after load",
        path="/late-signin.html",
        expected_action_set=frozenset(),
        note="enforced only at deep scope",
        requires="detonation",
    ),
    ExtendedCase(
        name="display:none element a script inserts after load",
        path="/late-hidden-text.html",
        expected_action_set=frozenset(),
        note="enforced only at deep scope",
        requires="detonation",
    ),
    ExtendedCase(
        name="script moves the browser to the sign-in fixture",
        path="/redirect-to-signin.html",
        expected_action_set=frozenset(),
        note="enforced only at deep scope",
        requires="detonation",
    ),
]


CASES: List[TestCase] = [
    TestCase(
        name="benign tea-blends article",
        path="/benign.html",
        expected_action_set=frozenset({"allow"}),
        expected_signal="no risk signals",
    ),
    TestCase(
        name="display:none promptware payload",
        path="/hidden-instruction.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="prompt_injection score elevated",
    ),
    TestCase(
        name="zero-width-character injection",
        path="/zero-width-injection.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="prompt_injection / promptware score elevated",
    ),
    TestCase(
        name="credential-harvest sign-in page",
        path="/credential-harvest.html",
        expected_action_set=frozenset({"warn", "redact", "sandbox", "block", "isolate"}),
        expected_signal="credential_harvest + brand_impersonation",
    ),
]


def read_env_value(key: str, default: str) -> str:
    """Best-effort .env reader. Avoids dotenv dep so the PoC can run
    on a clean machine with just the stdlib."""
    if not ENV_FILE.exists():
        return os.environ.get(key, default)
    try:
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith(f"{key}=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return os.environ.get(key, default)


def http_post_json(
    url: str, payload: dict, headers: dict, timeout: float
) -> tuple[int, dict | str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(text)
            except json.JSONDecodeError:
                return resp.status, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return e.code, json.loads(text)
        except Exception:
            return e.code, text
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def evaluate(
    gate_url: str, api_key: str, page_url: str, depth: str, tenant: str
) -> dict:
    return http_post_json(
        f"{gate_url.rstrip('/')}/evaluate",
        {
            "tenant_id": tenant,
            "url": page_url,
            "source": "poc-demo-runner",
            "depth": depth,
        },
        {"x-api-key": api_key},
        timeout=20.0,
    )[1]


def wait_for_gate(gate_url: str, max_seconds: int = 60) -> bool:
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"{gate_url.rstrip('/')}/health", timeout=2
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def fmt_scores(scores: dict) -> str:
    if not isinstance(scores, dict):
        return ""
    interesting = [
        (k, v) for k, v in scores.items()
        if isinstance(v, (int, float)) and v >= 0.05
    ]
    interesting.sort(key=lambda kv: kv[1], reverse=True)
    return ", ".join(f"{k}={v:.2f}" for k, v in interesting[:5]) or "all-zero"


def run_extended(gate_url: str, api_key: str, depth: str, tenant: str) -> int:
    """Submit the fixtures beyond the gating four. Returns the failure count.

    Only cases carrying an expected action set can fail. A report-only case
    prints what the gate said; a capability-gated case says which capability
    this demo does not run, so a permissive verdict is read as the
    configuration rather than as a miss. Every tally prints its denominator.
    """
    print(f"{INFO} extended fixtures ({len(EXTENDED)} pages)")
    print()

    failures = 0
    asserted = reported = gated = 0

    for case in EXTENDED:
        page_url = f"{TEST_BASE_URL_INTERNAL}{case.path}"
        print(f"{INFO} {case.name}")
        print(f"      url       : {page_url}")
        print(f"      about     : {case.note}")
        if case.requires:
            gated += 1
            print(f"      NOT ENFORCEABLE HERE: needs {case.requires} -- "
                  f"{UNAVAILABLE.get(case.requires, 'not available in this demo')}")
        elif case.expected_action_set:
            asserted += 1
            print(f"      expecting : {' or '.join(sorted(case.expected_action_set))}")
        else:
            reported += 1
            print("      expecting : (report only -- not judged)")

        result = evaluate(gate_url, api_key, page_url, depth=depth, tenant=tenant)
        if not isinstance(result, dict):
            print(f"      {FAIL} non-JSON response: {result}")
            if case.expected_action_set and not case.requires:
                failures += 1
            print()
            continue

        decision = (result.get("decision") or {}).get("action", "")
        reason = (result.get("decision") or {}).get("reason", "")
        print(f"      action    : {decision}")
        print(f"      reason    : {reason}")
        print(f"      scores    : {fmt_scores(result.get('scores') or {})}")

        if case.requires or not case.expected_action_set:
            print(f"      result    : {INFO} recorded")
        elif decision in case.expected_action_set:
            print(f"      result    : {PASS}")
        else:
            print(f"      result    : {FAIL} -- got {decision!r}, expected one of "
                  f"{sorted(case.expected_action_set)}")
            failures += 1
        print()

    print(f"{INFO} extended: {len(EXTENDED)} pages submitted -- "
          f"{asserted} judged, {reported} recorded, {gated} not enforceable here")
    print(f"{INFO} extended expectations come from the monorepo's records and were "
          f"NOT re-measured against this image tag; a FAIL above is that gap showing.")
    print()
    return failures


def run(gate_url: str, depth: str, tenant: str, extended: bool = False) -> int:
    api_key = read_env_value("URL_TRUST_GATE_API_SECRET", "change-me-url-trust-gate")

    print(f"{INFO} URL Trust Gate PoC demo")
    print(f"{INFO} gate    : {gate_url}")
    print(f"{INFO} depth   : {depth}")
    print(f"{INFO} tenant  : {tenant}")
    print(f"{INFO} secret  : {'(default — local PoC only)' if api_key == 'change-me-url-trust-gate' else '(from .env)'}")
    print()

    print(f"{INFO} Waiting for gate /health ...")
    if not wait_for_gate(gate_url):
        print(f"  {FAIL} gate did not become ready at {gate_url}")
        print("       run scripts/poc/install.sh first, or check `docker compose ps`")
        return 2
    print(f"  {PASS} gate is up")
    print()

    failures = 0
    for case in CASES:
        page_url = f"{TEST_BASE_URL_INTERNAL}{case.path}"
        print(f"{INFO} {case.name}")
        print(f"      url       : {page_url}")
        print(f"      expecting : {' or '.join(sorted(case.expected_action_set))} ({case.expected_signal})")

        result = evaluate(gate_url, api_key, page_url, depth=depth, tenant=tenant)
        if not isinstance(result, dict):
            print(f"      {FAIL} non-JSON response: {result}")
            failures += 1
            print()
            continue

        decision = (result.get("decision") or {}).get("action", "")
        reason = (result.get("decision") or {}).get("reason", "")
        scores = result.get("scores") or {}
        elapsed = result.get("elapsed_ms")

        print(f"      action    : {decision}")
        print(f"      reason    : {reason}")
        print(f"      scores    : {fmt_scores(scores)}")
        if elapsed is not None:
            print(f"      latency   : {elapsed} ms")

        if decision in case.expected_action_set:
            print(f"      result    : {PASS}")
        else:
            print(f"      result    : {FAIL} — got {decision!r}, expected one of {sorted(case.expected_action_set)}")
            failures += 1
        print()

    if extended:
        failures += run_extended(gate_url, api_key, depth, tenant)

    total = len(CASES)
    passed = total - failures
    print(f"{INFO} summary: {passed}/{total} passed (gating set)")
    if failures == 0:
        print(f"  {PASS} URL Trust Gate PoC demo succeeded")
        return 0
    print(f"  {FAIL} URL Trust Gate PoC demo had {failures} failure(s)")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--gate-url", default=os.environ.get("URL_TRUST_GATE_URL", GATE_URL_DEFAULT))
    p.add_argument("--depth", default="standard", choices=["fast", "standard", "deep"])
    p.add_argument("--tenant", default="poc")
    p.add_argument(
        "--extended",
        action="store_true",
        help="also submit the 12 fixtures beyond the gating four, printing what "
             "each returned and which cannot be enforced in this demo",
    )
    args = p.parse_args(argv)
    return run(args.gate_url, args.depth, args.tenant, extended=args.extended)


if __name__ == "__main__":
    raise SystemExit(main())
