"""Send a signed GitHub ``pull_request`` webhook to a local CodeGuard instance.

This is the offline path for demos: no GitHub App, no public callback URL, no
ngrok. It builds a realistic PR payload, signs the raw body with
HMAC-SHA256 (the same secret the receiver verifies), and posts it.

Usage::

    python scripts/emit_pr_webhook.py --repo encode/fastapi --pr 42
    python scripts/emit_pr_webhook.py --sha $(git rev-parse HEAD) --secret mysecret

The secret is read from ``--secret`` or ``GITHUB_WEBHOOK_SECRET``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def build_payload(
    *,
    repo_full_name: str,
    clone_url: str,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    base_branch: str,
    head_branch: str,
) -> dict:
    return {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "number": pr_number,
            "draft": False,
            "head": {"sha": head_sha, "ref": head_branch},
            "base": {"sha": base_sha, "ref": base_branch},
        },
        "repository": {
            "full_name": repo_full_name,
            "clone_url": clone_url or f"https://github.com/{repo_full_name}.git",
            "html_url": f"https://github.com/{repo_full_name}",
            "default_branch": base_branch,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit a signed PR webhook")
    parser.add_argument("--url", default="http://127.0.0.1:8000/webhook/github")
    parser.add_argument("--repo", default="encode/fastapi", help="owner/name")
    parser.add_argument(
        "--clone-url",
        default="",
        help="Repository clone URL. Point it at a local path to scan offline.",
    )
    parser.add_argument("--pr", type=int, default=42)
    parser.add_argument("--sha", default="", help="head commit SHA (default: random)")
    parser.add_argument("--base-sha", default="", help="base commit SHA")
    parser.add_argument("--base-branch", default="master")
    parser.add_argument("--head-branch", default="feature/codeguard-demo")
    parser.add_argument("--secret", default=os.getenv("GITHUB_WEBHOOK_SECRET", ""))
    parser.add_argument("--dry-run", action="store_true", help="Print the payload only")
    args = parser.parse_args()

    if not args.secret and not args.dry_run:
        print("ERROR: no webhook secret. Set GITHUB_WEBHOOK_SECRET or pass --secret.")
        return 2

    head_sha = args.sha or uuid.uuid4().hex * 2
    base_sha = args.base_sha or ("0" * 40)

    payload = build_payload(
        repo_full_name=args.repo,
        clone_url=args.clone_url,
        pr_number=args.pr,
        head_sha=head_sha,
        base_sha=base_sha,
        base_branch=args.base_branch,
        head_branch=args.head_branch,
    )
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    signature = hmac.new(
        args.secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()

    request = urllib.request.Request(
        args.url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": str(uuid.uuid4()),
            "X-Hub-Signature-256": f"sha256={signature}",
            "User-Agent": "CodeGuard-Demo/0.1",
        },
    )

    print(f"POST {args.url}")
    print(f"  repo={args.repo} pr=#{args.pr} sha={head_sha[:8]} signature=sha256={signature[:16]}…")

    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8", errors="replace")
            print(f"  HTTP {response.status} in {(time.time() - started) * 1000:.0f} ms")
            print(f"  {text}")
    except urllib.error.HTTPError as exc:
        print(f"  HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')}")
        return 1
    except urllib.error.URLError as exc:
        print(f"  connection failed: {exc.reason}")
        print("  is the API running? uvicorn src.api.app:create_app --factory --port 8000")
        return 1

    print("\n下一步：打开控制台「任务列表」，最新一条即本次 PR 触发的扫描。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
