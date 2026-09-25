"""Conservative private bounty scout; no public issues, claims, comments or PRs."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

STATE_FILE = Path("scout_state.json")
LEGACY_FILE = Path("seen_bounties.json")
OSLO = ZoneInfo("Europe/Oslo")
MAX_DIGEST = 15
MAX_COMMENTS = 25
MIN_RATE = 30
MAX_AGE_DAYS = 365
ORGS = (
    "SUSE",
    "openSUSE",
    "redhat",
    "fedora-infra",
    "fedora",
    "archlinux",
    "basecamp",
    "omarchy",
    "intel",
    "NVIDIA",
    "ROCm",
    "AMD",
    "go-gitea",
    "coollabsio",
    "spaceandtimefdn",
    "deskflow",
)
SEARCH_TERMS = ("bounty", "reward")
TOPICS = (
    "security",
    "vulnerability",
    "cve",
    "auth",
    "ai",
    "agent",
    "mcp",
    "rust",
    "python",
    "typescript",
    "api",
    "devops",
    "kubernetes",
    "linux",
    "port",
    "windows",
    "macos",
    "deployment",
)
BLOCKED = ("airdrop", "referral", "casino", "gambling", "trading bot")
AGGREGATOR_NAME = re.compile(
    r"(?:^|[-_])(?:awesome|bounties|bounty-list|bountyscout)(?:$|[-_])",
    re.IGNORECASE,
)
CLAIM = ("claiming", "i'll take", "i will take", "working on this", "/attempt")
AMOUNT = re.compile(
    r"(?:\$\s*([\d,]+(?:\.\d{1,2})?)|\bUSD\s*([\d,]+(?:\.\d{1,2})?))", re.IGNORECASE
)
DEADLINE = re.compile(
    r"(?:deadline|due date|closes?)\s*[:\-]?\s*(20\d\d-\d\d-\d\d)", re.IGNORECASE
)

# Exact repository-level public award evidence, not a promise of future payout.
# New sources are discovered globally but require a named, dated award review here.
AWARD_EVIDENCE = {
    "go-gitea/gitea": {
        "recipient": "Excellencedev",
        "awarded_at": "2026-03-25",
        "url": "https://algora.io/claims/Cu7g8vaVGy5BnDad",
    },
    "spaceandtimefdn/sxt-proof-of-sql": {
        "recipient": "Divanshu Grover",
        "awarded_at": "2025-04-22",
        "url": "https://github.com/spaceandtimefdn/sxt-proof-of-sql/pull/699",
    },
    "deskflow/deskflow": {
        "recipient": "mrnicegyu11",
        "awarded_at": "2025-05-01",
        "url": "https://github.com/deskflow/deskflow/issues/8005",
    },
    # Coolify's completed listing names Murat Aslan but only gives a relative
    # date. It stays under review until an exact award date is evidenced.
}


def eligible_repos(now: datetime | None = None) -> set[str]:
    now = now or datetime.now(timezone.utc)
    cutoff = now.date() - timedelta(days=730)
    return {
        repo
        for repo, proof in AWARD_EVIDENCE.items()
        if proof.get("recipient")
        and proof.get("url")
        and cutoff <= datetime.fromisoformat(proof["awarded_at"]).date() <= now.date()
    }


def load_state(path: Path = STATE_FILE) -> dict:
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {"version": 2, "legacy_seen": sorted(set(data)), "delivered": {}}
        if not isinstance(data, dict) or data.get("version") != 2:
            raise ValueError("Invalid state; refusing to reset history")
        return data
    legacy = (
        json.loads(LEGACY_FILE.read_text(encoding="utf-8"))
        if LEGACY_FILE.exists()
        else []
    )
    if not isinstance(legacy, list) or not all(isinstance(url, str) for url in legacy):
        raise ValueError("Invalid legacy state; refusing to reset history")
    return {"version": 2, "legacy_seen": sorted(set(legacy)), "delivered": {}}


def save_state(state: dict, path: Path = STATE_FILE) -> None:
    fd, temp_path = tempfile.mkstemp(prefix=".scout-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(state, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def request_json(
    url: str, token: str | None = None, *, payload: dict | None = None
) -> dict | list:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BountyScout/2",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        headers=headers,
        method="POST" if payload else "GET",
        data=json.dumps(payload).encode() if payload else None,
    )
    for attempt in range(1 if payload is not None else 3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if (
                payload is not None
                or attempt == 2
                or (
                    isinstance(exc, urllib.error.HTTPError)
                    and exc.code not in (429, 500, 502, 503, 504)
                )
            ):
                raise RuntimeError(
                    "Remote API request failed: " + type(exc).__name__
                ) from exc
            time.sleep(attempt + 1)
    raise RuntimeError("Unreachable retry state")


def github_pages(url: str, token: str, max_pages: int = 2) -> list[dict]:
    result = []
    for page in range(1, max_pages + 1):
        data = request_json(
            url + ("&" if "?" in url else "?") + f"per_page=100&page={page}", token
        )
        if isinstance(data, dict):
            if data.get("incomplete_results"):
                raise RuntimeError("Incomplete search; refusing partial results")
            batch = data.get("items", [])
        else:
            batch = data
        if not isinstance(batch, list):
            raise TypeError("Unexpected GitHub response")
        result.extend(batch)
        if len(batch) < 100:
            break
    return result


def discover(token: str) -> tuple[dict[str, dict], set[str]]:
    """Search broadly; unverified repositories enter a review list, never alerts."""
    found = {}
    queries = [f"org:{org} is:issue is:open bounty in:title,body" for org in ORGS]
    queries += [f"is:issue is:open {term} in:title,body" for term in SEARCH_TERMS]
    for query in queries:
        url = "https://api.github.com/search/issues?q=" + urllib.parse.quote(
            query + " sort:updated-desc"
        )
        for item in github_pages(url, token):
            issue_url = item.get("html_url", "")
            if "/issues/" not in issue_url:
                continue
            repo = issue_url.split("/issues/")[0].removeprefix("https://github.com/")
            _, _, name = repo.partition("/")
            if repo.lower() == "acidkill/bountyscout" or not name:
                continue
            if AGGREGATOR_NAME.search(name):
                continue
            found[issue_url] = item
    unknown = {
        url.split("/issues/")[0].removeprefix("https://github.com/")
        for url in found
        if "/issues/" in url
    } - eligible_repos()
    return found, unknown


def is_clean_candidate(item: dict, repo: str, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    url = item.get("html_url", "")
    if repo not in eligible_repos(now) or not url.startswith(
        f"https://github.com/{repo}/issues/"
    ):
        return False
    if item.get("state") != "open" or item.get("pull_request") or item.get("assignees"):
        return False
    if item.get("comments", 0) > MAX_COMMENTS or not item.get("created_at"):
        return False
    created = datetime.fromisoformat(item["created_at"].replace("Z", "+00:00"))
    if not 0 <= (now - created).days <= MAX_AGE_DAYS:
        return False
    text = (str(item.get("title") or "") + " " + str(item.get("body") or "")).lower()
    return not any(word in text for word in BLOCKED) and any(
        word in text for word in TOPICS
    )


def active_amount(item: dict, comments: list[dict]) -> float | None:
    """Only a single unambiguous maintainer-posted USD reward is accepted."""
    author = (item.get("user") or {}).get("login")
    texts = [item.get("body") or ""]
    texts += [
        comment.get("body") or ""
        for comment in comments
        if (comment.get("user") or {}).get("login") == author
    ]
    amounts = {
        float(next(part for part in match.groups() if part).replace(",", ""))
        for text in texts
        if re.search(r"bounty|reward|algora", text, re.IGNORECASE)
        for match in AMOUNT.finditer(text)
    }
    return amounts.pop() if len(amounts) == 1 else None


def score_candidate(item: dict, amount: float) -> dict:
    text = (str(item.get("title") or "") + " " + str(item.get("body") or "")).lower()
    wide_port = (
        "port" in text
        and "linux" in text
        and not any(
            word in text
            for word in ("single", "specific", "one feature", "acceptance criteria")
        )
    )
    hours = item.get("estimated_hours")
    if hours is None and any(
        word in text for word in ("single", "specific", "one endpoint", "test case")
    ):
        hours = 4
    if not isinstance(hours, (int, float)) or hours <= 0 or wide_port:
        hours = None
    hourly = round(amount / hours, 2) if hours else None
    return {
        "amount_usd": amount,
        "hours_estimate": hours,
        "hourly_usd": hourly,
        "priority": hourly is not None
        and hourly >= MIN_RATE
        and item.get("comments", 0) <= 5,
    }


def inspect_issue(item: dict, repo: str, token: str, now: datetime) -> dict | None:
    number = item.get("number")
    if not isinstance(number, int):
        return None
    api = f"https://api.github.com/repos/{repo}/issues/{number}"
    live = request_json(api, token)
    if not isinstance(live, dict) or not is_clean_candidate(live, repo, now):
        return None
    comments = github_pages(api + "/comments", token)
    timeline = github_pages(api + "/timeline", token)
    if any(
        term in str(comment.get("body") or "").lower()
        for comment in comments
        for term in CLAIM
    ):
        return None
    if any(
        event.get("event") == "cross-referenced"
        and (event.get("source") or {}).get("issue", {}).get("pull_request")
        for event in timeline
    ):
        return None
    deadline = DEADLINE.search(str(live.get("body") or ""))
    if deadline and datetime.fromisoformat(deadline.group(1)).date() < now.date():
        return None
    amount = active_amount(live, comments)
    if amount is None or amount <= 0:
        return None
    return {
        "repo": repo,
        "title": live["title"],
        "html_url": live["html_url"],
        "comments": live.get("comments", 0),
        **score_candidate(live, amount),
    }


def split_messages(lines: list[str], limit: int = 3900) -> list[str]:
    chunks, current = [], ""
    for line in lines:
        if len(line) > limit:
            line = line[: limit - 1] + "…"
        if current and len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = ""
        current = current + "\n" + line if current else line
    if current:
        chunks.append(current)
    return chunks


def send_telegram_notification(token: str, chat_id: str, message: str) -> bool:
    response = request_json(
        "https://api.telegram.org/bot" + token + "/sendMessage",
        payload={"chat_id": chat_id, "text": message, "disable_web_page_preview": True},
    )
    return isinstance(response, dict) and response.get("ok") is True


def should_run(now: datetime, mode: str) -> bool:
    local = now.astimezone(OSLO)
    if mode == "scan":
        return local.weekday() >= 5 or local.hour % 3 == 0
    if mode == "digest":
        return local.hour == 8 and local.minute >= 30
    if mode == "trial":
        return local.date().isoformat() == "2026-09-25" and local.hour == 16
    return mode in ("dry-run", "ping")


def format_entry(item: dict, index: int) -> str:
    title = re.sub(r"\s+", " ", item["title"])[:170]
    rate = (
        f"~${item['hourly_usd']}/h"
        if item["hourly_usd"] is not None
        else "effort to assess"
    )
    tier = "PRIORITY" if item.get("priority", False) else "REVIEW"
    return (
        f"{index}. [{tier}] {title}\n{item['repo']} · ${item['amount_usd']:g} USD · {rate} · "
        f"{item['comments']} comments\n{item['html_url']}"
    )


def deliver(
    items: list[dict],
    state: dict,
    token: str | None,
    chat_id: str | None,
    *,
    mode: str = "digest",
    dry_run: bool = False,
    path: Path = STATE_FILE,
) -> list[str]:
    if not items:
        return []
    if not dry_run and (not token or not chat_id):
        raise RuntimeError("Telegram secrets missing; no state write")
    heading = "BountyScout urgent" if mode == "scan" else "BountyScout digest"
    batches: list[tuple[str, list[str]]] = []
    message, urls = heading, []
    for index, item in enumerate(items, 1):
        entry = format_entry(item, index)
        if len(message) + len(entry) + 1 > 3900 and urls:
            batches.append((message, urls))
            message, urls = heading, []
        if len(message) + len(entry) + 1 > 3900:
            raise ValueError("Bounty entry exceeds Telegram message limit")
        message += "\n" + entry
        urls.append(item["html_url"])
    batches.append((message, urls))
    preview = [text for text, _ in batches]
    if dry_run:
        print(
            f"DRY RUN: {len(items)} items; {len(preview)} message chunks; no send/state write"
        )
        for chunk in preview:
            print(chunk)
        return preview
    delivered = []
    for chunk, acknowledged_urls in batches:
        if not send_telegram_notification(token, chat_id, chunk):
            return delivered
        for url in acknowledged_urls:
            state["delivered"][url] = datetime.now(timezone.utc).isoformat()
        save_state(state, path)
        delivered.extend(acknowledged_urls)
    return delivered


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("scan", "digest", "trial", "dry-run", "ping"),
        default="dry-run",
    )
    parser.add_argument("--state", type=Path, default=STATE_FILE)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    if not should_run(now, args.mode):
        print("Outside Europe/Oslo schedule; no work")
        return
    if args.mode == "ping":
        bot, chat = (
            os.environ.get("TELEGRAM_BOT_TOKEN"),
            os.environ.get("TELEGRAM_CHAT_ID"),
        )
        if (
            not bot
            or not chat
            or not send_telegram_notification(
                bot,
                chat,
                "BountyScout private delivery test. No bounty positions; no state change.",
            )
        ):
            raise RuntimeError("Private Telegram test failed")
        print("Private Telegram test accepted; no state change")
        return
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN required for authenticated GitHub checks")
    state = load_state(args.state)
    found, unknown = discover(token)
    print(
        f"Scanned {len(found)} issues; {len(unknown)} unverified repositories (never alerted)"
    )
    preferred = {org.lower() for org in ORGS}
    source_review = sorted(
        unknown,
        key=lambda repo: (repo.split("/")[0].lower() not in preferred, repo),
    )
    print("Source review sample: " + ", ".join(source_review[:25]))
    seen = set(state["legacy_seen"]) | set(state["delivered"])
    candidates = []
    for url, item in found.items():
        repo = url.split("/issues/")[0].removeprefix("https://github.com/")
        if url not in seen and repo in eligible_repos(now):
            checked = inspect_issue(item, repo, token, now)
            if checked:
                candidates.append(checked)
    candidates.sort(
        key=lambda item: (
            not item["priority"],
            -(item["hourly_usd"] or 0),
            -item["amount_usd"],
        )
    )
    if args.mode == "scan":
        candidates = [item for item in candidates if item["priority"]][:3]
    else:
        candidates = candidates[:MAX_DIGEST]
    print(f"Eligible candidates: {len(candidates)}")
    result = deliver(
        candidates,
        state,
        os.environ.get("TELEGRAM_BOT_TOKEN"),
        os.environ.get("TELEGRAM_CHAT_ID"),
        mode=args.mode,
        dry_run=args.mode == "dry-run",
        path=args.state,
    )
    if args.mode != "dry-run" and len(result) != len(candidates):
        raise RuntimeError(
            "Telegram delivery incomplete; undelivered entries remain pending"
        )


if __name__ == "__main__":
    main()
