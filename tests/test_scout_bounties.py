"""Regression tests for the pure parts of the bounty scout."""

import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scout_bounties as scout


def test_load_state_migrates_legacy_seen_url_list(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        '["https://example.test/a", "https://example.test/b"]', encoding="utf-8"
    )

    state = scout.load_state(path)

    assert state["legacy_seen"] == ["https://example.test/a", "https://example.test/b"]
    assert state["delivered"] == {}


def _candidate(**overrides):
    item = {
        "number": 24635,
        "title": "Improve auth security for a typed API endpoint",
        "html_url": "https://github.com/go-gitea/gitea/issues/24635",
        "state": "open",
        "labels": [{"name": "bounty"}],
        "body": "A $300 USD bounty is available for this specific implementation.",
        "created_at": "2026-09-01T12:00:00Z",
    }
    item.update(overrides)
    return item


def test_candidate_filter_accepts_recent_open_awarded_repo_issue():
    now = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)

    assert scout.is_clean_candidate(_candidate(), "go-gitea/gitea", now=now)


def test_candidate_filter_rejects_arbitrary_repo_even_if_issue_looks_eligible():
    item = _candidate(html_url="https://github.com/allowed/project/issues/1")

    assert not scout.is_clean_candidate(item, "allowed/project")


def test_candidate_filter_rejects_competitions_old_issues_closed_issues_and_prs():
    now = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    ineligible = [
        _candidate(
            title="Coding competition: best implementation wins",
            body="A $300 prize goes to the winner.",
        ),
        _candidate(created_at="2024-01-01T00:00:00Z"),
        _candidate(state="closed"),
        _candidate(
            pull_request={
                "url": "https://api.github.com/repos/go-gitea/gitea/pulls/24635"
            }
        ),
    ]

    assert all(
        not scout.is_clean_candidate(item, "go-gitea/gitea", now=now)
        for item in ineligible
    )


def test_score_candidate_prioritizes_rate_at_or_above_thirty_usd_per_hour():
    item = {
        "title": "Add integration tests",
        "estimated_hours": 2,
        "amount_usd": 60,
    }

    score = scout.score_candidate(item, 60)

    assert score["hourly_usd"] >= 30
    assert score["priority"]


def test_score_candidate_does_not_prioritize_wide_linux_port_but_accepts_narrow_port():
    wide = scout.score_candidate({"title": "Port this platform to Linux"}, 500)
    narrow = scout.score_candidate(
        {"title": "Port a single feature to Linux", "estimated_hours": 10}, 300
    )

    assert wide["hourly_usd"] is None
    assert not wide["priority"]
    assert narrow["hourly_usd"] == 30
    assert narrow["priority"]


def test_split_messages_respects_telegram_limit_and_preserves_content():
    lines = [f"Candidate {number}: " + ("x" * 850) for number in range(1, 11)]

    messages = scout.split_messages(lines, limit=3900)

    assert len(messages) > 1
    assert all(len(message) <= 3900 for message in messages)
    for line in lines:
        assert sum(line in message for message in messages) == 1


def test_failed_telegram_delivery_does_not_mark_items_delivered(monkeypatch, tmp_path):
    state = {"legacy_seen": [], "delivered": {}}
    items = [
        {
            **_candidate(
                number=2,
                html_url="https://github.com/go-gitea/gitea/issues/2",
                title="Fix API",
            ),
            "repo": "go-gitea/gitea",
            "amount_usd": 60,
            "hourly_usd": 30,
            "comments": 0,
        }
    ]
    path = tmp_path / "state.json"

    def fail_send(*args, **kwargs):
        return False

    monkeypatch.setattr(scout, "send_telegram_notification", fail_send)

    result = scout.deliver(items, state, token="token", chat_id="chat", path=path)

    assert not result
    assert state["delivered"] == {}
    assert not path.exists()


def test_digest_delivery_caps_candidates_at_fifteen(monkeypatch, tmp_path, capsys):
    found = {
        f"https://github.com/go-gitea/gitea/issues/{number}": {"number": number}
        for number in range(1, 21)
    }

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "scout_bounties.py",
            "--mode",
            "dry-run",
            "--state",
            str(tmp_path / "state.json"),
        ],
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        scout, "load_state", lambda path: {"legacy_seen": [], "delivered": {}}
    )
    monkeypatch.setattr(scout, "eligible_repos", lambda now: {"go-gitea/gitea"})
    monkeypatch.setattr(scout, "discover", lambda token: (found, []))
    monkeypatch.setattr(
        scout,
        "inspect_issue",
        lambda item, repo, token, now: {
            "title": f"Candidate {item['number']}",
            "repo": repo,
            "amount_usd": 60,
            "hourly_usd": 30,
            "comments": 0,
            "html_url": f"https://github.com/{repo}/issues/{item['number']}",
            "priority": True,
        },
    )

    scout.main()

    text = capsys.readouterr().out
    assert "Eligible candidates: 15" in text
    assert all(f"Candidate {number}" in text for number in range(1, 16))
    assert "Candidate 16" not in text


def test_oslo_digest_schedule_tracks_0830_across_dst():
    oslo = ZoneInfo("Europe/Oslo")
    # The same local delivery time maps to different UTC hours on either side
    # of the spring DST transition.
    before_dst = datetime(2026, 3, 28, 8, 30, tzinfo=oslo)
    after_dst = datetime(2026, 3, 30, 8, 30, tzinfo=oslo)

    assert before_dst.astimezone(timezone.utc).hour == 7
    assert after_dst.astimezone(timezone.utc).hour == 6
    assert scout.should_run(before_dst, "digest")
    assert scout.should_run(after_dst, "digest")


def test_digest_message_keeps_candidate_details_and_is_bounded():
    item = {
        **_candidate(title="Specific auth endpoint"),
        "repo": "go-gitea/gitea",
        "amount_usd": 120,
        "hourly_usd": 30,
        "comments": 1,
    }

    messages = scout.deliver(
        [item],
        {"legacy_seen": [], "delivered": {}},
        token=None,
        chat_id=None,
        dry_run=True,
    )

    assert len(messages) == 1
    assert "BountyScout digest" in messages[0]
    assert "Specific auth endpoint" in messages[0]
    assert "go-gitea/gitea" in messages[0]
    assert "$120 USD" in messages[0]
    assert "$30/h" in messages[0]
    assert len(messages[0]) <= 3900


def test_successful_digest_batches_positions_and_persists_acknowledged_urls(
    monkeypatch, tmp_path
):
    state = {"version": 2, "legacy_seen": [], "delivered": {}}
    items = [
        {
            **_candidate(
                number=number,
                html_url=f"https://github.com/go-gitea/gitea/issues/{number}",
            ),
            "repo": "go-gitea/gitea",
            "amount_usd": 120,
            "hourly_usd": 30,
            "comments": 0,
            "priority": True,
        }
        for number in (1, 2)
    ]
    sent = []
    monkeypatch.setattr(
        scout,
        "send_telegram_notification",
        lambda token, chat, message: sent.append(message) or True,
    )
    path = tmp_path / "state.json"

    acknowledged = scout.deliver(items, state, "token", "chat", path=path)

    assert len(sent) == 1
    assert len(acknowledged) == 2
    assert set(scout.load_state(path)["delivered"]) == set(acknowledged)


def test_no_empty_digest_or_state_write(monkeypatch, tmp_path):
    monkeypatch.setattr(
        scout,
        "send_telegram_notification",
        lambda *args: (_ for _ in ()).throw(AssertionError("unexpected send")),
    )
    path = tmp_path / "state.json"
    assert scout.deliver([], {"delivered": {}}, "token", "chat", path=path) == []
    assert not path.exists()


def test_discovery_excludes_own_scout_and_aggregators(monkeypatch):
    responses = [
        {"html_url": "https://github.com/acidkill/BountyScout/issues/1"},
        {"html_url": "https://github.com/other/BountyScout/issues/2"},
        {"html_url": "https://github.com/other/awesome-bounties/issues/3"},
        {"html_url": "https://github.com/go-gitea/gitea/issues/4"},
    ]
    monkeypatch.setattr(scout, "github_pages", lambda url, token: responses)

    found, unknown = scout.discover("test-token")

    assert list(found) == ["https://github.com/go-gitea/gitea/issues/4"]
    assert "acidkill/BountyScout" not in unknown
