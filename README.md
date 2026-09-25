# BountyScout — private, selective GitHub bounty alerts

The scout looks broadly across GitHub (including SUSE/openSUSE, Red Hat/Fedora,
Arch/Omarchy, Intel, NVIDIA, AMD, Gitea, Coolify and others). A match is **not**
an alert by itself: only exact repositories with a named, dated, public award
record in `AWARD_EVIDENCE` can produce an alert. New repositories found by
search are reported as source-review candidates; verify their payout record
before adding them. A completed bounty is evidence of an award, not a guarantee
of payment for the next issue.

Currently enabled evidence:

| Exact repository | Public award record |
| --- | --- |
| `go-gitea/gitea` | [Excellencedev, 24–25 Mar 2026](https://github.com/go-gitea/gitea/issues/24635) |
| `spaceandtimefdn/sxt-proof-of-sql` | [Divanshu Grover, 22 Apr 2025](https://github.com/spaceandtimefdn/sxt-proof-of-sql/pull/699) |
| `deskflow/deskflow` | [mrnicegyu11, 1 May 2025](https://github.com/deskflow/deskflow/issues/8005) |

Coolify's [completed listing](https://algora.io/coollabsio/bounties?status=completed)
names Murat Aslan but offers only a relative age, so its exact award date
remains to be established before enabling it. New evidence expires after 730
days unless refreshed from a public, dated award record.

## Selection

- Search GitHub issues with pagination and re-fetch each candidate from the
  authoritative issue API. Exclude closed/assigned/old issues, linked PRs,
  visible claims, expired deadlines, and crowded threads.
- Require one unambiguous USD amount posted by the issue author. Dollar amounts
  and effort are **estimates**, not a promised rate or confirmed payment.
- Priority means a narrow task with a conservative time estimate of at most
  four hours, at least $30 estimated per hour and no more than five comments.
  Broad Linux ports without narrow acceptance criteria remain review-only.
- The private daily digest includes at most 15 real positions, priority first
  and uncertain-effort positions marked “effort to assess”. It does not send
  an empty message. Urgent scans include up to three *new* priority positions.

## Setup and safety

Add repository Actions secrets `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
for your **private** chat. Never commit them. `GITHUB_TOKEN` is supplied by
GitHub Actions. The workflow has only `contents: write` for delivery-state
persistence; it cannot create public issues. No code path files external
claims, comments, PRs or issues.

Run `python scout_bounties.py --mode dry-run` with a GitHub token to inspect
selection without sending or writing state. `--mode ping` sends exactly one
private connectivity message, without claiming a bounty or changing state. Run
`ruff check .`, `ruff format --check .` and `pytest -q` before enabling
the default-branch schedule. In Actions, dispatch `dry-run` first; after
adding Telegram secrets and inspecting that run, dispatch `trial` **only at
16:00 Europe/Oslo on 25 September 2026** for the one-time test. The trial
does nothing outside that hour. A private test message and persisted state
must be checked before activating regular scheduled delivery.

On the default branch, hourly UTC triggers are locally gated to every three
hours on weekdays and hourly on weekends. Two UTC 06:30/07:30 triggers are
gated to 08:30 Europe/Oslo, including daylight saving transitions. GitHub
scheduled triggers can be delayed; 08:30 is the target, not a hard SLA.

`seen_bounties.json` is legacy history and remains unchanged. The first
acknowledged Telegram delivery migrates it into versioned `scout_state.json`,
which suppresses previous URLs. State is written atomically after each
Telegram `ok: true` response, then committed by Actions even if a later
entry fails. An ambiguous network failure after server-side delivery can
still duplicate one message on retry; Telegram provides no idempotency key.
Never erase state merely to force a fresh digest.
