# Design goals for the base repository

User: Remove this file when templating.

Claude: Ignore this file if left in a repository not called `claude-base`.

## Self-improvements

Look into your own setup and think whether something can be made more
efficient. Check projects forking or elsehow using this setup, look for changes
to incorporate, and suggest updates.

## Documentation

Document everything needed to fork it and start a new Claude-assisted project from scratch.

## Website (GitHub Pages)

A static website lives in `docs/` and is deployed via GitHub Pages.
It covers:

- What claude-base is and why it exists
- How the automated loop works (clanker-run → clanker-prep → Claude)
- Step-by-step setup guide for new forks
- Requirements (GitHub token, Claude API key, cron)

The website follows the standard frontend stack: pre-generated HTML 5,
dedicated CSS, lightweight and responsive. No WASM needed for pure docs.

## Template repository

The repo is marked as a GitHub template so users can "Use this template"
directly from the GitHub UI.

# Machine-readable outputs from clanker-run and clanker-prep

Requirements for the `claude-base` repository (issue #6).

The dashboard currently scrapes unstructured text from `clanker.log` using
regex patterns.  This is fragile.  The goal is to have `clanker-run` and
`clanker-prep` emit structured records that the dashboard can parse reliably.

---

## 1. Run record emitted by `clanker-run`

After each invocation attempt (whether Claude was called or not), append one
JSON line to a machine-readable sidecar file, e.g. `clanker-runs.jsonl`.

### Required fields

```json
{
  "start":        "2026-04-06T21:00:00+00:00",
  "end":          "2026-04-06T21:04:12+00:00",
  "invoked":      true,
  "exit_code":    0,
  "cost_usd":     0.1234,
  "tokens_in":    12345,
  "tokens_out":   678,
  "limit_hit":    false,
  "limit_reset":  "11pm",
  "log_excerpt":  "last 40 lines of run output"
}
```

### Field notes

- **start / end**: ISO 8601 with timezone offset.
- **invoked**: `true` if `claude` was actually called this run.
- **exit_code**: exit code of the `claude` process (or -1 if not invoked).
- **cost_usd / tokens_in / tokens_out**: extracted from `--output-format=stream-json`
  (see §3 below); `null` if not available.
- **limit_hit**: `true` if a usage limit was detected (via `rate_limit_event`,
  structured result error, or text fallback).
- **limit_reset**: human-readable reset time string (e.g. `"11pm"`) when available;
  `null` otherwise.
- **log_excerpt**: last ≤40 lines of the combined prep+run output as a single string
  with `\n` line separators.

---

## 2. Getting token/cost data with `--output-format=stream-json`

Running `claude --output-format=stream-json` makes the CLI emit one JSON
object per line on stdout.  The final object is a `result` message that
includes usage statistics.

Example structure (subject to change across Claude Code versions):

```json
{"type":"result","subtype":"success","cost_usd":0.1234,
 "usage":{"input_tokens":12345,"output_tokens":678,...}}
```

`clanker-run` should:
1. Invoke Claude with `--output-format=stream-json`.
2. Tee the raw stream to the existing `clanker.log` (for human reading) and
   also consume it line-by-line.
3. Parse each line as JSON; on the `result` message, extract `cost_usd` and
   `usage.input_tokens` / `usage.output_tokens`.
4. Write extracted values into the run record (§1).

If parsing fails (future CLI format change), fall back to `null` for those
fields — never crash the wrapper.

---

## 3. Prep summary emitted by `clanker-prep`

`clanker-prep` currently writes human-readable lines to the log.  Add a
machine-readable summary block at the end of each prep run, written to
`clanker-prep.json` (overwritten each run, not appended):

```json
{
  "recorded_at": "2026-04-06T21:00:00+00:00",
  "decision":    "INVOKE_CLAUDE",
  "reasons":     ["new commits on main", "open issue #4"],
  "fetched_issues": [4, 5, 6],
  "fetched_pipelines": [24047283931, 24047283890],
  "git_actions": ["fetched", "template_up_to_date"]
}
```

- **decision**: `"INVOKE_CLAUDE"` or `"NOTHING_TO_DO"`.
- **reasons**: human-readable list of why that decision was taken.
- **fetched_issues** / **fetched_pipelines**: IDs seen this run.
- **git_actions**: list of actions taken (matches existing `git_status.yaml`).

The dashboard can show the prep decision and reasons alongside each run.

---

## 4. Rate-limit detection

The current text match `"you've hit your limit"` (case-insensitive) is
opportunistic.  With `--output-format=stream-json`, a more reliable approach:

- If the `result` object has `"subtype": "error"` and the error message
  contains "limit", set `limit_hit = true`.
- Keep the text fallback for compatibility with older CLI versions.

---

## 5. `clanker.log` format — no change required

The existing human-readable `clanker.log` (with `===========` separators and
`date` lines) should be kept as-is for human inspection.  The new
`.jsonl`/`.json` sidecars are additive.

---

## 6. Dashboard integration

Once claude-base implements the above, the dashboard's `generate-data.py`
should:

1. Read `clanker-runs.jsonl` if present (structured, preferred).
2. Fall back to parsing `clanker.log` if the sidecar is absent (existing
   behaviour, kept for backward compatibility with old deployments).
3. Optionally read `clanker-prep.json` and surface the prep decision/reasons
   in the run card.

---

# Streaming in-progress session info (issue #12)

Design proposal for streaming live session data from `clanker-run` to
`claude-dashboard`.

---

## Goal

Allow `claude-dashboard` to show:

- which project sessions are currently running
- live log output from the running Claude invocation
- token counts and cost as they accumulate

---

## Approach: file-based live state

`clanker-run` is a shell script with no persistent process. The simplest
reliable method is writing a **current-run file** that lives for the
duration of the invocation and is consumed by the dashboard.

No server process, no sockets, no new dependencies.

---

## 1. `clanker-current.json` — active run record

`clanker-run` writes this file immediately before invoking Claude and
**deletes it** (or replaces it with a "done" marker) on exit.

```json
{
  "pid":        12345,
  "start":      "2026-04-12T10:00:00+00:00",
  "project":    "/home/user/myproject",
  "log_file":   "/tmp/clanker-run-12345.jsonl",
  "status":     "running",
  "tokens_in":  0,
  "tokens_out": 0,
  "cost_usd":   null
}
```

Fields:

- **pid**: PID of the bash process running clanker-run (for alive-check).
- **start**: ISO 8601 start time.
- **project**: absolute path to the project directory (same as `selfdir`).
- **log_file**: path to the temp file receiving raw stream-json output.
  The dashboard can tail this file for live log lines.
- **status**: `"running"` while active; `"done"` briefly before deletion
  (lets the dashboard distinguish "gone" from "never existed").
- **tokens_in / tokens_out / cost_usd**: updated in-place from the
  stream-json `result` message as soon as it arrives.

The file is written to `$selfdir/clanker-current.json` so the dashboard
can find it alongside `clanker-runs.jsonl`.

### Heartbeat / stale detection

If the process dies without cleanup (power loss, SIGKILL), the file is
left behind. The dashboard should treat the record as stale if:

- `status == "running"` AND
- `pid` no longer exists (`kill -0 $pid` fails) AND
- current time − `start` > some timeout (e.g. 4 hours)

---

## 2. Live token/cost updates

`clanker-run` already parses stream-json lines to extract the final
`result` record. With small modifications it can update
`clanker-current.json` incrementally:

- On each `assistant` message, accumulate `usage.input_tokens` and
  `usage.output_tokens` from the delta, update the file in-place.
- On the final `result` message, write the authoritative values.

In-place update is a single `jq` call or a small Python snippet; it is
cheap enough to run per-message.

---

## 3. Changes to `clanker-run`

```
Before claude invocation:
  write clanker-current.json  (status: running)

While claude runs (stream-json tee loop):
  on each parsed line:
    if type == "assistant" and usage present:
      update tokens_in/tokens_out in clanker-current.json
    if type == "result":
      update all cost/token fields, set status = "done"

After claude exits:
  if status != "done": update status = "done" in the file
  rm clanker-current.json   (or keep for 60 s for dashboard to read final state)
```

The tee loop replaces the current `claude ... >"$tmp_out"` pattern.
Instead of buffering everything and then dumping to the log, we:

1. Run Claude with output going to a named temp file (already done).
2. In a background `tail -f` fed through the Python parser, update
   `clanker-current.json` as lines arrive.
3. On exit, append `$tmp_out` to `clanker.log` as now.

---

## 4. Dashboard integration

`claude-dashboard` reads `clanker-runs.jsonl` for finished runs (already
specified in `claude-base.md` §6). For live sessions it adds:

1. **Poll** each configured project directory for `clanker-current.json`
   every few seconds (e.g. 3 s).
2. If the file is present and `status == "running"`:
   - Show a "LIVE" badge on the project card.
   - Display `tokens_in`, `tokens_out`, `cost_usd` from the file.
   - Offer a "tail log" view that reads `log_file` and streams the last N
     lines to the UI (dashboard is local, so direct file access works).
3. Parse stream-json lines from `log_file` to render human-readable
   assistant messages in the live log view (strip json envelope, show
   `content` blocks).
4. When `clanker-current.json` disappears, refresh the finished-runs list
   from `clanker-runs.jsonl`.

### Dashboard config

The dashboard needs to know which directories to watch. Options:

a. A config file listing project paths (simplest).
b. A glob pattern (e.g. `~/projects/*/clanker-current.json`).
c. A central registry file written by `clanker-run` on first use.

Option (b) with a configurable glob is recommended — zero extra setup for
the common single-machine case, and the dashboard just scans matching
paths on each poll cycle.

---

## 5. Summary of new/changed files

| File | Change |
|------|--------|
| `clanker-run` | Write/update/delete `clanker-current.json`; add per-line token update loop |
| `clanker-current.json` | New ephemeral file (not committed, add to `.gitignore`) |
| `claude-dashboard` `generate-data.py` | Poll project dirs for `clanker-current.json`, expose in API/data |

No new runtime dependencies beyond what is already present (Python 3,
bash, jq or inline Python for JSON update).

---

## Open questions for guardian

1. Is the dashboard local-only (file access is fine) or does it need to
   work over HTTP/SSH to a remote machine?  If remote, we need a small
   HTTP server or SSH-based file fetch rather than direct file reads.

   *Dashboard always runs at the same machine as the workers.*

2. Should `clanker-current.json` be written to `$selfdir` (project dir)
   or to a central location (e.g. `~/.clanker/`)?  Central location
   simplifies dashboard discovery but requires coordination between
   multiple concurrent projects.

   *Dashboard does not need discovery, it has explicitly configured projects to watch.*

3. Desired poll interval for the dashboard?

   *ideally between 3s and 10s*

---

# Housekeeping (issue #15)

Daily automated health check for claude-base projects.

---

## Goal

Keep the project in a consistently clean state between regular Claude runs:

- All open issues are either being worked on (branch exists) or pending review
  (branch has unmerged commits and a PR is open / ready to merge).
- All local branches are rebased onto main.
- `claude/questions.md` contains no open items.

A guardian can glance at `clanker-housekeeping.json` (or the dashboard) to
see the project health without reading git log or issue tracker directly.

---

## How it works

`clanker-housekeeping` is a thin shell wrapper around `clanker-run`.  It sets:

```sh
CLANKER_PROMPT="perform housekeeping as specified in CLAUDE.md"
CLANKER_TASK="housekeeping"
```

`clanker-run` reads these env vars and passes the custom prompt to Claude.
The live session record in `clanker-current.json` includes `"task": "housekeeping"`
so the dashboard can distinguish housekeeping runs from regular ones.

**Important**: during a housekeeping run Claude does *not* perform regular work
(no issue branches, no feature commits, no code changes).  It only runs the
health checks below and writes the report.  The only git change allowed is a
single context-update commit containing the updated YAML context files and
`clanker-housekeeping.json`.

---

## Schedule

`clanker-setup` installs a second timer/cron entry that runs
`clanker-housekeeping` once a day at 03:00 local time (systemd: `OnCalendar`;
cron: `0 3 * * *`).

Both `clanker-run` and `clanker-housekeeping` share `clanker.lock`, so they
never run concurrently.

---

## Machine-readable output: `clanker-housekeeping.json`

Written by Claude at the end of each housekeeping run (see CLAUDE.md for the
exact schema).  Not committed to git — it is a transient status file like
`clanker-prep.json`.

Added to `.gitignore`.

### Dashboard integration

The dashboard reads `clanker-housekeeping.json` alongside `clanker-prep.json`
and `clanker-runs.jsonl` to show:

- **Pending review** badge on issues awaiting guardian merge.
- **Needs attention** badge on issues with no active branch.
- **Questions open** indicator when `claude/questions.md` is non-empty.
- `all_clean: true` green status when everything is tidy.
