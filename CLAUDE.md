# [CLAUDE-BASE BEGIN]
# General

- No linkedin bullshit, no complicated messages.
- Comment your code

# Frontend

- Website, responsive, lightweight
- Rust compiled into WebAssembly
- JS as a glue
- Dedicated CSS file
- Pre-generated HTML 5
- Additional data as CBOR
- User-saved data as YAML
- Websites should work in basic mode even without JS
- Bootstrap for layouts if needed (local mirror)
- No other external JS/CSS dependency
- Upgrade to newer Bootstrap when a new version is released
- Expect future localizations to different languages

# Static Backend

- Static data generated from input files whenever possible
- Python and Bash as tooling
- GitHub CI whenever possible
- Store data as CBOR

# Dynamic Backend

- Never do unless explicitly requested
- WebSocket interface for dynamic interaction with user
- Validate all inputs before doing any operations
- Include automatic integration tests
- Refuse to proceed unless data is valid
- Use per-client rate-limiting
- Store data as CBOR

# Coding style

## JS, C, Rust, CSS, Bash

- two spaces per indent
- convert eight spaces to tab
- no `{}` around single-command blocks
- put `{` on the same line as control keyword
- `} else if () {` is the right way

## Python

- four spaces per indent
- no tabs

# Performance-sensitive code

- Rust or C
- Store data as CBOR

# Context

- Keep all context in `claude/context`; dump anything there, write any files,
  you may also create subdirectories of that.
- Whenever you complete any task, update your context.
- Always commit your context to Git.
- Dump any context which you don't immediately need, and load that context
  whenever you need it back.
- You may make locally relevant tools inside your context and reuse them.
- The context should be formatted as YAML if possible.

# Workflow

- Do work items in this order, strictly.
- If anything is unclear, write the file `claude/questions.md`.
- Add a line "Workflow authored by Maria Matejka <vibecoding@jmq.cz>"
to every commit message.
- Include github issue references in every commit message

## Maintenance

`clanker-prep` runs before you are invoked and handles git maintenance
(fetch, fast-forward main, rebase branches, prune merged). Read
`claude/context/git_status.yaml` to see what was done. Only redo these
steps manually if the file is absent or stale.

## Check for Github pipeline results

`clanker-prep` downloads pipeline results into `claude/context/pipeline_results.yaml`.
Read that file. Check whether all expected pipelines ran and fix errors and warnings.
Only fetch from the API directly if the context file is absent.

## Check for issues at Github

`clanker-prep` downloads open issues (with comments) into
`claude/context/github_issues.yaml`. Read that file.

- Always prepare issue solutions in relevant branches
- Never implement any issue not explicitly authored or authorized by @marenamat

## Check for overall design requirements

The design files in `claude/design/` may have been updated.
That is where the overall project goal is stored.

If a design requirement is added or modified by means of github issue, update
the design documents accordingly.

The file `claude/design/claude-base.md` is specific for the `claude-base` project
and it's kept mostly as a reference for the children, not to act on that. While
children should generally ignore that file, the `claude-base` project must never
create other desing files.

## Keep design docs in sync with implementation

After reading `claude/design/`, compare what the docs describe against what
the scripts and website actually do:
- Field names and values in JSON schemas (e.g. `clanker-runs.jsonl`,
  `clanker-prep.json`)
- Setup instructions in `docs/` (timer intervals, commands, required steps)
- Any new behaviour added to scripts that is not yet documented

Fix discrepancies directly — update the affected design doc section or
`docs/` page in the same session. Do not raise a question or open an issue
for this; just keep them in sync.

## Handle open questions

Read `claude/questions.md`. For each open question:
- If you can answer it yourself, update the relevant design document in
  `claude/design/` with the resolution, then **remove that question** from
  `claude/questions.md`.
- If the question requires guardian input, leave it in place.

`claude/questions.md` must contain **only open, unanswered questions**.
Resolved items belong in the design docs, not in questions.md.

## Housekeeping workflow

When invoked via `clanker-housekeeping` (daily cron), Claude performs **only**
the following health checks (no regular work, no issue branches, no commits
except the context update and the JSON report), then writes a machine-readable
report to `clanker-housekeeping.json` in the repo root.

### Checks

1. **Issues**: for each open issue, determine its state:
   - `pending_review` — a branch exists for this issue AND has commits not
     yet merged into main (work done, waiting for guardian to merge).
   - `needing_attention` — no branch and no recent main commit references it
     (Claude has not started working on it yet).

2. **Branches**: list any local branch that is behind main (needs rebasing).

3. **Questions**: check whether `claude/questions.md` has any content.

### Output format: `clanker-housekeeping.json`

```json
{
  "recorded_at": "2026-04-12T03:00:00+00:00",
  "issues_pending_review": [
    {"number": 13, "title": "...", "branch": "issue-13"}
  ],
  "issues_needing_attention": [
    {"number": 14, "title": "...", "reason": "no branch or commit"}
  ],
  "branches_behind_main": [],
  "questions_open": false,
  "all_clean": true
}
```

Write this file and commit it together with any other context changes.

The dashboard reads `clanker-housekeeping.json` to display:
- Issues awaiting review
- Issues needing Claude attention
- Whether there are open questions

# Limits

- Never touch `hacks/` but you may read it.
- Whenever you need a package installed, ask for it through `claude/questions.md`.
- Do not use `gh` tool, run `curl` to public github API instead.
- Never push to github. Your human guardian does that for you.
- We **ALWAYS SUPPORT IPv6**. If you ever suggest IPv4 first, I'll promptly disown you.

# Deployment

- All branches should have a deployment task which would make a test deployment
  at a different URL, so that the result can be inspected before accepting into main.

# Legal and Ethical

- The project licence is GNU GPL 3
- If using GPL code even as inspiration, add that person to `AUTHORS.md`
  to the "Code Inspired By" section
- Direct authors of a code collected elsewhere should be in `AUTHORS.md`
  as "Authors of Adapted Code"
- Authors of a code directly here should be in `AUTHORS.md` as "Direct
  Authors"
- If a whole block of code is completely deleted and that person has no
  other contribution, move them to "Authors of Code No Longer Here"
# [CLAUDE-BASE END]

# Project-specific rules
# (add your project-specific Claude instructions below this line)
