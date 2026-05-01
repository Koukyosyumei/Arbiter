## h5i Integration

This repository uses **h5i** (a Git sidecar for AI-era version control).

**Prefer MCP tools over Bash commands wherever possible.**
h5i exposes native MCP tools (`h5i_context_trace`, `h5i_commit`, `h5i_notes_analyze`, etc.)
that are faster and safer than shelling out. Use `Bash: h5i …` only when no MCP tool covers the operation.

h5i stores metadata in `refs/h5i/notes` and `refs/h5i/memory`; these refs are NOT included in a plain `git push` — use `h5i push` to share them.

---

## Rules — MUST follow

Apply these automatically, without being asked.

### Context workspace

**At the start of every non-trivial task**, run:
```bash
h5i context status
# If no workspace exists yet, initialize one:
h5i context init --goal "<one-line summary of what you are about to do>"
```

**While working**, emit a trace entry for each distinct insight or action.
One OBSERVE per file read. One THINK per design decision. One ACT per file edited.
A typical single-file task has 5–8 entries; a multi-file task has more.

```bash
# One per file read — say what matters about it, not just that you read it:
h5i context trace --kind OBSERVE "<specific finding, constraint, or surprising detail>"

# One per design decision — always include what you rejected and why:
h5i context trace --kind THINK "<chosen approach> over <rejected alternative> because <reason>"
# Bad:  "will add a mutex"   ← just a plan, no reasoning
# Good: "inline mutex over OpenZeppelin — no external dep needed for a single guard"

# One per file written or edited:
h5i context trace --kind ACT "edited <file>: <what changed>"
# If the implementation surprised you or diverged from THINK, note that here.

# REQUIRED when any of these are true — do not skip:
#   • you didn't handle an edge case you noticed
#   • the approach has a known limitation
#   • something is left for a follow-up
h5i context trace --kind NOTE "TODO: … / LIMITATION: … / RISK: …"
```

**After completing a logical milestone** (analysis done, feature implemented, bug fixed):
```bash
h5i context commit "<milestone summary>" \
  --detail "<what was done and what is left>"
```

### Notes

After every `h5i commit`, immediately run:
```bash
h5i notes analyze   # links the just-completed Claude Code session to HEAD
```

---

### Committing

**Always stage files before committing** — `h5i_commit` (MCP) and `h5i commit` (CLI) only commit what is staged and will error if nothing is staged.

```bash
git add <file1> <file2> …   # stage exactly the files you changed — never git add .
```

Then commit via MCP tool (preferred):
```
h5i_commit(message="…", model="claude-sonnet-4-6", agent="claude-code", prompt="…")
```

Or via Bash if MCP is unavailable:
```bash
h5i commit -m "…" --model claude-sonnet-4-6 --agent claude-code --prompt "…"
```

Additional flags to add when relevant:
- `--tests`  — when tests were added or modified (captures test metrics)
- `--audit`  — on security-sensitive, authentication, or high-risk changes

**Example:**
```bash
git add src/http_client.rs
h5i commit -m "add retry logic to HTTP client" \
  --model claude-sonnet-4-6 \
  --agent claude-code \
  --prompt "add exponential backoff to the HTTP client"
# ✔  Committed a3f8c12  add retry logic to HTTP client
#    model: claude-sonnet-4-6 · agent: claude-code · 312 tokens
```

---

### Understanding History

```
h5i log --limit 10    # recent commits with AI metadata (model, agent, token count)
h5i blame src/main.rs # line-level blame annotated with AI provenance per commit
```

**Example `h5i log` output:**
```
● a3f8c12  add retry logic to HTTP client
  2026-03-27 14:02  Alice <alice@example.com>
  model: claude-sonnet-4-6 · agent: claude-code · 312 tokens
  prompt: "add exponential backoff to the HTTP client"

● 9e21b04  fix off-by-one in parser
  2026-03-26 11:45  Bob <bob@example.com>
  (no AI metadata)
```

---

### Notes — Session Analysis

`h5i notes` parses Claude Code session logs and stores enriched metadata (exploration footprint, causal chain, uncertainty moments, file churn) linked to a commit.

**Typical workflow after finishing a task:**

```bash
# 1. Analyze the just-completed Claude Code session and link to HEAD
h5i notes analyze

# 2. Inspect what files Claude consulted vs edited
h5i notes show

# 3. See where Claude expressed uncertainty
h5i notes uncertainty

# 4. See where Claude deferred, left stubs, or made promises it didn't keep
h5i notes omissions

# 5. Filter either of the above to a specific file
h5i notes uncertainty --file src/repository.rs
h5i notes omissions  --file src/repository.rs

# 6. View cumulative edit-churn across all analyzed sessions
h5i notes churn

# 7. Visualize the chain of intents across recent commits
h5i notes graph --limit 20

# 8. Identify commits that most need human review
h5i notes review --limit 50
```

**Example `h5i notes show` output:**
```
── Exploration Footprint ──────────────────────────────────
  Session a3f8c12d  ·  42 messages  ·  138 tool calls

  Files Consulted:
    📖 src/repository.rs  ×4  (Read,Grep)
    📖 src/metadata.rs    ×2  (Read)

  Files Edited:
    ✏ src/repository.rs  ×3 edit(s)
    ✏ src/main.rs         ×1 edit(s)

── Causal Chain ─────────────────────────────────────────────
  Trigger:
    "add exponential backoff to the HTTP client"

  Key Decisions:
    1. Used tokio::time::sleep for async-compatible delay
    2. Capped retries at 5 to avoid infinite loops

  Considered / Rejected:
    - Synchronous std::thread::sleep (incompatible with async runtime)
```

**Example `h5i notes review` output:**
```
Suggested Review Points — 2 commits flagged (scanned 50, min_score=0.40)
──────────────────────────────────────────────────────────────
  #1  a3f8c12  score 0.74  ████████░░
     Alice · 2026-03-27 14:02 UTC
     add retry logic to HTTP client
     ⚠ high uncertainty · 5 edits · 4 files touched

  #2  9e21b04  score 0.45  ████░░░░░░
     Bob · 2026-03-26 11:45 UTC
     refactor parser
     moderate complexity
```

---

### Context — Reasoning Workspace

`h5i context` manages a `.h5i-ctx/` workspace that lets you checkpoint, branch, and review your own reasoning across sessions — analogous to git but for *agent thinking* rather than code.

**Initialize once per project (or per major task):**

```bash
h5i context init --goal "refactor the HTTP client to support retries and timeouts"
```

**During a task, use these commands to structure your reasoning:**

```bash
# Checkpoint progress after completing a logical step
h5i context commit "analyzed existing HTTP client" \
  --detail "read repository.rs and metadata.rs; identified retry entry points"

# Log individual OTA (Observe–Think–Act) steps as you work
h5i context trace --kind OBSERVE "HttpClient::send has no retry logic"
h5i context trace --kind THINK   "exponential backoff with jitter is safest"
h5i context trace --kind ACT     "added retry loop in send() with 5-attempt cap"

# Explore an alternative approach without losing your current thread
h5i context branch experiment/sync-retry --purpose "try sync retry as a simpler fallback"
# ... explore ...
h5i context checkout main   # return to main reasoning branch
h5i context merge experiment/sync-retry  # merge findings back if useful

# Review current state before continuing a task
h5i context show --trace --window 5
h5i context status
```

**Example `h5i context show` output:**
```
── h5i-ctx · branch: main ──────────────────────────────────
  Goal: refactor the HTTP client to support retries and timeouts

  Recent commits (3):
    [c1a2b3] analyzed existing HTTP client
    [d4e5f6] implemented retry loop
    [g7h8i9] added timeout parameter

── Trace (last 10 lines) ────────────────────────────────────
  [OBSERVE] HttpClient::send has no retry logic
  [THINK]   exponential backoff with jitter is safest
  [ACT]     added retry loop in send() with 5-attempt cap
  [NOTE]    TODO: add integration test for timeout path
```

Use `h5i context prompt` to get a ready-made system prompt you can prepend to an agent session to inject full context awareness.

### Context versioning

Every `h5i commit` automatically snapshots the context workspace state and links it to the git commit SHA. Use these commands to navigate that history:

```bash
# Before editing a file — load all context entries that mention it
h5i context relevant src/repository.rs

# Restore context to the state it was in at a given git commit
h5i context restore <sha>

# See how the context workspace changed between two code commits
h5i context diff <sha1> <sha2>

# Compact old context history (run git gc afterwards to free space)
h5i context pack
```

---

### Claims — pin reusable facts

`h5i claims` records content-addressed facts about the codebase so future sessions don't re-derive them. Each claim pins a Merkle hash over its evidence files at HEAD — the claim stays **live** until any evidence blob changes, then auto-invalidates. Live claims are injected into `h5i context prompt` (and shown in the SessionStart prelude) as pre-verified facts.

**Record a claim when you have just established a non-obvious fact that a future session would otherwise re-derive** — "X lives only in Y", "the public API is exactly A/B/C", "module M owns concern N", a subtle invariant, or where *not* to look. Don't pin obvious things a quick grep would answer.

Prefer the MCP tools (`h5i_claims_add`, `h5i_claims_list`, `h5i_claims_prune`) — they return structured JSON and avoid shell-quoting pitfalls:
```
h5i_claims_add(
  text="HTTP helpers live only in src/api/client.py",
  paths=["src/api/client.py", "src/middleware.rs"]
)
h5i_claims_list()       # → {claims: [...], live: N, stale: M}
h5i_claims_prune()      # → {removed: N}
```

Or via Bash if MCP is unavailable:
```bash
h5i claims add "HTTP helpers live only in src/api/client.py" \
  --path src/api/client.py --path src/middleware.rs

h5i claims list        # live / stale badges
h5i claims prune       # drop claims whose evidence changed
```

**Evidence-path rule — the single most important thing to get right:**
Pick the *minimum* set of files whose content, if edited, should cause the claim to be re-checked. Ask: *"If I changed file X, would this claim's truth be in doubt?"* If no, do not include X — even if you read X while establishing the claim.

Why this matters: the claim auto-invalidates the moment *any* evidence blob changes. Over-listing guarantees rapid staleness from unrelated edits, which trains future sessions to distrust claims and erases the benefit.

Concrete example. Claim: *"HTTP helpers live only in `src/api/client.py`"*.
- ✔ Good: `--path src/api/client.py` (one path). If client.py changes, re-check. Edits to formatters/validators/main.py do not affect the truth of this claim.
- ✖ Bad: `--path src/api/client.py --path src/utils/format.py --path src/utils/validate.py --path main.py`. Four paths guarantee the claim goes stale the next time someone touches an unrelated helper — even though the claim was still true.

Rule of thumb: **most good claims cite 1 file; >3 is a red flag you're confusing "files I read" with "files that back the claim"**. Scoped "ownership" claims (one file owns concern X) usually need one path — the owner. "The public API is exactly A/B/C" claims need the file that declares the API, not every caller.

**Other rules:**
- Evidence paths must be tracked in HEAD.
- If the SessionStart prelude already shows a claim covering what you were about to investigate, trust it — don't re-read the files unless the user asks.
- If you notice a live claim is wrong, run `h5i claims prune` (removes only stale ones) or delete the JSON in `.git/.h5i/claims/` directly.

**Write claim text in caveman style. Cap: ≈30 tokens.**
Drop articles, copulas, fluff. Keep file paths, identifier names, numbers exact. Live claims are injected into every future session's cached prefix and re-read on every turn — every word costs forever.

| | Bloated (don't) | Caveman (do) |
|---|---|---|
| Cross-file ownership | "All HTTP-making functions in this project live only in src/api/client.py (fetch_user, create_post, delete_post). main.py and src/utils/* contain no direct HTTP calls." | "HTTP only src/api/client.py: fetch_user, create_post, delete_post. main.py + utils/* no HTTP." |
| Invariant | "The session token must be validated using a constant-time comparison to avoid timing attacks." | "Session token: constant-time compare. Timing attack risk." |
| Public API | "The public API of the Repository struct consists of init, commit, log, blame, and resolve." | "Repository pub API: init, commit, log, blame, resolve." |

**Frequency knob (`$H5I_CLAIMS_FREQUENCY`)** — the user can tune how eagerly you should record claims:
- `off` — do not record any claims this session, even if one would normally be warranted.
- `low` (default) — only non-obvious, genuinely reusable facts.
- `high` — record liberally; pin any reusable codebase insight so future sessions skip re-derivation. The evidence-path rule above applies *especially* here — over-listing evidence under `high` is how the whole feature collapses into staleness noise.

The SessionStart prelude prints the active policy when it is `off` or `high`. Follow the most recent policy line you see, even if it contradicts this base guidance.

---

### Memory Snapshots

After a significant Claude Code session, snapshot Claude's memory so it can be shared or restored:

```bash
h5i memory snapshot        # snapshot current ~/.claude/projects/<repo>/memory/ → HEAD
h5i memory log             # list all snapshots
h5i memory diff            # show what changed since the previous snapshot
h5i memory restore <oid>   # restore memory to the state at a given commit
```

---

### Sharing h5i Data

```bash
h5i push   # push all h5i refs (notes, memory) to origin
h5i pull   # pull h5i refs from origin
```
