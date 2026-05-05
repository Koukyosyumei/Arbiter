# Branch: main

**Purpose:** Primary development branch

_Commits will be appended below._

## Commit 69f9553c — 2026-05-05 02:26 UTC

### Branch Purpose
Primary development branch

### Previous Progress Summary


### This Commit's Contribution
Root cause was orchestrator's max_targets cap evicting decorator-scan cli targets when LLM returned enough network targets. Fix: _cap_with_decorator_quota reserves cap//2 slots for decorator-scan results. Verified: 218 unit tests pass, fresh leo scan now produces witness for MarkupCommands.run_asciidoctor → subprocess.Popen via execute_shell_commands wrapper at leoMarkup.py:388

---

