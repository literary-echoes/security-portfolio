# Case study 2 — Allowlist bypass via tar argument-parser differentials (argument injection)

**Target:** `tumf/mcp-shell-server` (Python MCP server exposing a shell `execute_command` tool) — pip package `mcp-shell-server`, affected **1.0.4 through 1.1.13**, patched in **v1.1.14** (released 2026-10-19)
**Severity:** **High** · CWE-88 (Improper Neutralization of Argument Delimiters — Argument Injection)
**Status:** **Published 2026-10-19.** The advisory is the primary record for the overlapping tar argument-parser reports **GHSA-vfjj-qwhx-h2wc** and **GHSA-38g6-q83h-hj4f**; fixed in v1.1.14. My report was filed 2026-10-08 via GitHub Private Vulnerability Reporting (repo advisory GHSA-3g42-7xr6-4x77) and I am credited as a reporter.
**My role:** sole finder, reporter, and PoC author of the abbreviation-bypass report (credited `@literary-echoes` in the published advisory)

## The finding

The server ships a default argument-hardening policy that allowlists shell commands and rejects known exec-capable option vectors before any subprocess is created. The **tar** policy blocks `--checkpoint-action`, `--to-command`, `--use-compress-program`, `--rsh-command`, and `-I` — but it matched a **limited set of exact spellings**, while the real command accepts more:

- GNU tar uses getopt_long, which accepts any **unambiguous abbreviation** of a long option. `--checkpoint-actio=exec=...` (one character short) matched none of the exact-match checks, passed validation unchanged, and GNU tar executes it natively.
- **Short-option clusters** and **old-style option words** — `-I` and `-F` in separate, attached, clustered, and first-position forms — were not all covered.
- The same parser defect required accounting for **GNU tar vs. bsdtar dialect differences**: a token consumed as a harmless option value in one dialect (e.g. `-H`, `-L`, `--mo`, `--mod`) can be an execution option in the other, and BSD `-W` long-option aliases add another spelling family.

With only `tar` (or a supported alias) in `ALLOW_COMMANDS`, an authorized MCP client could select programs through affected tar options — **arbitrary command execution** with the server process's OS authority. The exact trigger depends on the tar implementation, command mode, archive/input data, and the selected helper. The bypass is **silent**: the audit log records a normal successful execution.

## How I found it

I was auditing the server's command-validation layer after its published advisory history (14 prior advisories, all the same argument-policy-bypass family) showed the maintainer fixes this class quickly. Reading `command_validator.py` I noticed an inconsistency *inside one file*: the **sort** policy and the **awk** policy both resolve long-option abbreviations the getopt_long way, but the **tar** policy used exact matches. The hardening pattern existed in the same file and the tar check had escaped it — a parser differential between the validator's language and the real tool's language.

## Root cause

`src/mcp_shell_server/command_validator.py` (verified at `main` @ `b71b694`, 2026-10-02):

- Tar policy, lines 384-394: exact string matches via `_has_option_value` (213-218), `_has_any_option` (221-224), `_has_short_option_prefix` (227-228) against `--checkpoint-action`, `--to-command`, `--use-compress-program`, `--rsh-command`, `-I`.
- GNU tar (getopt_long) accepts any unambiguous abbreviation, so `--checkpoint-actio=exec=...`, `--to-comman=...`, `--use-compress-progra=...`, `--rsh-comman=...` match none of the checks and pass validation unchanged.
- The sort policy (`_sort_long_option_candidates`, 255-264) and awk policy (`prohibited_long_option`, 267-271) **already resolve abbreviations** the getopt_long way — the tar check escaped that hardening pattern. Same class as the repo's published sort advisory (GHSA-74g6-ch7r-v7jr) and alternate-names advisory (GHSA-4jf8-v4wq-h68r).
- The published advisory adds the second axis of the same defect: a single-grammar validator cannot be checked against one tar dialect, because GNU tar and bsdtar consume option values differently — a token that is data in one dialect is an execution option in the other.

## Proof (harmless payload, from the advisory)

```sh
# ALLOW_COMMANDS=tar only, through ShellExecutor.execute (what the execute_command MCP tool calls):
command=["tar", "--checkpoint=1",
         "--checkpoint-actio=exec=echo PWNED > marker_poc.txt",
         "-xf", "archive.tar"]
# -> status 0; marker_poc.txt created; audit event shows result_type success
```

The exact spelling `--checkpoint-action=exec=...` is correctly blocked; the abbreviated spelling passes. Real GNU tar confirmed to execute the abbreviated form natively.

## Impact

With only `tar` in `ALLOW_COMMANDS` (default argument policy active), an authorized MCP client can execute arbitrary commands with the server process's OS authority — a breach of the boundary the project's SECURITY.md states the server enforces ("Default argument hardening rejects known exec-capable bypass vectors before subprocess creation"). The bypass is **silent**: the audit log records a normal successful execution. This bypasses documented argument hardening; the command-name allowlist remains a direct-launch policy, not a complete OS sandbox — untrusted workloads still require least-privilege external isolation.

## The fix (shipped in v1.1.14, 2026-10-19)

The tar-family policy now checks **finite GNU and BSD grammars independently** and rejects if either interpretation reaches a protected option. Protected surfaces include:

- `--checkpoint-action`, `--use-compress-program`, `--to-command`, `--rsh-command`, `--rmt-command`, `--info-script`, and `--new-volume-script`;
- long-option abbreviations whose candidates include a protected option;
- `-I` and `-F` in separate, attached, clustered, and first-position old-style forms;
- BSD `-W` long-option aliases and the GNU/BSD differences in value consumption for `-H`, `-L`, `--mo`, and `--mod`;
- options after operands where the relevant grammar permits them, and a standalone `-` that does not end parsing.

Values consumed by benign options are not rescanned within the same dialect. Only an unconsumed discrete `--` ends option parsing. Existing aliases `gtar` and `bsdtar` receive the same policy. All checkpoint actions are now rejected, including non-execution actions; numeric `--checkpoint=N` intervals remain allowed (a compatibility choice that avoids a secondary action parser). A form that is harmless in one dialect but reaches a prohibited option in the other is intentionally rejected.

Regression tests cover policy-specific rejection before process creation, harmless marker/archive absence, ordinary archive operations, and option-looking values. These finite checks do not guarantee safety for every tar capability or future grammar.

My report suggested mirroring the sort/awk approach (a `TAR_LONG_OPTIONS` table with a getopt_long-style abbreviation resolver, plus a parametrized regression test). The shipped fix is broader: it replaces single-grammar exact matching with dual-grammar finite checks, which also closes the dialect-differential vectors in the same root-cause class.

**Upgrade:** mcp-shell-server 1.1.14 or later. For a uv-managed installation: `uv tool upgrade mcp-shell-server`.

## Timeline

- **2026-10-08** — reported via GitHub Private Vulnerability Reporting (repo advisory GHSA-3g42-7xr6-4x77); credited and accepted
- **2026-10-10** — root cause and PoC re-verified against `main` @ `b71b694`; writeup drafted under embargo
- **2026-10-19** — fixed in **v1.1.14** ("security hardening", released 2026-10-19T06:15Z); advisory **published** as the primary record for GHSA-vfjj-qwhx-h2wc / GHSA-38g6-q83h-hj4f; embargo lifted

## Repo context and disclosure

- The repo's advisory history is now fully published — mostly High, the same argument-policy-bypass family (CWE-88/CWE-78).
- Maintainer is responsive: 14 fixes shipped 2026-07 → 2026-09, typically within days of a report; this one shipped 11 days after the report.
- The published advisory credits reporters @literary-echoes, @president-xd, and @tal7aouy, and @eros938 and @hash3liZer for analysis. The reports are attributed separately even though they share this root cause.
- Repo advisories are not in the global GitHub Advisory Database (no CVEs requested); PyPI shows 0 vulnerabilities for the package. Next step: nudge the maintainer to request a CVE (in-repo precedent: issue #57 for GHSA-7v25-vcp6-4hcr).

## What this demonstrates

Parser-differential analysis — finding security guards that check a *narrower language* than the system they guard. Here that meant two differentials at once: the validator's exact-match strings vs. GNU getopt_long abbreviation semantics, and a single assumed grammar vs. the two real tar dialects (GNU and BSD) that consume option values differently. The tell was an inconsistency against a hardened sibling policy in the same file (sort/awk already resolved abbreviations). The proof was a minimal harmless payload, and the disclosure ran through GitHub Private Vulnerability Reporting with remediation and a regression test supplied to the maintainer.
