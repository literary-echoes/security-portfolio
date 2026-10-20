# Security Research — literary-echoes

Vulnerability research in open-source software, focused on MCP servers and WordPress plugins. Every finding below was reported through coordinated disclosure (GitHub Private Vulnerability Reporting, vendor channels, or Patchstack), with a suggested fix and — where possible — a regression test included in the report.

## Case studies

- **[Case study 2 — Allowlist bypass via tar argument-parser differentials (argument injection)](case-studies/02-mcp-shell-server-tar-allowlist-bypass.md)** — `tumf/mcp-shell-server` · CWE-88 · High. Published advisory [GHSA-3g42-7xr6-4x77](https://github.com/tumf/mcp-shell-server/security/advisories/GHSA-3g42-7xr6-4x77) (primary record for GHSA-vfjj-qwhx-h2wc / GHSA-38g6-q83h-hj4f); fixed in v1.1.14.
- **[Case study 3 — Sandbox escape through a second reference to the original core (`__bootstrap.core.print`)](case-studies/03-mcp-js-bootstrap-print-sandbox-escape.md)** — `r33drichards/mcp-js` · CWE-693 · Critical. Fixed via [PR #289](https://github.com/r33drichards/mcp-js/pull/289) (2026-10-20), maintainer-verified with a live repro and regression tests.

## Findings

| # | Date | Target | Severity | Status | Link |
|---|---|---|---|---|---|
| 19 | 2026-10-11 | r33drichards/mcp-js | Critical | Fixed (PR #289, 2026-10-20) | [issue #279](https://github.com/r33drichards/mcp-js/issues/279) |
| 12 | 2026-10-08 | tumf/mcp-shell-server | High | Published + fixed (v1.1.14) | [GHSA-3g42-7xr6-4x77](https://github.com/tumf/mcp-shell-server/security/advisories/GHSA-3g42-7xr6-4x77) |
| 15 | 2026-10-10 | libreform/libreform (WP Libre Form 2) | Critical | Patchstack — awaiting triage | — |
| 17 | 2026-10-11 | comptoirdesappli/amapress | Critical | Open (public issue) | [issue #39](https://github.com/comptoirdesappli/amapress/issues/39) |
| 18 | 2026-10-11 | sinanisler/gumroad-connect | Critical | Open (public issue) | [issue #3](https://github.com/sinanisler/gumroad-connect/issues/3) |
| 16 | 2026-10-11 | wp-sync-db/wp-sync-db-media-files | High | Open (public issue) | [issue #45](https://github.com/wp-sync-db/wp-sync-db-media-files/issues/45) |
| 11 | 2026-10-10 | msrbuilds/wp-launcher | High | Open (public issue) | [issue #13](https://github.com/msrbuilds/wp-launcher/issues/13) |
| 13 | 2026-10-10 | bilalnaseer/wsp-wordpress-mcp | High + Medium + Low | Vendor + plugins@wordpress.org; Patchstack eligibility inquiry pending | — |
| 20 | 2026-10-11 | r33drichards/mcp-js | Medium | Open | [issue #280](https://github.com/r33drichards/mcp-js/issues/280) |
| 14 | 2026-10-10 | Ultimate-Multisite/ultimate-multisite | Medium | GHSA in triage — details withheld until published | — |
| — | 2026-10 | Muvon/octofs | Critical | Open (public issue) | [issue #12](https://github.com/Muvon/octofs/issues/12) |
| — | 2026-10 | H-mmer/pentest-agents | High | Open (public issue) | [issue #27](https://github.com/H-mmer/pentest-agents/issues/27) |
| — | 2026-10 | H-mmer/pentest-agents | High | Open (public issue) | [issue #28](https://github.com/H-mmer/pentest-agents/issues/28) |
| — | 2026-10 | kontext-security/browser-use-mcp-server | High | Open (public issue) | [issue #69](https://github.com/kontext-security/browser-use-mcp-server/issues/69) |
| — | 2026-10 | pathintegral-institute/mcpm.sh | High | Open (public issue) | [issue #447](https://github.com/pathintegral-institute/mcpm.sh/issues/447) |
| — | 2026-10 | Muvon/octofs | High | Open (public issue) | [issue #13](https://github.com/Muvon/octofs/issues/13) |
| — | 2026-10 | d3cline/VibeShell | High | Open (public issue) | [issue #1](https://github.com/d3cline/VibeShell/issues/1) |
| — | 2026-10 | fkxxyz/mcp-shell | High | Open (public issue) | [issue #2](https://github.com/fkxxyz/mcp-shell/issues/2) |
| — | 2026-10 | zinja-coder/apktool-mcp-server | Medium | Open (public issue) | [issue #17](https://github.com/zinja-coder/apktool-mcp-server/issues/17) |
| — | 2026-10 | pathintegral-institute/mcpm.sh | Medium | Open (public issue) | [issue #448](https://github.com/pathintegral-institute/mcpm.sh/issues/448) |
| — | 2026-10 | d3cline/VibeShell | Medium | Open (public issue) | [issue #2](https://github.com/d3cline/VibeShell/issues/2) |
| — | 2026-10 | saumilthecode/mcp-shell-exec | Medium | Open (public issue) | [issue #1](https://github.com/saumilthecode/mcp-shell-exec/issues/1) |
| — | 2026-10 | soflyy/agent-connector-for-wp | Medium | Open (public issue) | [issue #137](https://github.com/soflyy/agent-connector-for-wp/issues/137) |
| — | 2026-10 | noovertime7/mcp-shell | Low | Open (public issue) | [issue #1](https://github.com/noovertime7/mcp-shell/issues/1) |

## Disclosure policy

Writeups are published only after the vendor publishes an advisory or ships a fix. Reports still in triage are listed above without technical details. One further writeup (msrbuilds/wp-launcher, High) is complete but held until the maintainer responds or fixes.

## Contact

GitHub: [@literary-echoes](https://github.com/literary-echoes)
