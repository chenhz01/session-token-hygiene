# Changelog

All notable changes to this project are documented here.
Format based on Keep a Changelog; versioning: SemVer.

## [0.1.1] - 2026-10-13

### Fixed / Revised (round-2 iteration)
- pinned boundary semantics by test: access TTL exactly 24h is WARN (over 1h warn ceiling), only >24h is FAIL (C10)
- unnamed-token placeholder assertion hardened (H011 fires first, placeholder verified across all findings)

### Verification
- self_test re-run green after revisions: SUMMARY: PASS 66/66 (64 cases + 2 meta; >=60 gate met)
- CLI error contract re-verified (exit 0/1/2); four scaffold-v2 defenses inherited.

## [0.1.0] - 2026-10-13

### Added
- Core module `session_token_hygiene.py`: check (policy.json, --max-access-warn/--max-access-fail/--max-refresh-fail, --json), pure standard library.
- argparse CLI with `--json` machine output and 0/1/2 exit-code contract.
- `self_test.py` inheriting scaffold-v2 defenses: SystemExit capture, unicode-safe
  regexes, `newline=""` fixtures, and the `SUMMARY: PASS n/n` last-line contract.
- README (Performance section with [Measured] numbers and in-repo repro commands),
  MIT LICENSE, ALIGNMENT.md (16-item rubric).
