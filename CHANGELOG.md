# Changelog

## [Unreleased]

### Planned
- Offline Pwned Passwords range matching
- Cryptographically secure password generator
- Diceware-style passphrase generator
- Encrypted local vault
- Web/App UI version

## [2026-08-27] Version 1.4 - HaveIBeenPwned API Integration

### Added
- New `scripts/hibp.py` module implementing the HIBP Pwned Passwords k-anonymity range lookup
- `_hash_password()` hashes the password with SHA-1 and splits it into a 5-character prefix and 35-character suffix; only the prefix is ever sent over the network
- `_query_range()` calls `GET https://api.pwnedpasswords.com/range/{prefix}` using stdlib `urllib`; raises `HIBPError` on any network error, timeout, or non-200 response so callers can never silently treat an outage as safe
- `_parse_response()` scans the returned `SUFFIX:COUNT` blob locally and returns the breach count for the password's suffix, or 0 if not found
- `hibp_check()` wires the three private functions into a single public call returning `{checked, pwned, count, error}`; the full hash and plaintext password never leave the process (k-anonymity model, documented explicitly)
- `match_info["hibp"]` field added to the `score_password()` return value
- Score is capped at 20 when a password is found in a known breach
- Feedback warns when the check fails, with explicit instruction not to treat a failure as confirmation the password is safe
- HIBP result printed in the Detection section of the CLI output

### Changed
- `score_password()` now calls `hibp_check()` after all local checks
- `match_info` schema extended with the `hibp` key
- Made `nltk` and `zxcvbn` required, no longer optional
- Changed zxcvbn scoring to the one already made by zxcvbn

## [2026-08-22] Version 1.3.1 - The Restructuring

### Added
- A `requirements.txt` file to make downloading dependencies easier.
- New images for documentation

### Changed
- Reworded and updated `README.md` to accurately document my development.
- Moved `nist_checker.py` to the `scripts/` folder since it is not the main script for the project.
- Reworded how updates are worded in `CHANGELOG.md`

### Removed
- Removed old images

## [2026-08-19] Version 1.3 - NIST SP 800-63B Compliance Checker

### Added
- New `nist_checker.py` module implementing a control-matrix compliance check against NIST SP 800-63B Section 5.1.1.2 (Memorized Secret Verifiers)
- `check_nist_compliance()` returns a structured report with per-item pass/fail/not-assessed status, the cited clause for each failure, an overall compliant/non-compliant verdict, and a summary
- 10 controls covering: 8-character minimum, no truncation and 64+ support, no composition rules, no periodic rotation, commonly-used/breach list check, dictionary word check, context-specific word check (optional `--username`/`--service`), printable ASCII/Unicode/emoji acceptance, no password hints, and strength-meter screening
- Breach list and dictionary results come from the v1.1 `match_info`; entropy comes from the v1.2 zxcvbn analysis, both fed in as inputs rather than re-implemented
- Entropy is reported as a screening tool only, never a rejection rule, matching the standard's guidance
- New `--nist` flag on `password_checker.py` runs the compliance flow; `--json` emits a machine-readable report

## [2026-08-19] Version 1.2.1 - Removing COMMON_PATTERNS

### Added
- (none)

### Changed
- Remove `COMMON_PATTERNS`
- `COMMON_PATTERNS` is now handled by `zxcvbn`
- `score_password()` now returns `match_info` with boolean flags plus matched values and sources.

## [2026-08-19] Version 1.2 - Entropy-Based Scoring

### Added
- Integrated the `zxcvbn` library for pattern-aware entropy estimation, crack display times, and score mapping as the primary, authoritative entropy provider
- Added detailed entropy dictionary containing bits, guesses, score, and crack times to `score_password()` return data
- Graceful startup checks that verify the presence of `zxcvbn`, exit cleanly with installation instructions if missing

### Changed
- Updated `ARCHITECTURE.md` to document the exclusive choice of pattern-aware entropy over naive Shannon formulas

## [2026-08-18] Version 1.1 - Common Password Database + Dictionary Word Detection

### Added
- Common Password Database detection: checks input against a SecLists-derived breached/common password list (default top 1M), exact match with O(1) set lookup, -20 point penalty
- Dictionary word detection: NLTK `words` corpus, 4+ character substring matching, -10 point penalty per unique word (capped at 3)
- Leetspeak normalization (0 to o, 3 to e, @ to a, 1 to i, 5 to s, 7 to t, and more) applied before both list checks, so variants like `P@ssw0rd` are caught
- `scripts/download_wordlists.py` to fetch SecLists common-password lists into `data/` with stdlib only
- `score_password()` now returns `match_info` with boolean flags plus matched values and sources
- Graceful fallbacks: hardcoded pattern list is used when the database file is missing; dictionary check skips cleanly without NLTK installed

### Changed
- `score_password()` return signature is now `(score, feedback, match_info)`
- Common-password data files kept out of git (`data/common-passwords.txt` is gitignored)
- Hardcoded pattern list now scans the normalized form too, catching leetspeak variants even without the database file
- Scoring rebalanced: length is now worth up to 40 points and clean passwords earn a 20 point bonus, making 100/100 and the Very Strong rating reachable
- README, ARCHITECTURE, and project structure updated for v1.1

## [2026-07-19] Version 1.0.3 - Proper Documentation

### Added
- CHANGELOG.md with full version history
- ARCHITECTURE.md explaining system design and decisions
- documentation/ folder filled with screenshots

### Changed
- Rewrote README.md to follow standard project documentation structure

### Removed
- Personal profile content that was duplicated in README.md
- Template files (README_template, CHANGELOG_template, ARCHITECTURE_template)

## [2026-07-14] Version 1.0.2 - Optimisation of Feedback

### Added
- Feedback suggestion when password is shorter than 16 characters

### Fixed
- Naming bug in feedback output

## [2026-07-08] Version 1.0.1 - New Common Password Patterns

### Added
- More common password patterns to the detection list (passw0rd, qwerty123, 1q2w3e4r, 111111, 000000, asdfghjkl, user, guest)

## [2025-06-25] Version 1.0.0 - The Password Checker

### Added
- Password scoring on a 0–100 scale
- Strength rating system (Very Weak, Weak, Moderate, Strong, Very Strong)
- Length-based scoring (up to 30 points)
- Character variety scoring: uppercase, lowercase, digits, symbols (up to 40 points)
- Common weak password pattern detection with penalty scoring
- Personalized feedback and improvement suggestions
- CLI interface for interactive use
