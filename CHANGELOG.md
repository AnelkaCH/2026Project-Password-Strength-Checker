# Changelog

## [Unreleased]

### Planned
- Entropy-based scoring
- NIST SP 800-63B compliance checker
- HaveIBeenPwned API integration for breach checking
- Offline Pwned Passwords range matching
- Cryptographically secure password generator
- Diceware-style passphrase generator
- Encrypted local vault
- Web UI version

## [2026-08-18] - Version 1.1 (Common Password Database + Dictionary Word Detection)

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

## [2026-07-19] - Version 1.0.3

### Added
- CHANGELOG.md with full version history
- ARCHITECTURE.md explaining system design and decisions
- documentation/ folder filled with screenshots

### Changed
- Rewrote README.md to follow standard project documentation structure

### Removed
- Personal profile content that was duplicated in README.md
- Template files (README_template, CHANGELOG_template, ARCHITECTURE_template)

## [2026-07-14] - Version 1.0.2

### Added
- Feedback suggestion when password is shorter than 16 characters

### Fixed
- Naming bug in feedback output

## [2026-07-08] - Version 1.0.1

### Added
- More common password patterns to the detection list (passw0rd, qwerty123, 1q2w3e4r, 111111, 000000, asdfghjkl, user, guest)

## [2025-06-25] - Version 1.0.0

### Added
- Password scoring on a 0–100 scale
- Strength rating system (Very Weak, Weak, Moderate, Strong, Very Strong)
- Length-based scoring (up to 30 points)
- Character variety scoring: uppercase, lowercase, digits, symbols (up to 40 points)
- Common weak password pattern detection with penalty scoring
- Personalized feedback and improvement suggestions
- CLI interface for interactive use
