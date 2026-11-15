# Architecture

This document explains how the system is structured and why key decisions were made.

## Overview

A Python CLI tool that evaluates password strength. The numeric score comes from zxcvbn's pattern-aware strength estimate. Three detection checks run alongside it: a local common-password database, an NLTK dictionary scan, and a HaveIBeenPwned (HIBP) breach lookup. A separate module turns those results into a NIST SP 800-63B compliance report.

The entry point is `password_checker.py`. All logic lives in `scripts/`:

| Module | Responsibility |
|---|---|
| `password_checker.py` | CLI input and output, `--nist` routing, optional report prompt |
| `scripts/core.py` | `score_password()`, the scoring and detection engine |
| `scripts/pw_scoring.py` | Maps zxcvbn scores to 0-100 and 0-100 to a rating |
| `scripts/pw_normalizer.py` | Leetspeak and symbol normalization |
| `scripts/common_pw_and_dict.py` | Loads the common-password list and NLTK words, finds embedded words |
| `scripts/hibp.py` | HIBP Pwned Passwords k-anonymity lookup |
| `scripts/nist_checker.py` | NIST SP 800-63B Section 5.1.1.2 control matrix |
| `scripts/download_wordlists.py` | Downloads the SecLists common-password list into `data/` |

## Key Components

### score_password() (scripts/core.py)
The core engine. Returns `(score, feedback, match_info)`.

1. Runs zxcvbn to get the guess estimate, entropy bits (log2 of guesses), the 0-4 zxcvbn score, and crack-time estimates.
2. Converts the zxcvbn score to 0-100 with `entropy_to_score()`.
3. Adds guidance feedback for length under 8, missing character classes, and length of 16 or less when the zxcvbn score is below 4. Guidance never changes the score.
4. Checks the common-password database (see below). A match caps the score at 20.
5. Scans for embedded dictionary words. Matches are reported as feedback only.
6. Queries HIBP. A breach hit caps the score at 20. A failed lookup adds an explicit warning.
7. Clamps the score to 0-100.

`match_info` holds `common_password`, `dictionary_word`, `entropy` (bits, guesses, score, crack_times, failed) and `hibp` (checked, pwned, count, error).

### entropy_to_score() and get_rating() (scripts/pw_scoring.py)
`entropy_to_score()` multiplies the zxcvbn score by 25, so possible scores are 0, 25, 50, 75 and 100. `get_rating()` maps the score to Very Weak (<30), Weak (<50), Moderate (<70), Strong (<90) or Very Strong (90+).

### normalize() and normalize_symbols() (scripts/pw_normalizer.py)
`normalize()` lowercases the password, applies the full leetspeak table (digits and symbols, for example 0 to o, 3 to e, @ to a, $ to s), then strips non-alphanumeric characters. It turns `P@ssw0rd` into `password`.

`normalize_symbols()` only translates `@` to a and `$` to s, then strips other symbols, leaving digits intact. It turns `P@ssword1` into `password1`, which the full table would turn into `passwordi`.

### Common-password lookup
The database is checked against three candidates in order: the fully normalized password, the symbol-only normalized password, and the plain lowercase password. The first hit wins.

### _load_common_passwords() (scripts/common_pw_and_dict.py)
Lazily reads `data/common-passwords.txt` (latin-1) into a cached `set` for O(1) lookups. Returns an empty set if the file is missing, which skips the check.

### _load_dictionary_words() and _find_dictionary_words()
NLTK and its `words` corpus are required. If either is missing, the module exits at import with install instructions. Words of 4 or more characters are cached in a `set`. `_find_dictionary_words()` checks every 4+ character substring of the normalized password and returns matches longest first.

### hibp_check() (scripts/hibp.py)
Hashes the password with SHA-1 and splits the hex digest into a 5-character prefix and 35-character suffix. Only the prefix is sent to `https://api.pwnedpasswords.com/range/{prefix}`. The response lists every known suffix for that prefix with a breach count, and the suffix is compared locally. Any network error, timeout or non-200 response raises `HIBPError`, which `hibp_check()` turns into `{"checked": False, ...}` so an outage is never reported as safe.

### check_nist_compliance() (scripts/nist_checker.py)
Takes the password and the `match_info` from `score_password()` and returns a 10-item control matrix against Section 5.1.1.2. Each item has a clause, a SHALL/SHOULD level, a status (pass, fail, na, info) and a detail. Any failed item makes the verdict non-compliant.

The dictionary control (item 6) fails only when the whole normalized password is a dictionary word. Passwords that merely contain words, such as passphrases, pass, and the contained words appear in the item detail.

### nist_checker.main()
Parses `--json`, `--username` and `--service`. When called from `password_checker.py` after the report prompt, it receives the existing password and `match_info` and reuses them. When run on its own (`--nist` or directly), it prompts for the password and calls `score_password()` itself.

## Design Decisions

- **zxcvbn score as the only source of the numeric score** (Version 1.4.1).
  **Reasoning:** Rule-based checklists reward predictable patterns, and Shannon entropy overstates the strength of human-chosen passwords. zxcvbn models real attacker guessing, so its 0-4 score is used directly.

- **Detections cap the score instead of subtracting points** (Version 1.4, extended in 1.4.2).
  **Reasoning:** A password that appears in a breach or on a common list is weak no matter how random it looks. Capping at 20 guarantees a Very Weak rating instead of a partial penalty.

- **Guidance is never a rejection rule.**
  **Reasoning:** NIST SP 800-63B forbids composition rules. Character-class and length tips are shown as suggestions only.

- **Hidden password input** (Version 1.4.2).
  **Reasoning:** `getpass` keeps the password off the screen and out of terminal scrollback.

- **Normalization before checking.**
  **Reasoning:** Attackers routinely substitute leetspeak characters. Checking several normalized forms catches `P@ssw0rd` and `P@ssword1` without guessing which digits are letters.

- **Set-based exact match for the breach database.**
  **Reasoning:** `set` membership is O(1), which matters with a million entries.

- **NLTK `words` corpus for the dictionary.**
  **Reasoning:** About 236k English words with no wordlist committed to the repo.

- **k-anonymity for HIBP** (Version 1.4).
  **Reasoning:** The plaintext and full hash never leave the machine, and no API key is needed.

- **Compliance as a control matrix** (Version 1.3).
  **Reasoning:** Auditing against a standard maps naturally to a checklist of controls, each tied to a clause and a SHALL/SHOULD level, which keeps every failure traceable.

- **Reuse results instead of re-running checks** (Version 1.3, extended in 1.4.2).
  **Reasoning:** The compliance module consumes `match_info` rather than repeating the checks, so there is one source of truth and only one HIBP request per run.

- **Entropy is a screening tool, not a rejection rule** (Version 1.3).
  **Reasoning:** SP 800-63B recommends a strength meter as user guidance. The entropy item is informational and never affects the verdict.

- **Policy controls still appear in the matrix** (Version 1.3).
  **Reasoning:** Composition rules, rotation and hints are verifier-side policies this tool does not enforce, so they pass with a note instead of being omitted.

## Data Flow

1. The user runs `python password_checker.py` and enters a password at a hidden prompt.
2. `score_password()` runs zxcvbn, builds guidance feedback, checks the common-password database, scans for dictionary words and queries HIBP.
3. `get_rating()` maps the score to a label.
4. The score, rating, entropy analysis, feedback and detections are printed.
5. The user is asked whether to generate a NIST report. On `y` or `yes`, `nist_checker.main()` builds it from the same `match_info`.
6. The program exits. No state is persisted.

## Data Files

- `data/common-passwords.txt`: breached/common passwords, one per line. Created with `python scripts/download_wordlists.py` (SecLists top 10k, 100k or 1M). Gitignored because it is large.
- English dictionary words come from the NLTK `words` corpus at runtime.

## Known Limitations / Future Work

- The common-password check is exact-match on three normalized forms. Mixed cases such as `M0nkey!2024`, where some digits are letters and others are numbers, are still missed.
- The score has only five possible values because it comes straight from the zxcvbn 0-4 score.
- The HIBP check adds about 1-2 seconds of network latency per run, with no caching.
- Dictionary substring matching reports incidental matches (for example `sword` inside `password`).
- The NIST report follows SP 800-63B Revision 3 (Section 5.1.1.2), not Revision 4.
- No tests yet.
- CLI only, interactive use only, no batch mode.
