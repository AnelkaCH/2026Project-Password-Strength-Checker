# Architecture

This document explains how the system is structured and why key decisions were made.

## Overview

A single-file Python CLI tool that evaluates password strength locally. The scoring engine combines length, character variety, common-password database detection, and dictionary word detection into a 0-100 score, then maps it to a human-readable strength rating. Common-password lists are stored in `data/` and English words come from the NLTK `words` corpus.

```
[User Input] -> [score_password()] -> (score, feedback, match_info) -> [get_rating()] -> [CLI Output]
```

## Key Components

### COMMON_PATTERNS (list)
A hardcoded fallback list of 30 common weak passwords (password, 123456, qwerty, admin, etc.), used only when no database file is present. 15 points are deducted per match.

### normalize()
Normalizes a password before list checks: lowercases it, translates leetspeak characters to letters (0 to o, 3 to e, @ to a, 1 to i, 5 to s, 7 to t, and more) via a `str.maketrans` table, then strips remaining non-alphanumeric characters. This turns `P@ssw0rd` into `password`, which naive matching would miss.

### _load_common_passwords()
Lazily reads `data/common-passwords.txt` (latin-1) into a `set` for O(1) exact-match lookups, cached after first load. Returns an empty set if the file is missing.

### _load_dictionary_words()
Lazily loads the NLTK `words` corpus into a `set` of words at least 4 characters long. If NLTK or the corpus is unavailable it attempts a quiet `nltk.download("words")`, then falls back to an empty set with a console hint. Never raises.

### _find_dictionary_words()
Generates every 4+ character substring of the normalized password and checks each against the dictionary set. Longest matches are returned first.

### score_password()
The core scoring engine. It evaluates a password in four phases:
1. **Length scoring** - up to 40 points based on thresholds (8, 12, 16 characters)
2. **Character variety scoring** - up to 40 points, 10 points each for uppercase, lowercase, digits, and symbols
3. **Common-password check** - 20 points deducted for an exact hit against the database; 15 per hardcoded pattern match when the database is absent
4. **Dictionary word check** - 10 points deducted per unique matched word, capped at 3 words
5. **Clean bonus** - 20 points added when neither the common-password nor the dictionary check matched, so a full-score password is achievable

Returns a clamped score (0-100), a list of feedback strings, and a `match_info` dict with boolean flags plus the matched values and sources.

### get_rating()
Maps a numeric score to one of five strength labels: Very Weak (<30), Weak (<50), Moderate (<70), Strong (<90), Very Strong (90+).

### main()
Handles CLI I/O, prompts for a password, calls the scoring functions, and prints the score, rating, feedback, and detection summary to stdout.

## Design Decisions

- **Additive scoring with penalties** over entropy-based approaches.
  **Reasoning:** Simple, auditable, and transparent for a local-first tool. Entropy math is planned for a later version.

- **Set-based exact match for the breach database** over a list scan.
  **Reasoning:** Membership in a `set` is O(1) versus O(n) for a list. This matters when checking against millions of entries per request. RockYou-style lists store full passwords, so exact matching is the correct semantic.

- **Normalization before checking** against both the database and the dictionary.
  **Reasoning:** Attackers routinely substitute leetspeak characters. Normalizing catches `P@ssw0rd`, which naive matching misses, and documenting this logic shows understanding of real attacker behavior.

- **Database supersedes the hardcoded list** when present.
  **Reasoning:** The downloaded database is a strict superset of the hardcoded patterns, so the fallback only runs when the data file is missing. The fallback scans both the raw and normalized forms.

- **Dictionary check via substring matching** of 4+ character substrings.
  **Reasoning:** Catches cases like `Password123` containing `password`. Longest matches are reported first to keep feedback readable.

- **NLTK `words` corpus for the dictionary** with graceful degradation.
  **Reasoning:** ~236k common English words with zero wordlist files committed to the repo. When NLTK is unavailable the check is skipped with a hint instead of crashing.

- **Differentiated penalties** (20 for breach, 10 per dictionary word, 15 for hardcoded fallback).
  **Reasoning:** Membership in a breached-password database is the highest-signal signal and should cost the most.

- **Clean bonus of 20 points** when no detection matches.
  **Reasoning:** Length (40) plus variety (40) only reaches 70, which made 100/100 and the Very Strong rating unreachable. The bonus rewards genuinely clean passwords and keeps the full 0-100 scale meaningful.

- **Score clamped to 0-100** rather than allowing negative values.
  **Reasoning:** A bounded scale is more intuitive for end users and maps cleanly to the five-tier rating system.

## Data Flow

1. User runs `python password_checker.py`
2. Program prompts for password input via `input()`
3. `score_password()` processes the password:
   - Calculates length score (0-30)
   - Checks character classes and adds variety score (0-40)
   - Normalizes the password and checks it against the common-password database (or the hardcoded fallback)
   - Scans normalized substrings against the dictionary and deducts penalties
   - Adds the clean bonus when no detection matched
   - Clamps final score to 0-100
4. `get_rating()` maps score to a strength label
5. Score, rating, feedback, and detection details are printed to stdout
6. Program exits, no state is persisted

## Data Files

- `data/common-passwords.txt` - breached/common passwords, one per line. Downloaded with `python scripts/download_wordlists.py` (SecLists top 100k/1M). Gitignored because it is large.
- English dictionary words come from the NLTK `words` corpus at runtime, not from repo files.

## Known Limitations / Future Work

- No entropy calculation, scoring is rule-based, not entropy-based
- Breach check is exact-match only; a full RockYou-scale list will slow first-load slightly but lookups stay O(1)
- No HaveIBeenPwned API integration (planned for next version)
- Dictionary substring matching can report incidental matches (for example `sword` inside `password`)
- No password generation suggestions
- No GUI, CLI only
- Single-threaded, interactive use only, no batch mode
