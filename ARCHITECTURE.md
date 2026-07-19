# Architecture

This document explains how the system is structured and why key decisions were made.

## Overview

A single-file Python CLI tool that evaluates password strength locally with no external dependencies. The scoring engine combines length, character variety, and common pattern detection into a 0–100 score, then maps it to a human-readable strength rating.

```
[User Input] → [score_password()] → (score, feedback) → [get_rating()] → [CLI Output]
```

## Key Components

### COMMON_PATTERNS (list)
A hardcoded list of 30 common weak passwords (password, 123456, qwerty, admin, etc.). When any of these appear as a substring in the input, 15 points are deducted per match. The list was built from well-known weakest-password rankings.

### score_password()
The core scoring engine. It evaluates a password in three phases:
1. **Length scoring** - up to 30 points based on thresholds (8, 12, 16 characters)
2. **Character variety scoring** - up to 40 points, 10 points each for uppercase, lowercase, digits, and symbols
3. **Common pattern penalty** - 15 points deducted per matched pattern

Returns a clamped score (0–100) and a list of feedback strings.

### get_rating()
Maps a numeric score to one of five strength labels: Very Weak (<30), Weak (<50), Moderate (<70), Strong (<90), Very Strong (90+).

### main()
Handles CLI I/O, prompts for a password, calls the scoring functions, and prints the results and feedback to stdout.

## Design Decisions

- **Additive scoring with penalties** over entropy-based or dictionary-based approaches.
  **Reasoning:** Simple, auditable, and requires zero external dependencies. For a local-first tool, transparency in how the score is calculated matters more than cryptographic precision.

- **Hardcoded pattern list** over file-based or network-fetched wordlists.
  **Reasoning:** Keeps the tool dependency-free and portable, runs anywhere Python 3.x is installed with no setup beyond cloning the repo.

- **Score clamped to 0–100** rather than allowing negative values.
  **Reasoning:** A bounded scale is more intuitive for end users and maps cleanly to the five-tier rating system.

- **Penalty per substring match** rather than exact match.
  **Reasoning:** Catches variants like "mypassword123" that still contain the weak pattern, making detection more useful in practice.

## Data Flow

1. User runs `python password_checker.py`
2. Program prompts for password input via `input()`
3. `score_password()` processes the password:
   - Calculates length score (0–30)
   - Checks character classes and adds variety score (0–40)
   - Scans for common patterns and deducts penalties
   - Clamps final score to 0–100
4. `get_rating()` maps score to a strength label
5. Score, rating, and feedback are printed to stdout
6. Program exits, no state is persisted

## Known Limitations / Future Work

- No entropy calculation, scoring is rule-based, not entropy-based
- No dictionary word detection beyond the hardcoded pattern list
- No HaveIBeenPwned API integration (planned for next version)
- Common patterns list is static and doesn't scale without manual updates
- No password generation suggestions
- No GUI, CLI only
- Single-threaded, interactive use only, no batch mode
