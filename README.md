# Password Strength Checker

A Python CLI tool that evaluates password strength using a scoring engine based on length, character variety, a common-password breach database, and dictionary word detection. Built as a first step into cybersecurity.

## Why I built this

Before university started, I wanted to start with a simple security project. I didn't have much experience in security yet, so a password strength checker felt like the right first project, small enough to finish, practical enough to learn from, and directly relevant to where I'm heading.

## Features

- Scores passwords on a scale of **0-100**
- Assigns strength ratings: Very Weak, Weak, Moderate, Strong, Very Strong
- Rewards longer passwords (up to 40 points)
- Awards a bonus for clean passwords with no detected weaknesses
- Checks for uppercase letters, lowercase letters, numbers, and symbols
- Checks passwords against a **breached/common password database** (SecLists, default top 1M) with O(1) set lookups
- Detects **dictionary words** inside passwords via 4+ character substring matching (NLTK `words` corpus)
- **Leetspeak normalization** catches variants like `P@ssw0rd` that naive matching misses
- Falls back to a hardcoded common-pattern list when the database file is not present
- Provides personalized feedback and improvement suggestions, including which list or word matched
- **Entropy Analysis** (Version 1.2):
  - Integrates the **`zxcvbn` library** for a mathematically grounded, pattern-aware strength score and estimated crack times (keyboard walks, dictionary words, and common substitutions)
- **NIST SP 800-63B Compliance Checker** (Version 1.3):
  - Runs a password through the actual requirements of **NIST SP 800-63B Section 5.1.1.2** (Memorized Secret Verifiers) and returns a pass/fail control matrix with the cited clause for each failure
  - Builds the compliance report on the v1.1 breach/dictionary list results and the v1.2 entropy score instead of re-implementing them
  - Gets the standard right where most meters get it backwards: no composition rules, no periodic rotation, 8-char minimum is compliant if the password is clean, and the entropy meter is treated as a screening tool, not a rejection rule

## Tech Stack

`Python` (stdlib math, re, pathlib, urllib)
`zxcvbn` (required, for pattern-aware analysis)
`nltk` (optional, for English dictionary word matching)

## Screenshots / Demo

### Good Password

![good_passwords](/documentation/image.png)

### Bad Password

![bad_passwords](/documentation/image-1.png)

```
=== Password Strength Checker ===

Enter password: P@ssw0rd

=== RESULTS ===
Score: 10/100
Rating: Very Weak

Feedback:
- Consider making your password longer than 16 characters for better security.
- Password found in a database of 10,000 breached passwords.
- Contains dictionary word(s): password, sword, pass

Detection:
- Breached/common password: password (source: database)
- Dictionary word: password, sword, pass
```

## How It Works

The tool runs locally as a Python script. When a password is entered, it calculates a score based on four factors: length (up to 40 points), character variety across four classes (up to 40 points), an exact-match check against a breached/common password database (20 point penalty), and dictionary word detection (10 points per word, capped at 3). Passwords with no detected weaknesses earn a 20 point bonus, so a 16+ character password using all four character classes can score 100. The password is normalized first (lowercased, leetspeak translated, non-alphanumeric characters stripped) so obfuscated variants are caught. The final score is clamped to 0-100 and mapped to a strength rating, with feedback returned to the user.

In Version 1.2, it also performs a pattern-aware entropy analysis using the `zxcvbn` library. This evaluates password strength based on guess difficulty (representing actual entropy in bits) rather than naive character sets, and estimates realistic cracking times under various attack scenarios (online vs. offline fast/slow hashing).

## Getting Started

### Prerequisites

- Python 3.x
- `zxcvbn` library (required, for pattern-aware entropy and crack-time estimates)
- `nltk` with the `words` corpus for dictionary detection (optional, skips cleanly if missing)

### Installation

```bash
git clone https://github.com/AnelkaCH/PasswordStrengthChecker.git
cd PasswordStrengthChecker
pip install zxcvbn nltk
python -m nltk.downloader words
python scripts/download_wordlists.py
```

`download_wordlists.py` fetches the SecLists top-1M common-password list into `data/common-passwords.txt`. Use `--list 100000` or `--list 10000` for smaller, faster lists.

### Usage

```bash
python password_checker.py
```

Enter a password when prompted, and the program will display the score, strength rating, feedback, and detection details.

### NIST SP 800-63B Compliance Checker

```bash
python password_checker.py --nist
python nist_checker.py --json --username bob --service example.com
```

Both entry points prompt for a password, run the v1.1/v1.2 analysis, then produce a control matrix against NIST SP 800-63B Section 5.1.1.2 with an overall `compliant` or `non-compliant` verdict. Add `--username` and/or `--service` to enable the context-specific word check. Add `--json` for a machine-readable report.

## Project Structure

```
PasswordStrengthChecker/
├── password_checker.py
├── nist_checker.py
├── scripts/
│   └── download_wordlists.py
├── data/
│   └── common-passwords.txt   (gitignored, created by the download script)
├── LICENSE
├── README.md
├── ARCHITECTURE.md
└── CHANGELOG.md
```

## Documentation

- [Architecture](./ARCHITECTURE.md) - design decisions and system structure
- [Changelog](./CHANGELOG.md) - version history

## References

- NIST SP 800-63B Section 5.1.1.2 (memorized secret verifiers) requires checking passwords against lists of commonly-used, expected, or compromised values.
- The v1.3 compliance checker is built from the primary text of SP 800-63B Section 5.1.1.2, not secondhand summaries. Most password meters get NIST 800-63B backwards by still enforcing the composition rules the standard explicitly discourages. This checker encodes the actual clauses: 8-character minimum, no composition rules, no periodic rotation, list-based rejection, printable ASCII plus Unicode/emoji acceptance, and no password hints. Translating a regulatory document into automated control checks is the core job of a GRC analyst, and this module does exactly that in miniature.

## License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) for details.

## Contact

Anelka Hariyanto - [LinkedIn](https://www.linkedin.com/in/anelka-hariyanto) - [GitHub: AnelkaCH](https://github.com/AnelkaCH)
