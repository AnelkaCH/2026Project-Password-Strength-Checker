# Password Strength Checker

A Python CLI tool that scores password strength using zxcvbn pattern-aware entropy, a breached-password database, dictionary word detection, and a full NIST SP 800-63B compliance check.

## Screenshots

### Good Password
![good_passwords](/documentation/good_password.png)

### Bad Password
![bad_passwords](/documentation/bad_password.png)

### NIST Compliance Report
![compliance_report](/documentation/compliance_report.png)

## Features

- Scores passwords from 0 to 100 using zxcvbn pattern-aware entropy estimates
- Rates them Very Weak, Weak, Moderate, Strong, or Very Strong
- Flags missing uppercase letters, lowercase letters, numbers, and symbols as improvement guidance only (never affects the score)
- Checks passwords against a breached/common password database (SecLists, top 1M) using O(1) set lookups
- Catches dictionary words hidden inside passwords, including leetspeak variants like `P@ssw0rd`
- Checks the password against the HaveIBeenPwned Pwned Passwords API using k-anonymity: only a 5-character SHA-1 prefix is sent, the plaintext and full hash never leave your machine; no API key required
- Caps the score at 20 when a breach hit is found; treats an API failure as an explicit warning rather than a pass
- Skips the local breach check cleanly when the database file is absent (the NIST report marks that control not assessed)
- Uses the `zxcvbn` library for pattern-aware entropy scoring and realistic crack-time estimates
- Runs a full NIST SP 800-63B Section 5.1.1.2 compliance check, with a control matrix of pass, fail, not assessed, and informational statuses and the exact clause cited for each failure
- Gives specific feedback: which word matched, which list it came from, what to fix

## How It Works

When a password is entered, it gets normalized first (lowercased, leetspeak translated, symbols stripped) so obfuscated versions still get caught properly. The numeric score comes from zxcvbn's pattern-aware guess estimate: guesses are converted to entropy bits via log2, then mapped onto the 0-100 scale using fixed bit thresholds at 28, 36, 60, and 80 bits, clamped, and mapped to a strength rating. Separately, an exact-match check runs against a breached/common password database and a dictionary scan finds embedded words through 4+ character substring matching; both surface only as feedback and detection details, never as score adjustments, and both feed the NIST compliance report.

Version 1.2 added `zxcvbn` for entropy analysis, which looks at guess difficulty instead of just counting character types, and gives crack time estimates under different attack conditions.

Version 1.3 added a NIST compliance checker that runs the password through the real requirements in NIST SP 800-63B Section 5.1.1.2. Most password meters get this standard backwards, they still enforce composition rules and periodic rotation, both of which NIST explicitly tells you to stop doing. This checker follows the actual clauses instead: 8 character minimum, no composition rules, no rotation, list-based rejection, and Unicode/emoji allowed. It builds its report on top of the v1.1 breach/dictionary results and the v1.2 entropy score rather than redoing that work.

Version 1.4 added HaveIBeenPwned API integration. After all local checks run, the password is hashed with SHA-1 and split: only the first 5 characters (prefix) go to the API, the remaining 35 (suffix) stay local. The API returns every hash suffix it knows that starts with that prefix, and the suffix is compared locally. This k-anonymity design means the plaintext password and full hash are never sent anywhere. If the password appears in a known breach the score is capped at 20 regardless of entropy, and if the API is unreachable the tool surfaces an explicit warning instead of silently passing.

## What I Learned

Going in, I assumed a stronger password checker just meant stricter rules, more required symbols, longer minimums, more rejected patterns. Reading the actual NIST standard changed that completely. NIST 800-63B argues the opposite: composition rules and forced rotation push people toward predictable patterns (Password1!, Password2!) and don't actually stop attackers. What works better is checking against real breach data and letting people use long, simple passphrases. That was the most useful thing I took from this project, since "more rules" and "more secure" turned out not to be the same thing.

Building the dictionary detection also taught me that naive substring matching breaks fast. A password like `Passw0rd123` needed leetspeak normalization before matching would catch it, and even then I had to be careful not to flag legitimate substrings inside longer words as false positives.

Translating a legal/technical standard into actual pass/fail code was its own skill. NIST documents aren't written to be turned into logic straight away, so figuring out which clauses were testable rules versus general guidance was most of the work in v1.3.

The HIBP integration in v1.4 taught me how to consume a real security API safely. The k-anonymity model (send only 5 chars of the hash, compare the rest locally) is a clean solution to the privacy problem of "how do you check if a password is breached without sending the password". Handling the failure case correctly was the other lesson: an API timeout should never look the same as a clean result.

## Getting Started

### Prerequisites

- Python 3.x
- `zxcvbn` (for entropy and crack-time analysis)
- `nltk` with the `words` corpus (skips cleanly if missing)

### Installation

```bash
git clone https://github.com/AnelkaCH/PasswordStrengthChecker.git
cd PasswordStrengthChecker
pip install -r requirements.txt
python -m nltk.downloader words
python scripts/download_wordlists.py
```

`download_wordlists.py` downloads the SecLists top-1M common password list into `data/common-passwords.txt`. Use `--list 100000` or `--list 10000` for smaller, faster lists.

### Using the Password Checker

```bash
python password_checker.py
```

Enter a password when prompted to see the score, rating, feedback, and detection details.

### Using the NIST Compliance Checker

```bash
python password_checker.py --nist
python scripts/nist_checker.py --json --username bob --service example.com
```

Both commands prompt for a password, run the full v1.1/v1.2 analysis, and return a compliance matrix against NIST SP 800-63B Section 5.1.1.2, with a compliant/non-compliant verdict. Add `--username` and `--service` to check for context-specific words, and `--json` for a machine-readable report.

## Project Structure

```
PasswordStrengthChecker/
├── password_checker.py
├── scripts/
│   ├── download_wordlists.py
│   ├── hibp.py
│   └── nist_checker.py
├── data/
│   └── common-passwords.txt   (gitignored, created by the download script)
├── LICENSE
├── README.md
├── ARCHITECTURE.md
└── CHANGELOG.md
```

## Do I plan to do more with this project?

Yes! I actually want to add more features. This project is the first step toward a full password manager: a generator next, then a vault built with Argon2id and AES-256-GCM. More detail in [ARCHITECTURE.md](./ARCHITECTURE.md).

## Documentation

- [Architecture](./ARCHITECTURE.md) - design decisions and system structure
- [Changelog](./CHANGELOG.md) - version history

## License

MIT License, see [LICENSE](./LICENSE) for details.

## Contact

Anelka Hariyanto - [LinkedIn](https://www.linkedin.com/in/anelka-hariyanto) - [GitHub: AnelkaCH](https://github.com/AnelkaCH)