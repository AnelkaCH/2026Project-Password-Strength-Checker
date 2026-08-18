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

## Tech Stack

`Python`

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

## Getting Started

### Prerequisites

- Python 3.x
- NLTK with the `words` corpus for dictionary detection (optional, detection skips cleanly without it)

### Installation

```bash
git clone https://github.com/AnelkaCH/PasswordStrengthChecker.git
cd PasswordStrengthChecker
pip install nltk
python -m nltk.downloader words
python scripts/download_wordlists.py
```

`download_wordlists.py` fetches the SecLists top-1M common-password list into `data/common-passwords.txt`. Use `--list 100000` or `--list 10000` for smaller, faster lists.

### Usage

```bash
python password_checker.py
```

Enter a password when prompted, and the program will display the score, strength rating, feedback, and detection details.

## Project Structure

```
PasswordStrengthChecker/
├── password_checker.py
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

## License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) for details.

## Contact

Anelka Hariyanto - [LinkedIn](https://www.linkedin.com/in/anelka-hariyanto) - [GitHub: AnelkaCH](https://github.com/AnelkaCH)
