# Password Strength Checker

A Python CLI tool that evaluates password strength using a scoring engine based on length, character variety, and common pattern detection. Built as a first step into cybersecurity.

## Why I built this

Before university started, I wanted to start with a simple security project. I didn't have much experience in security yet, so a password strength checker felt like the right first project, small enough to finish, practical enough to learn from, and directly relevant to where I'm heading.

## Features

- Scores passwords on a scale of **0–100**
- Assigns strength ratings: Very Weak, Weak, Moderate, Strong, Very Strong
- Rewards longer passwords (up to 30 points)
- Checks for uppercase letters, lowercase letters, numbers, and symbols
- Detects 30+ common weak password patterns (password, qwerty, admin, etc.)
- Provides personalized feedback and improvement suggestions

## Tech Stack

`Python`

## Screenshots / Demo

### Good Password

![good_passwords](/documentation/image.png)

### Bad Password

![bad_passwords](/documentation/image-1.png)

```
=== Password Strength Checker ===

Enter password: Password123

=== RESULTS ===
Score: 55/100
Rating: Moderate

Feedback:
- Add symbols.
- Contains common pattern: password
- Contains common pattern: password123
```

## How It Works

The tool runs locally as a single Python script with no external dependencies. When a password is entered, it calculates a score based on three factors: length (up to 30 points), character variety across four classes (up to 40 points), and penalties for matching common weak patterns. The final score is clamped to 0–100 and mapped to a strength rating, with specific feedback returned to the user.

## Getting Started

### Prerequisites

- Python 3.x

### Installation

```bash
git clone https://github.com/AnelkaCH/PasswordStrengthChecker.git
cd PasswordStrengthChecker
```

### Usage

```bash
python password_checker.py
```

Enter a password when prompted, and the program will display the score, strength rating, and feedback.

## Project Structure

```
PasswordStrengthChecker/
├── password_checker.py
├── LICENSE
├── README.md
├── ARCHITECTURE.md
└── CHANGELOG.md
```

## Documentation

- [Architecture](./ARCHITECTURE.md) - design decisions and system structure
- [Changelog](./CHANGELOG.md) - version history

## License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) for details.

## Contact

Anelka Hariyanto - [LinkedIn](https://www.linkedin.com/in/anelka-hariyanto) - [GitHub: AnelkaCH](https://github.com/AnelkaCH)
