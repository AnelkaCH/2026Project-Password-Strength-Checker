# Password Strength Checker 🫣

( Note: This is an on-going project )

Before university starts, before all of that, I want to start with a simple security project: a password strength checker. Since I don't really have that much experience in security yet, I think this project marks my first steps. This project will created with python, since I can do python.

## Version 1.1

### Updated Features

* Just added more common password patterns.

(Note: I'm currently adding a new feature. Hopefully I figure out how to add it.)

## Version 1.0

### Created Features

* Scores passwords on a scale of **0–100**
* Assigns a strength rating:

  * Very Weak
  * Weak
  * Moderate
  * Strong
  * Very Strong
* Rewards longer passwords (up to 30 points)
* Checks for:

  * Uppercase letters
  * Lowercase letters
  * Numbers
  * Symbols
* Detects common weak password patterns such as:

  * password
  * password123
  * qwerty
  * admin
  * letmein
  * and others
* Provides personalized feedback and improvement suggestions

### How It Works

The password score is calculated based on:

1. **Length** (up to 30 points)
2. **Character variety** (up to 40 points)

   * Uppercase letters
   * Lowercase letters
   * Digits
   * Symbols
3. **Common password pattern detection**

   * Deducts points for commonly used and easily guessed patterns

## Usage

Run the script:

```bash
python password_checker.py
```

Enter a password when prompted, and the program will display:

* Password score
* Strength rating
* Feedback and recommendations

## Example Output

```text
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

## Future Improvements

There so many things I want to add. For example: 
* Entropy-based scoring
* Dictionary word detection
* Password generation suggestions
* GUI version
