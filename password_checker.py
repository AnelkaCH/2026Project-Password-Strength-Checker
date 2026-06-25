import re

# Some common patterns that I could think of at the moment
COMMON_PATTERNS = [
    "password",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
    "abc123",
    "password123",
    "qwerty",
    "asdf",
    "zxcv",
    "12345"
]


def get_rating(score):
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Moderate"
    elif score < 90:
        return "Strong"
    else:
        return "Very Strong"


def score_password(password):
    score = 0
    feedback = []

    # The longer, the better (max points = 30)
    length = len(password)

    if length >= 16:
        score += 30
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        feedback.append("Password is too short (minimum 8 characters).")

    # There should variety (max points = 40)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", password))

    score += sum([
        has_upper,
        has_lower,
        has_digit,
        has_symbol
    ]) * 10

    if not has_upper:
        feedback.append("Add uppercase letters.")

    if not has_lower:
        feedback.append("Add lowercase letters.")

    if not has_digit:
        feedback.append("Add numbers.")

    if not has_symbol:
        feedback.append("Add symbols.")

    # Common patterns
    lowered = password.lower()

    for pattern in COMMON_PATTERNS:
        if pattern in lowered:
            score -= 15
            feedback.append(
                f"Contains common pattern: {pattern}"
            )

    # Scoring
    score = max(0, min(score, 100))

    return score, feedback


def main():
    print("=== Password Strength Checker ===\n")

    password = input("Enter password: ")

    score, feedback = score_password(password)

    print("\n=== RESULTS ===")
    print(f"Score: {score}/100")
    print(f"Rating: {get_rating(score)}")

    print("\nFeedback:")
    if feedback:
        for item in feedback:
            print(f"- {item}")
    else:
        print("- Excellent password!")


if __name__ == "__main__":
    main()