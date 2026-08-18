import re
from pathlib import Path

COMMON_PATTERNS = [
    "password",
    "123456",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "password123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "iloveyou",
    "sunshine",
    "princess",
    "master",
    "login",
    "passw0rd",
    "qwerty123",
    "1q2w3e4r",
    "111111",
    "000000",
    "asdfghjkl",
    "user",
    "guest",
]

LEETSPEAK_TABLE = str.maketrans({
    "@": "a",
    "4": "a",
    "0": "o",
    "3": "e",
    "1": "i",
    "!": "i",
    "5": "s",
    "$": "s",
    "7": "t",
    "9": "g",
})

DATA_FILE = Path(__file__).parent / "data" / "common-passwords.txt"

_cached_passwords = None
_cached_words = None
_words_warned = False


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


def normalize(password):
    lowered = password.lower()
    translated = lowered.translate(LEETSPEAK_TABLE)
    return re.sub(r"[^a-z0-9]", "", translated)


def _load_common_passwords():
    global _cached_passwords
    if _cached_passwords is not None:
        return _cached_passwords
    try:
        with open(DATA_FILE, encoding="latin-1") as f:
            _cached_passwords = {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        _cached_passwords = set()
    return _cached_passwords


def _load_dictionary_words():
    global _cached_words, _words_warned
    if _cached_words is not None:
        return _cached_words
    try:
        from nltk.corpus import words as nltk_words
        raw = nltk_words.words()
    except LookupError:
        try:
            import nltk
            nltk.download("words", quiet=True)
            from nltk.corpus import words as nltk_words
            raw = nltk_words.words()
        except Exception:
            raw = None
    except Exception:
        raw = None
    if raw is None:
        if not _words_warned:
            print("Dictionary check skipped: install NLTK and its 'words' corpus (pip install nltk).")
            _words_warned = True
        _cached_words = set()
    else:
        _cached_words = {w for w in raw if len(w) >= 4}
    return _cached_words


def _find_dictionary_words(normalized, dict_words):
    if not dict_words or len(normalized) < 4:
        return []
    found = set()
    n = len(normalized)
    for length in range(4, n + 1):
        for i in range(n - length + 1):
            sub = normalized[i:i + length]
            if sub in dict_words:
                found.add(sub)
    return sorted(found, key=lambda w: (-len(w), w))


def score_password(password):
    score = 0
    feedback = []
    match_info = {
        "common_password": {"matched": False, "value": None, "source": None},
        "dictionary_word": {"matched": False, "words": []},
    }

    length = len(password)

    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        feedback.append("Password is too short (minimum 8 characters).")

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
    if not length > 16:
        feedback.append("Consider making your password longer than 16 characters for better security.")

    lowered = password.lower()
    normalized = normalize(password)

    common_passwords = _load_common_passwords()
    if common_passwords:
        if normalized in common_passwords:
            score -= 20
            match_info["common_password"] = {"matched": True, "value": normalized, "source": "database"}
            feedback.append(f"Password found in a database of {len(common_passwords):,} breached passwords.")
        elif lowered in common_passwords:
            score -= 20
            match_info["common_password"] = {"matched": True, "value": lowered, "source": "database"}
            feedback.append(f"Password found in a database of {len(common_passwords):,} breached passwords.")
    else:
        for pattern in COMMON_PATTERNS:
            if pattern in lowered or pattern in normalized:
                score -= 15
                match_info["common_password"] = {"matched": True, "value": pattern, "source": "hardcoded"}
                feedback.append(f"Contains common pattern: {pattern}")

    dict_words = _load_dictionary_words()
    if dict_words:
        matched_words = _find_dictionary_words(normalized, dict_words)
        if matched_words:
            top = matched_words[:3]
            score -= 10 * len(top)
            match_info["dictionary_word"] = {"matched": True, "words": top}
            feedback.append("Contains dictionary word(s): " + ", ".join(top))

    if not match_info["common_password"]["matched"] and not match_info["dictionary_word"]["matched"]:
        score += 20

    score = max(0, min(score, 100))

    return score, feedback, match_info


def main():
    print("=== Password Strength Checker ===")
    print()

    password = input("Enter password: ")

    score, feedback, match_info = score_password(password)

    print()
    print("=== RESULTS ===")
    print(f"Score: {score}/100")
    print(f"Rating: {get_rating(score)}")

    print()
    print("Feedback:")
    if feedback:
        for item in feedback:
            print(f"- {item}")
    else:
        print("- Excellent password!")

    print()
    print("Detection:")
    common = match_info["common_password"]
    if common["matched"]:
        print(f"- Breached/common password: {common['value']} (source: {common['source']})")
    else:
        print("- Breached/common password: none")
    dict_match = match_info["dictionary_word"]
    if dict_match["matched"]:
        print(f"- Dictionary word: {', '.join(dict_match['words'])}")
    else:
        print("- Dictionary word: none")


if __name__ == "__main__":
    main()
