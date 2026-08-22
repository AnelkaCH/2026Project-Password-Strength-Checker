import math
import re
import sys
from pathlib import Path

try:
    import zxcvbn
except ImportError:
    print("Error: The 'zxcvbn' library is required to run this tool.")
    print("Please install it using: pip install zxcvbn")
    sys.exit(1)

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

def entropy_to_score(bits):
    """
    Convert guessability-derived entropy into a 0-100 score.

    < 28 bits  -> Very Weak
    < 36 bits  -> Weak
    < 60 bits  -> Moderate
    < 80 bits  -> Strong
    >= 80 bits -> Very Strong
    """

    if bits < 28:
        return int((bits / 28) * 30)

    elif bits < 36:
        return 30 + int(((bits - 28) / 8) * 20)

    elif bits < 60:
        return 50 + int(((bits - 36) / 24) * 20)

    elif bits < 80:
        return 70 + int(((bits - 60) / 20) * 20)

    else:
        return 100

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
            _cached_passwords = {
                line.strip()
                for line in f
                if line.strip()
            }

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
            print(
                "Dictionary check skipped: install NLTK and its "
                "'words' corpus (pip install nltk)."
            )
            _words_warned = True
        _cached_words = set()
    else:
        _cached_words = {
            w for w in raw
            if len(w) >= 4
        }
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
    return sorted(
        found,
        key=lambda w: (-len(w), w)
    )


def score_password(password):
    feedback = []
    zxcvbn_bits = 0.0
    zxcvbn_guesses = 0
    zxcvbn_score = 0
    zxcvbn_crack_times = {}

    if password:
        try:
            zxcvbn_res = zxcvbn.zxcvbn(password)

            zxcvbn_guesses = zxcvbn_res.get(
                "guesses",
                0
            )

            if zxcvbn_guesses > 0:
                zxcvbn_bits = math.log2(
                    zxcvbn_guesses
                )

            zxcvbn_score = zxcvbn_res.get(
                "score",
                0
            )

            zxcvbn_crack_times = zxcvbn_res.get(
                "crack_times_display",
                {}
            )

        except Exception:
            pass

    score = entropy_to_score(zxcvbn_bits)

    length = len(password)

    if length < 8:
        feedback.append(
            "Password is too short (minimum 8 characters)."
        )

    has_upper = bool(
        re.search(r"[A-Z]", password)
    )

    has_lower = bool(
        re.search(r"[a-z]", password)
    )

    has_digit = bool(
        re.search(r"\d", password)
    )

    has_symbol = bool(
        re.search(r"[^A-Za-z0-9]", password)
    )

    if not has_upper:
        feedback.append(
            "Consider adding uppercase letters."
        )

    if not has_lower:
        feedback.append(
            "Consider adding lowercase letters."
        )

    if not has_digit:
        feedback.append(
            "Consider adding numbers."
        )

    if not has_symbol:
        feedback.append(
            "Consider adding symbols."
        )

    if length <= 16:
        feedback.append(
            "Consider making your password longer than "
            "16 characters."
        )

    match_info = {
        "common_password": {
            "matched": False,
            "value": None,
            "source": None,
        },

        "dictionary_word": {
            "matched": False,
            "words": [],
        },

        "entropy": {
            "bits": zxcvbn_bits,
            "guesses": zxcvbn_guesses,
            "score": zxcvbn_score,
            "crack_times": zxcvbn_crack_times,
        },
    }

    lowered = password.lower()
    normalized = normalize(password)

    common_passwords = _load_common_passwords()

    if common_passwords:
        if normalized in common_passwords:
            match_info["common_password"] = {
                "matched": True,
                "value": normalized,
                "source": "database",
            }

            feedback.append(
                f"Password found in a database of "
                f"{len(common_passwords):,} breached passwords."
            )

        elif lowered in common_passwords:
            match_info["common_password"] = {
                "matched": True,
                "value": lowered,
                "source": "database",
            }

            feedback.append(
                f"Password found in a database of "
                f"{len(common_passwords):,} breached passwords."
            )

    dict_words = _load_dictionary_words()

    if dict_words:

        matched_words = _find_dictionary_words(
            normalized,
            dict_words
        )

        if matched_words:

            top = matched_words[:3]

            match_info["dictionary_word"] = {
                "matched": True,
                "words": top,
            }

            feedback.append(
                "Contains dictionary word(s): "
                + ", ".join(top)
            )

    score = max(
        0,
        min(score, 100)
    )

    return score, feedback, match_info


def main():
    if "--nist" in sys.argv:
        sys.argv = [
            arg for arg in sys.argv
            if arg != "--nist"
        ]
        from scripts.nist_checker import main as nist_main
        nist_main()
        return

    print("=== Password Strength Checker ===")
    print()

    password = input("Enter password: ")

    score, feedback, match_info = score_password(
        password
    )

    print()
    print("=== RESULTS ===")

    print(f"Score: {score}/100")
    print(f"Rating: {get_rating(score)}")

    print()
    print("Entropy Analysis (Guessability-Derived):")

    entropy = match_info["entropy"]

    print(
        f"- Entropy: {entropy['bits']:.1f} bits "
        f"(based on estimated "
        f"{entropy['guesses']:,} guesses)"
    )

    print(
        f"- zxcvbn Score: "
        f"{entropy['score']}/4"
    )

    print("- Crack Time Estimates:")

    crack_times = entropy["crack_times"]

    print(
        "  * Online throttling (100/hr): "
        f"{crack_times.get(
            'online_throttling_100_per_hour',
            'N/A'
        )}"
    )

    print(
        "  * Online no throttling (10/sec): "
        f"{crack_times.get(
            'online_no_throttling_10_per_second',
            'N/A'
        )}"
    )

    print(
        "  * Offline slow hashing (10k/sec): "
        f"{crack_times.get(
            'offline_slow_hashing_1e4_per_second',
            'N/A'
        )}"
    )

    print(
        "  * Offline fast hashing (10B/sec): "
        f"{crack_times.get(
            'offline_fast_hashing_1e10_per_second',
            'N/A'
        )}"
    )

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
        print(
            f"- Breached/common password: "
            f"{common['value']} "
            f"(source: {common['source']})"
        )
    else:
        print(
            "- Breached/common password: none"
        )

    dict_match = match_info["dictionary_word"]

    if dict_match["matched"]:
        print(
            "- Dictionary word: "
            + ", ".join(dict_match["words"])
        )
    else:
        print(
            "- Dictionary word: none"
        )


if __name__ == "__main__":
    main()