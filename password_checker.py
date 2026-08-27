import math
import re
import sys
import zxcvbn

from scripts.hibp import hibp_check
from scripts.common_pw_and_dict import _load_common_passwords, _load_dictionary_words, _find_dictionary_words
from scripts.pw_normalizer import normalize
from scripts.pw_scoring import entropy_to_score, get_rating

def score_password(password):
    feedback = []
    zxcvbn_bits = 0.0
    zxcvbn_guesses = 0
    zxcvbn_score = 0
    zxcvbn_crack_times = {}
    zxcvbn_failed = False

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
            zxcvbn_failed = True

    score = entropy_to_score(zxcvbn_score)

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

    if zxcvbn_failed:
        feedback.append(
            "Entropy analysis failed; strength score may be inaccurate."
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
            "failed": zxcvbn_failed,
        },

        "hibp": {
            "checked": False,
            "pwned": False,
            "count": 0,
            "error": None,
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

    hibp_result = hibp_check(password)
    match_info["hibp"] = hibp_result

    if not hibp_result["checked"]:
        feedback.append(
            f"HaveIBeenPwned check failed: {hibp_result['error']}. "
            "Do not treat this as confirmation the password is safe."
        )
    elif hibp_result["pwned"]:
        feedback.append(
            f"Password found in {hibp_result['count']:,} known data breach(es) "
            "(HaveIBeenPwned). Do not use this password."
        )
        score = min(score, 20)

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

    hibp = match_info["hibp"]

    if not hibp["checked"]:
        print(f"- HaveIBeenPwned: check failed ({hibp['error']})")
    elif hibp["pwned"]:
        print(f"- HaveIBeenPwned: found in {hibp['count']:,} breach(es)")
    else:
        print("- HaveIBeenPwned: not found in any known breach")


if __name__ == "__main__":
    main()