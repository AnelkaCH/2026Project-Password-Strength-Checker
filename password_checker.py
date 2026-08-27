import math
import re
import sys
import zxcvbn
from scripts.nist_checker import main as nist_main

from scripts.core import score_password
from scripts.pw_scoring import get_rating


def main():
    if "--nist" in sys.argv:
        sys.argv = [
            arg for arg in sys.argv
            if arg != "--nist"
        ]
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

    ask_for_report = input("Do you want a compliance report? (Y/N/Whatever): ").strip().lower()

    if ask_for_report == "y":
        nist_main(password)


if __name__ == "__main__":
    main()