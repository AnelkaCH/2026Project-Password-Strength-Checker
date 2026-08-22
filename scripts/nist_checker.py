import argparse
import json
import sys
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import password_checker

STANDARD = "NIST SP 800-63B"
SECTION = "5.1.1.2 Memorized Secret Verifiers"
MIN_LENGTH = 8
SUGGESTED_MAX = 64


def _non_printable_chars(password):
    bad = []
    for ch in password:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cs"):
            bad.append(repr(ch))
    return bad


def _context_hit(password, tokens):
    lowered = password.lower()
    for token in tokens:
        token_lower = token.lower()
        if token_lower and token_lower in lowered:
            return token
    return None


def check_nist_compliance(password, match_info, username=None, service=None):
    length = len(password)
    items = []

    min_status = "pass" if length >= MIN_LENGTH else "fail"
    items.append({
        "id": 1,
        "control": "Minimum length of 8 characters",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": min_status,
        "detail": (
            f"Length is {length} character(s); each Unicode code point "
            "counts as one character."
        ),
    })

    trunc_detail = "The full secret is verified; truncation is never applied."
    if length > SUGGESTED_MAX:
        trunc_detail += (
            f" Length exceeds {SUGGESTED_MAX} and is still accepted in full "
            "per 'Truncation of the secret SHALL NOT be performed'."
        )
    items.append({
        "id": 2,
        "control": "Full secret verified; 64+ characters supported",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHOULD",
        "status": "pass",
        "detail": trunc_detail,
    })

    items.append({
        "id": 3,
        "control": "No mandatory composition rules",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": "pass",
        "detail": (
            "Not enforced by this verifier. Character-class feedback is "
            "guidance only and is never a basis for rejection."
        ),
    })

    items.append({
        "id": 4,
        "control": "No periodic rotation required",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": "pass",
        "detail": "Not enforced by this verifier.",
    })

    common = match_info.get("common_password", {})
    breach_available = bool(password_checker._load_common_passwords())
    if not breach_available:
        breach_status = "na"
        breach_detail = "Common/breach list not available (data file missing)."
    elif common.get("matched"):
        breach_status = "fail"
        breach_detail = (
            f"Password matched '{common.get('value')}' on the "
            "commonly-used/compromised list."
        )
    else:
        breach_status = "pass"
        breach_detail = "No match on the commonly-used/compromised list."
    items.append({
        "id": 5,
        "control": "Not on a commonly-used or breached-password list",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": breach_status,
        "detail": breach_detail,
    })

    dict_available = bool(password_checker._load_dictionary_words())
    dict_match = match_info.get("dictionary_word", {})
    if not dict_available:
        dict_status = "na"
        dict_detail = "Dictionary corpus not available (install NLTK 'words')."
    elif dict_match.get("matched"):
        dict_status = "fail"
        dict_detail = (
            "Contains dictionary word(s): "
            + ", ".join(dict_match.get("words", []))
        )
    else:
        dict_status = "pass"
        dict_detail = "No dictionary words detected."
    items.append({
        "id": 6,
        "control": "Not a dictionary word",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": dict_status,
        "detail": dict_detail,
    })

    context_tokens = []
    if username:
        context_tokens.append(username)
    if service:
        context_tokens.append(service)

    if not context_tokens:
        ctx_status = "na"
        ctx_detail = (
            "No username or service provided; context-specific words "
            "not assessed."
        )
    else:
        ctx_hit = _context_hit(password, context_tokens)
        if ctx_hit:
            ctx_status = "fail"
            ctx_detail = f"Contains context-specific word '{ctx_hit}'."
        else:
            ctx_status = "pass"
            ctx_detail = (
                "No context-specific words (username/service) detected."
            )
    items.append({
        "id": 7,
        "control": "Not a context-specific word (service/username)",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": ctx_status,
        "detail": ctx_detail,
    })

    bad_chars = _non_printable_chars(password)
    if bad_chars:
        print_status = "fail"
        print_detail = (
            "Contains non-printable character(s): "
            + ", ".join(bad_chars)
        )
    else:
        print_status = "pass"
        print_detail = (
            "All characters are printable ASCII or printable Unicode "
            "(emoji allowed)."
        )
    items.append({
        "id": 8,
        "control": "Printable ASCII, space, Unicode and emoji allowed",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHOULD",
        "status": print_status,
        "detail": print_detail,
    })

    items.append({
        "id": 9,
        "control": "No password hints or knowledge-based prompts",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHALL",
        "status": "pass",
        "detail": (
            "Not enforced by this verifier; it stores no hints and prompts "
            "for no knowledge-based information."
        ),
    })

    entropy = match_info.get("entropy", {})
    bits = entropy.get("bits", 0.0)
    items.append({
        "id": 10,
        "control": "Strength-meter screening guidance",
        "clause": "SP 800-63B 5.1.1.2",
        "level": "SHOULD",
        "status": "info",
        "detail": (
            f"zxcvbn entropy estimate is {bits:.1f} bits. The strength meter "
            "is a screening tool per 5.1.1.2, not a rejection rule."
        ),
    })

    failed = [it for it in items if it["status"] == "fail"]
    verdict = "non-compliant" if failed else "compliant"

    summary = {
        "total": len(items),
        "passed": sum(1 for it in items if it["status"] == "pass"),
        "failed": len(failed),
        "not_assessed": sum(1 for it in items if it["status"] == "na"),
        "informational": sum(1 for it in items if it["status"] == "info"),
    }

    return {
        "standard": STANDARD,
        "section": SECTION,
        "verdict": verdict,
        "items": items,
        "summary": summary,
    }


def _print_report(report):
    print(f"{report['standard']} Compliance Report")
    print(f"Section {report['section']}")
    print()
    print(f"Verdict: {report['verdict'].upper()}")
    print()
    print("Control matrix:")

    for item in report["items"]:
        status = item["status"].upper()
        if status == "NA":
            status = "N/A"
        print(
            f"[{item['id']:02d}] {item['level']:<6} {status:<5} "
            f"{item['control']}"
        )
        if item["status"] in ("fail", "na", "info"):
            print(f"      {item['clause']}: {item['detail']}")

    print()
    summary = report["summary"]
    print(
        f"Summary: {summary['passed']} passed, {summary['failed']} failed, "
        f"{summary['not_assessed']} not assessed, "
        f"{summary['informational']} informational"
    )


def main():
    parser = argparse.ArgumentParser(
        description="NIST SP 800-63B compliance checker"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report as JSON",
    )
    parser.add_argument(
        "--username",
        help="Account username for the context-specific word check",
    )
    parser.add_argument(
        "--service",
        help="Service name for the context-specific word check",
    )
    args = parser.parse_args()

    password = input("Enter password: ")

    _, _, match_info = password_checker.score_password(password)
    report = check_nist_compliance(
        password,
        match_info,
        args.username,
        args.service,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)


if __name__ == "__main__":
    main()
