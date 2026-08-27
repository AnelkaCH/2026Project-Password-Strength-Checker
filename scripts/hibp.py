import hashlib
import urllib.request
import urllib.error

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 10


class HIBPError(Exception):
    """Raised when the HIBP API call fails for any reason."""


def _hash_password(password):
    full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    return full_hash[:5], full_hash[5:]


def _query_range(prefix):
    url = HIBP_API_URL.format(prefix=prefix)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PasswordStrengthChecker/1.4"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise HIBPError(
            f"HIBP API returned HTTP {exc.code} for prefix {prefix}"
        ) from exc
    except urllib.error.URLError as exc:
        raise HIBPError(
            f"HIBP API unreachable: {exc.reason}"
        ) from exc
    except Exception as exc:
        raise HIBPError(
            f"Unexpected error querying HIBP: {exc}"
        ) from exc

def _parse_response(response_text, suffix):
    target = suffix.upper()
    for line in response_text.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip() == target:
            return int(parts[1].strip())
    return 0

def hibp_check(password):
    try:
        prefix, suffix = _hash_password(password)
        response_text = _query_range(prefix)
        count = _parse_response(response_text, suffix)
        return {"checked": True, "pwned": count > 0, "count": count, "error": None}
    except HIBPError as exc:
        return {"checked": False, "pwned": False, "count": 0, "error": str(exc)}

# For testing purposes
if __name__ == "__main__":
    for pw in ["password", "f47ac10b-58cc-4372-a567-0e02b2c3d479"]:
        result = hibp_check(pw)
        if result["checked"]:
            status = f"PWNED x{result['count']:,}" if result["pwned"] else "clean"
            print(f"{pw!r}: {status}")
        else:
            print(f"{pw!r}: check failed -- {result['error']}")