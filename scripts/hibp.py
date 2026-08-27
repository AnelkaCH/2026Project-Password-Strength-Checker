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


# testing
prefix, suffix = _hash_password("password")
print("Prefix:", prefix)
print("Suffix:", suffix)

try:
    result = _query_range(prefix)
    print("API request successful!")
    print("Response length:", len(result))
except HIBPError as e:
    print("API error:", e)
    result = None

FAKE_RESPONSE = """AABBCC:3\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10000000\nDDEEFF:1"""
count = _parse_response(FAKE_RESPONSE, suffix)
print("Parse test (expect 10000000):", count)

if result:
    live_count = _parse_response(result, suffix)
    print("Live breach count for 'password':", live_count)