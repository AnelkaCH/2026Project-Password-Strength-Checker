from pathlib import Path
import sys

try:
    from nltk.corpus import words as nltk_words
    nltk_words.words()
except ImportError:
    print("Error: The 'nltk' library is required.")
    print("Please install it using: pip install nltk")
    sys.exit(1)
except LookupError:
    print("Error: The NLTK 'words' corpus is required.")
    print('Please run: python -c "import nltk; nltk.download(\'words\')"')
    sys.exit(1)

DATA_FILE = Path(__file__).parent / "data" / "common-passwords.txt"

_cached_passwords = None
_cached_words = None

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
    global _cached_words

    if _cached_words is not None:
        return _cached_words

    raw = nltk_words.words()

    _cached_words = {
        w.lower()
        for w in raw
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