import re

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

SYMBOL_TABLE = str.maketrans({
    "@": "a",
    "$": "s",
})

def normalize(password):
    lowered = password.lower()
    translated = lowered.translate(LEETSPEAK_TABLE)
    return re.sub(r"[^a-z0-9]", "", translated)

# Keeps digits intact so "P@ssword1" maps to "password1"
def normalize_symbols(password):
    lowered = password.lower()
    translated = lowered.translate(SYMBOL_TABLE)
    return re.sub(r"[^a-z0-9]", "", translated)