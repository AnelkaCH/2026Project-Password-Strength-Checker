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

def normalize(password):
    lowered = password.lower()
    translated = lowered.translate(LEETSPEAK_TABLE)
    return re.sub(r"[^a-z0-9]", "", translated)