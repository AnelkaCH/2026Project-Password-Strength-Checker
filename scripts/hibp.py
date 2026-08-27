import hashlib


def _hash_password(password):
    full_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    return full_hash[:5], full_hash[5:]

prefix, suffix = _hash_password("password123")

print(prefix)
print(suffix)