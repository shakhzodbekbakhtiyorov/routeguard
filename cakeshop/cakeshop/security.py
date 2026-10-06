import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def check_password(stored_hash, password):
    return hash_password(password) == stored_hash
