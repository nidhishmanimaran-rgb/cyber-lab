from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re


SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
DKLEN = 32


def strength_feedback(password: str) -> dict:
    score = 0
    notes: list[str] = []
    if len(password) >= 12:
        score += 30
    else:
        notes.append("Use at least 12 characters.")
    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 20
    else:
        notes.append("Mix upper and lower case characters.")
    if re.search(r"\d", password):
        score += 15
    else:
        notes.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 20
    else:
        notes.append("Add symbols.")
    if len(set(password)) >= 8:
        score += 15
    else:
        notes.append("Avoid repeated characters.")
    label = "strong" if score >= 75 else "reasonable" if score >= 50 else "weak"
    return {"score": min(score, 100), "label": label, "notes": notes}


def generate_verifier(password: str) -> dict:
    if not password:
        raise ValueError("Password is required.")
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=DKLEN,
    )
    verifier = "scrypt${n}${r}${p}${salt}${digest}".format(
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        salt=base64.b64encode(salt).decode("ascii"),
        digest=base64.b64encode(digest).decode("ascii"),
    )
    return {
        "algorithm": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": verifier,
        "strength": strength_feedback(password),
        "education": "Hashing stores a one-way verifier. Encryption is reversible with a key. Plaintext password storage is unsafe.",
    }


def verify_password(password: str, verifier: str) -> dict:
    try:
        algorithm, raw_n, raw_r, raw_p, raw_salt, raw_digest = verifier.split("$", 5)
        if algorithm != "scrypt":
            raise ValueError
        salt = base64.b64decode(raw_salt.encode("ascii"))
        expected = base64.b64decode(raw_digest.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(raw_n),
            r=int(raw_r),
            p=int(raw_p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        raise ValueError("Invalid verifier format.") from None
    return {"valid": hmac.compare_digest(actual, expected), "algorithm": "scrypt"}
