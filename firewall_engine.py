import re
from collections import Counter

# The text we replace private data with
REDACTED = "[REDACTED]"

# ---------------------------------------------------------------
# PATTERNS ("regex"): descriptions of what private data looks like
# ---------------------------------------------------------------

# Email: letters/numbers, then @, then a domain like example.com
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Credit card: 13 to 19 digits, maybe separated by spaces or dashes
CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")

# Aadhaar (Indian ID): 12 digits, first digit 2-9, often grouped 4-4-4
AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b")

# Indian mobile: optional +91, then 10 digits starting with 6, 7, 8 or 9
PHONE_IN_RE = re.compile(
    r"(?<!\w)(?:\+91[\s-]?|91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\w)"
)

# US-style phone: needs separators, like (415) 555-2671 or 415-555-2671
PHONE_US_RE = re.compile(
    r"(?<!\w)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)"
)


def luhn_valid(number: str) -> bool:
    """Real credit cards pass a math check called the Luhn algorithm.
    Random digit strings usually fail it, so this avoids false alarms."""
    digits = [int(c) for c in number if c.isdigit()]
    checksum = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2 == 1:      # every second digit from the right
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact_pii(text: str) -> tuple[str, dict]:
    """Takes raw text. Returns (cleaned text, count of what was found)."""
    findings = Counter()   # keeps a tally, like {"email": 1, "phone": 2}

    def mask(label):
        # Builds a small function that counts a match, then hides it
        def _replace(match):
            findings[label] += 1
            return REDACTED
        return _replace

    def mask_card(match):
        # Only hide it if it also passes the Luhn check
        if luhn_valid(match.group()):
            findings["credit_card"] += 1
            return REDACTED
        return match.group()   # not a real card, leave it alone

    # Order matters: long/specific patterns first, short ones last
    text = EMAIL_RE.sub(mask("email"), text)
    text = CARD_RE.sub(mask_card, text)
    text = AADHAAR_RE.sub(mask("aadhaar"), text)
    text = PHONE_IN_RE.sub(mask("phone"), text)
    text = PHONE_US_RE.sub(mask("phone"), text)

    return text, dict(findings)


# This block runs only when you run this file directly (not when imported)
if __name__ == "__main__":
    sample = (
        "Hi, I'm Priya. Email me at priya.sharma@example.com or call "
        "+91 98765 43210. My card is 4111 1111 1111 1111 and Aadhaar "
        "2345 6789 0123."
    )
    clean, found = redact_pii(sample)
    print("ORIGINAL :", sample)
    print("SANITIZED:", clean)
    print("FINDINGS :", found)

    print("\nType your own text (press Enter on an empty line to quit):")
    while True:
        user_text = input("> ")
        if not user_text.strip():
            break
        clean, found = redact_pii(user_text)
        print("SANITIZED:", clean)
        print("FINDINGS :", found)