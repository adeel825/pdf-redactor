"""
Regex-based PII detection pass.
Each pattern is a tuple: (pattern, label, replacement, value_group)
  value_group=0  → use full match as the PDF search string
  value_group=N  → use captured group N as the PDF search string
                   (used for context-prefix patterns so we search for
                    the bare value, not the "DOB: " prefix)
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class RegexMatch:
    start: int        # char offset of full match in page text (for dedup)
    end: int
    text: str         # text to search for in the PDF (may be a sub-group)
    label: str
    replacement: str


# ---------------------------------------------------------------------------
# Luhn algorithm – validates credit/debit card numbers
# ---------------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits]
    d.reverse()
    total = 0
    for i, v in enumerate(d):
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

_PATTERNS = [
    # ── SSN ─────────────────────────────────────────────────────────────────
    (r'\b(\d{3}-\d{2}-\d{4})\b',               'SSN',            '[SSN REDACTED]',        1),
    (r'\b(\d{3} \d{2} \d{4})\b',               'SSN',            '[SSN REDACTED]',        1),

    # ── EIN (Employer Identification Number)  XX-XXXXXXX ─────────────────────
    # Distinct from SSN (XXX-XX-XXXX): EIN has 2 digits, one dash, 7 digits.
    # The negative lookahead blocks the rare case where XX-XXXXXXX appears as
    # a suffix of a longer digit string (e.g. inside a credit card number).
    (r'(?<!\d)(\d{2}-\d{7})(?!\d)',            'EIN',            '[EIN REDACTED]',        1),

    # ── Email ────────────────────────────────────────────────────────────────
    (r'\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b',
                                                'EMAIL',          '[EMAIL REDACTED]',      1),

    # ── Phone ────────────────────────────────────────────────────────────────
    (r'\b((?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4})\b',
                                                'PHONE',          '[PHONE REDACTED]',      1),
    (r'\b(\+1\d{10})\b',                        'PHONE',          '[PHONE REDACTED]',      1),

    # ── Credit / debit card (Luhn validated later) ───────────────────────────
    # 4-4-4-4  (Visa / MC / Discover)
    (r'\b((?:\d{4}[-\s]){3}\d{4})\b',          'CREDIT_CARD',    '[CARD REDACTED]',       1),
    # 4-6-5  (Amex)
    (r'\b(\d{4}[-\s]\d{6}[-\s]\d{5})\b',       'CREDIT_CARD',    '[CARD REDACTED]',       1),
    # 15-16 raw digits (catch-all, Luhn validated)
    (r'(?<!\d)(\d{15,16})(?!\d)',               'CREDIT_CARD',    '[CARD REDACTED]',       1),

    # ── IP address ───────────────────────────────────────────────────────────
    (r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
     r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b',    'IP_ADDRESS',     '[IP REDACTED]',         1),

    # ── Date of birth (requires context keyword) ─────────────────────────────
    (r'(?:DOB|D\.O\.B\.?|Date\s+of\s+Birth|Birth\s*(?:date|day)|Born\s+(?:on\s+)?)'
     r'[^\d]{0,10}(\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4})',
                                                'DOB',            '[DOB REDACTED]',        1),
    (r'(?:DOB|D\.O\.B\.?|Date\s+of\s+Birth|Birth\s*(?:date|day))'
     r'[^\w]{0,10}((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*'
     r'\.?\s+\d{1,2},?\s+\d{4})',
                                                'DOB',            '[DOB REDACTED]',        1),

    # ── Driver's license (context required) ──────────────────────────────────
    (r"(?:Driver(?:'s)?[\s\-]*Licen[sc]e|(?:\bDL\b|\bD\.L\.))\s*"
     r"(?:No\.?|Num(?:ber)?|#)?\s*[:\s]*([A-Z0-9]{6,12})",
                                                'DRIVER_LICENSE', '[DL REDACTED]',         1),

    # ── Passport (context required) ───────────────────────────────────────────
    (r'(?:Passport\s*(?:No\.?|Num(?:ber)?|#)?\s*[:\s]*)([A-Z]{1,2}\d{7,9})',
                                                'PASSPORT',       '[PASSPORT REDACTED]',   1),

    # ── Bank account (context required) ──────────────────────────────────────
    (r'(?:(?:Bank\s+)?Acct(?:ount)?\s*(?:No\.?|Num(?:ber)?|#)?\s*[:\s]+)(\d{8,17})',
                                                'BANK_ACCOUNT',   '[ACCT REDACTED]',       1),

    # ── ABA routing number (context required) ────────────────────────────────
    (r'(?:(?:ABA\s+)?Routing\s*(?:No\.?|Num(?:ber)?|#)?\s*[:\s]+)([0-3]\d{8})',
                                                'ROUTING_NUMBER', '[ACCT REDACTED]',       1),

    # ── Medical record number (context required) ──────────────────────────────
    (r'(?:MRN|Medical\s+Record\s+(?:No\.?|Num(?:ber)?)|Patient\s+ID|Chart\s+(?:No\.?|Num(?:ber)?))'
     r'\s*[:\s#]*([A-Z0-9\-]{4,15})',
                                                'MRN',            '[MRN REDACTED]',        1),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_regex_pii(text: str) -> List[RegexMatch]:
    """Return all PII matches found in *text* via regex patterns."""
    matches: List[RegexMatch] = []
    seen: set = set()

    for pattern, label, replacement, vgroup in _PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            full_start, full_end = m.start(), m.end()

            # Extract the string we'll actually search for in the PDF
            try:
                search_text = m.group(vgroup).strip() if vgroup else m.group(0).strip()
            except IndexError:
                search_text = m.group(0).strip()

            if not search_text:
                continue

            # Luhn-check card numbers
            if label == 'CREDIT_CARD':
                digits = re.sub(r'\D', '', search_text)
                if len(digits) not in (15, 16) or not _luhn_ok(digits):
                    continue

            # Deduplicate by exact character range of the full match
            key = (full_start, full_end)
            if key in seen:
                continue
            seen.add(key)

            matches.append(RegexMatch(
                start=full_start,
                end=full_end,
                text=search_text,
                label=label,
                replacement=replacement,
            ))

    return matches
