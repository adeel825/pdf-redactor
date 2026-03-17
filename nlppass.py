"""
NLP-based PII detection using Microsoft Presidio + spaCy en_core_web_lg.
Also runs a usaddress pass for US street addresses.

The AnalyzerEngine is initialised ONCE at module import time (~560 MB).
"""

import re
import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data class shared with the rest of the pipeline
# ---------------------------------------------------------------------------

@dataclass
class NLPMatch:
    start: int
    end: int
    text: str
    label: str
    replacement: str
    score: float


# ---------------------------------------------------------------------------
# Entity → replacement label mapping
# None means "skip this entity type"
# ---------------------------------------------------------------------------

ENTITY_REPLACEMENTS = {
    'PERSON':             '[NAME REDACTED]',
    'LOCATION':           '[ADDRESS REDACTED]',
    'EMAIL_ADDRESS':      '[EMAIL REDACTED]',
    'PHONE_NUMBER':       '[PHONE REDACTED]',
    'CREDIT_CARD':        '[CARD REDACTED]',
    'US_SSN':             '[SSN REDACTED]',
    'IP_ADDRESS':         '[IP REDACTED]',
    'US_DRIVER_LICENSE':  '[DL REDACTED]',
    'US_PASSPORT':        '[PASSPORT REDACTED]',
    'US_BANK_NUMBER':     '[ACCT REDACTED]',
    'MEDICAL_LICENSE':    '[MRN REDACTED]',
    'US_ITIN':            '[SSN REDACTED]',
    'NRP':                '[NAME REDACTED]',
    # Types we intentionally skip
    'DATE_TIME':          None,   # too many false positives without context
    'URL':                None,
    'ORG':                None,
    'GPE':                None,
    'CRYPTO':             None,
    'IBAN_CODE':          '[ACCT REDACTED]',
}

_WANTED = [k for k, v in ENTITY_REPLACEMENTS.items() if v is not None]


# ---------------------------------------------------------------------------
# Presidio initialisation (module-level — runs once at startup)
# ---------------------------------------------------------------------------

analyzer: Optional[object] = None
NLP_AVAILABLE = False

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider, NerModelConfiguration

    _ner_model_config = NerModelConfiguration(
        labels_to_ignore=[
            "CARDINAL",
            "ORDINAL",
            "MONEY",
            "QUANTITY",
            "PERCENT",
            "TIME",
            "WORK_OF_ART",
            "LANGUAGE",
            "FAC",
            "NORP",
        ]
    )

    _nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{
            "lang_code": "en",
            "model_name": "en_core_web_lg",
            "ner_model_configuration": _ner_model_config,
        }],
    }
    _provider = NlpEngineProvider(nlp_configuration=_nlp_config)
    _nlp_engine = _provider.create_engine()
    analyzer = AnalyzerEngine(
        nlp_engine=_nlp_engine,
        supported_languages=["en"],
    )
    NLP_AVAILABLE = True
    logger.info("Presidio AnalyzerEngine loaded with en_core_web_lg")
except Exception as exc:
    logger.warning(
        "Presidio/spaCy failed to load — NLP pass disabled.\n"
        "  Run: python -m spacy download en_core_web_lg\n"
        f"  Error: {exc}"
    )


# ---------------------------------------------------------------------------
# usaddress helper
# ---------------------------------------------------------------------------

try:
    import usaddress as _usaddress
    _USADDRESS_AVAILABLE = True
except ImportError:
    _USADDRESS_AVAILABLE = False
    logger.warning("usaddress not installed — address regex pass disabled")

# A loose pattern that catches house-number + street combos
_ADDR_RE = re.compile(
    r'\b(\d{1,5}\s+[A-Za-z][A-Za-z0-9\s]{3,40}'
    r'(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct'
    r'|Boulevard|Blvd|Way|Place|Pl|Circle|Cir|Terrace|Terr?|Trail|Trl)'
    r'\.?(?:[,\s]+[A-Za-z\s]{2,30})?(?:[,\s]+[A-Z]{2})?'
    r'(?:[,\s]+\d{5}(?:-\d{4})?)?)\b',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Form-label name heuristic
# ---------------------------------------------------------------------------

# Matches "(1) First name" / "(2) Last name" table row labels followed
# immediately by 1-4 all-caps words on the same line (no newline allowed).
# This is the exact structure of the IRS 1040 dependents table and many
# other government/financial forms.
_FORM_LABEL_NAME_RE = re.compile(
    r'\(\d+\)\s+(?i:(?:first|last)\s+name)\s+'
    r'([A-Z]{2,}(?:[ \t]+[A-Z]{2,}){0,3})'
)


def _find_form_label_names(text: str) -> List[NLPMatch]:
    """Catch names that immediately follow '(N) First/Last name' form labels.

    Returns one NLPMatch per row label hit.  The reconciler's token search
    then looks up each individual token (ALINA, AMIRAH, ASAD) in the PDF.
    """
    results = []
    for m in _FORM_LABEL_NAME_RE.finditer(text):
        logger.debug("[NLP] form-label name: %r", m.group(1))
        results.append(NLPMatch(
            start=m.start(1),
            end=m.end(1),
            text=m.group(1),
            label='PERSON',
            replacement='[NAME REDACTED]',
            score=0.85,
        ))
    return results


# ---------------------------------------------------------------------------
# All-caps sequence heuristic  (safety net for spaCy gaps)
# ---------------------------------------------------------------------------

# Matches 2-3 consecutive ALL-CAPS words of 3+ chars each.
_CAPS_NAME_SEQ_RE = re.compile(r'\b([A-Z]{3,}(?:[ \t]+[A-Z]{3,}){1,2})\b')

# Sequences where EVERY word is in this blocklist are skipped — they are
# form labels, legal boilerplate, or common abbreviations, not names.
_CAPS_NONNAME: frozenset = frozenset({
    'IRS', 'USA', 'OMB', 'EIN', 'SSN', 'TIN', 'AGI', 'PTIN', 'ITIN',
    'INC', 'LLC', 'LLP', 'LTD', 'CORP', 'SEC', 'FBI', 'CIA', 'DOD',
    'TAX', 'FORM', 'YEAR', 'PAGE', 'LINE', 'PART', 'ITEM', 'CODE',
    'TOTAL', 'AMOUNT', 'INCOME', 'WAGES', 'RETURN', 'FILING', 'STATUS',
    'INDIVIDUAL', 'JOINT', 'MARRIED', 'SINGLE', 'FEDERAL', 'STATE',
    'LOCAL', 'TREASURY', 'REVENUE', 'SERVICE', 'INTERNAL', 'DEPARTMENT',
    'SOCIAL', 'SECURITY', 'MEDICARE', 'TAXABLE', 'ADJUSTED', 'GROSS',
    'SCHEDULE', 'PAYMENT', 'MAIL', 'ONLY', 'USE', 'NOT', 'FOR', 'YES',
    'NO', 'DATE', 'SIGN', 'HERE', 'SIGNATURE', 'TITLE', 'PRINT', 'NAME',
    'NAMES', 'ADDRESS', 'CITY', 'ZIP', 'PHONE', 'EMAIL', 'NUMBER',
    'ACCOUNT', 'ROUTING', 'BANK', 'CREDIT', 'DEBIT', 'ENTER', 'CHECK',
    'DIGITAL', 'ASSETS', 'PROPERTY', 'FIRST', 'LAST', 'MIDDLE',
    'NORTH', 'SOUTH', 'EAST', 'WEST', 'NEW', 'YORK', 'LOS', 'SAN',
    'STREET', 'AVENUE', 'ROAD', 'DRIVE', 'SUITE', 'FLOOR',
    'ALIMONY', 'PENSION', 'ANNUITY', 'CAPITAL', 'GAINS', 'LOSS',
    'REPORTED', 'WITHHELD', 'ELECTION', 'CAMPAIGN', 'PRESIDENTIAL',
    'AUTHORIZATION', 'ELECTRONIC', 'INDIVIDUALS', 'DEPENDENTS',
    'AND', 'OR', 'OF', 'IN', 'TO', 'THE',
})


def _find_caps_name_sequences(text: str) -> List[NLPMatch]:
    """Catch 2-3 consecutive ALL-CAPS words as PERSON candidates.

    Acts as a safety net for names spaCy misses due to low confidence or
    lack of surrounding sentence context (common on tax / legal forms).
    Sequences where every word is in the non-name blocklist are skipped.
    """
    results = []
    for m in _CAPS_NAME_SEQ_RE.finditer(text):
        words = m.group(1).split()
        if all(w in _CAPS_NONNAME for w in words):
            continue
        logger.debug("[NLP] caps-seq name candidate: %r", m.group(1))
        results.append(NLPMatch(
            start=m.start(1),
            end=m.end(1),
            text=m.group(1),
            label='PERSON',
            replacement='[NAME REDACTED]',
            score=0.7,
        ))
    return results


def _find_addresses(text: str) -> List[NLPMatch]:
    if not _USADDRESS_AVAILABLE:
        return []
    results = []
    for m in _ADDR_RE.finditer(text):
        candidate = m.group(1)
        try:
            _, addr_type = _usaddress.tag(candidate)
            if addr_type in ('Street Address', 'Ambiguous'):
                results.append(NLPMatch(
                    start=m.start(1),
                    end=m.end(1),
                    text=candidate,
                    label='ADDRESS',
                    replacement='[ADDRESS REDACTED]',
                    score=0.85,
                ))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _title_case_caps(text: str) -> str:
    """
    Title-case runs of ALL-CAPS words so spaCy's NER model recognises them.

    spaCy is trained on mixed-case corpora and regularly misses names written
    in ALL CAPS (e.g. form headers, legal documents).  Title-casing only the
    all-caps tokens — leaving already-mixed-case text untouched — gives the
    model its best chance without corrupting other tokens (abbreviations, etc.
    that are a single uppercase word are left alone).

    Character offsets are preserved because we only change case, never insert
    or delete characters, so spans from the normalised string map directly back
    to the original.
    """
    return re.sub(
        r'\b([A-Z]{2,})\b',
        lambda m: m.group(1).capitalize(),
        text,
    )


def _presidio_pass(
    analysis_text: str,
    original_text: str,
    min_score: float,
    seen_spans: set,
    label: str,
) -> List[NLPMatch]:
    """Run one Presidio analysis pass and return new NLPMatch objects.

    *analysis_text* is fed to Presidio; *original_text* is used to recover
    the actual characters at each span (important when analysis_text has been
    normalised).  *seen_spans* is updated in-place to deduplicate across
    multiple passes.  *label* is a short string used only for debug output.
    """
    if analyzer is None:
        return []

    presidio_results = analyzer.analyze(
        text=analysis_text,
        language="en",
        entities=_WANTED,
        score_threshold=min_score,
    )
    logger.debug("[NLP] %s pass — Presidio returned %d result(s)", label, len(presidio_results))

    hits: List[NLPMatch] = []
    for r in presidio_results:
        span_key = (r.start, r.end)
        span_text = original_text[r.start:r.end]   # always the original casing
        replacement = ENTITY_REPLACEMENTS.get(r.entity_type)
        logger.debug(
            "[NLP]   [%s] entity=%-20s score=%.2f span=[%d:%d] text=%r -> replacement=%r",
            label, r.entity_type, r.score, r.start, r.end, span_text, replacement,
        )
        if not replacement:
            logger.debug("[NLP]   ^ skipped (no replacement mapping)")
            continue
        if span_key in seen_spans:
            logger.debug("[NLP]   ^ skipped (duplicate span from earlier pass)")
            continue
        seen_spans.add(span_key)
        hits.append(NLPMatch(
            start=r.start,
            end=r.end,
            text=span_text,
            label=r.entity_type,
            replacement=replacement,
            score=r.score,
        ))
    return hits


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_nlp_pii(text: str, min_score: float = 0.6) -> List[NLPMatch]:
    """Return NLP + address matches found in *text*.

    Runs two Presidio passes:
    1. Original text — catches correctly-cased names.
    2. Title-cased copy — catches ALL-CAPS names that spaCy's model misses
       (common in forms, headers, and legal documents).
    Both passes share the same character offsets so results are directly
    comparable and deduplication is exact.
    """
    results: List[NLPMatch] = []

    if NLP_AVAILABLE and analyzer is not None:
        logger.debug("[NLP] Analyzing %d chars (min_score=%.2f)", len(text), min_score)
        seen_spans: set = set()

        # Pass 1: original text
        results.extend(_presidio_pass(text, text, min_score, seen_spans, "original"))

        # Pass 2: title-case normalised — only run if the text actually contains
        # all-caps runs (avoids a redundant second Presidio call otherwise)
        normalised = _title_case_caps(text)
        if normalised != text:
            logger.debug("[NLP] All-caps tokens detected — running title-case pass")
            results.extend(_presidio_pass(normalised, text, min_score, seen_spans, "title-cased"))
        else:
            logger.debug("[NLP] No all-caps tokens — skipping title-case pass")

    results.extend(_find_form_label_names(text))
    results.extend(_find_caps_name_sequences(text))
    results.extend(_find_addresses(text))
    return results
