"""
Merge regex + NLP matches, deduplicate overlapping spans, then map each
matched string to its bounding rectangles on the PDF page via
fitz.Page.search_for().
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Set

import fitz  # PyMuPDF

logger = logging.getLogger(__name__)

# Entity labels that represent person names — eligible for token-level search
_PERSON_LABELS: Set[str] = {'PERSON', 'NRP'}


@dataclass
class RedactionTarget:
    text: str
    label: str
    replacement: str
    rects: List[fitz.Rect]
    page_num: int


# ---------------------------------------------------------------------------
# Rect helpers
# ---------------------------------------------------------------------------

def _dedup_rects(rects: list) -> list:
    """Drop rects that are within 1 pt of an already-kept rect.

    When we search for the same text in multiple case variants, PyMuPDF
    returns identical coordinates each time.  This removes those duplicates
    before we pass the list to add_redact_annot().
    """
    kept = []
    for r in rects:
        if not any(
            abs(r.x0 - k.x0) < 1 and abs(r.y0 - k.y0) < 1 and
            abs(r.x1 - k.x1) < 1 and abs(r.y1 - k.y1) < 1
            for k in kept
        ):
            kept.append(r)
    return kept


def _search_all_variants(page: fitz.Page, text: str) -> list:
    """Search for *text* in all four case variants and return deduplicated rects.

    Tries: original, UPPERCASE, lowercase, Title Case.
    Using a set of variants avoids redundant calls when the text is already
    all-caps or all-lowercase.
    """
    all_rects = []
    for variant in {text, text.upper(), text.lower(), text.title()}:
        all_rects.extend(page.search_for(variant, quads=False))
    return _dedup_rects(all_rects)


# ---------------------------------------------------------------------------
# Span deduplication
# ---------------------------------------------------------------------------

def _dedup(matches: list) -> list:
    """
    Sort matches by start position (ties broken by longer span first).
    Walk forward and drop any match whose span overlaps the previous winner.
    """
    if not matches:
        return []
    ordered = sorted(matches, key=lambda m: (m.start, -(m.end - m.start)))
    kept = [ordered[0]]
    for m in ordered[1:]:
        if m.start < kept[-1].end:  # overlaps → skip
            continue
        kept.append(m)
    return kept


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def reconcile_and_map(
    page: fitz.Page,
    regex_matches: list,
    nlp_matches: list,
    page_num: int,
) -> List[RedactionTarget]:
    """
    Combine regex + NLP hits, remove overlaps, then locate each matched
    string inside *page* using PyMuPDF's search_for().
    Returns a list of RedactionTarget objects ready for the redactor.
    """
    logger.debug(
        "[Reconciler] Page %d — %d regex match(es), %d NLP match(es)",
        page_num, len(regex_matches), len(nlp_matches),
    )

    all_matches = list(regex_matches) + list(nlp_matches)
    deduped = _dedup(all_matches)

    logger.debug(
        "[Reconciler] Page %d — %d match(es) after dedup",
        page_num, len(deduped),
    )

    targets: List[RedactionTarget] = []
    seen_texts: set = set()

    for match in deduped:
        search_text = match.text.strip()
        if not search_text or search_text in seen_texts:
            logger.debug(
                "[Reconciler]   [%s] %r — skipped (empty or duplicate search text)",
                match.label, search_text,
            )
            continue
        seen_texts.add(search_text)

        # Search in all four case variants; deduplicate overlapping rects
        rects = _search_all_variants(page, search_text)

        if rects:
            logger.debug(
                "[Reconciler]   [%s] %r — found %d rect(s) on page %d",
                match.label, search_text, len(rects), page_num,
            )
            targets.append(RedactionTarget(
                text=search_text,
                label=match.label,
                replacement=match.replacement,
                rects=rects,
                page_num=page_num,
            ))
        else:
            logger.debug(
                "[Reconciler]   [%s] %r — NOT FOUND in any case variant",
                match.label, search_text,
            )

        # ── Token-level search for person names ──────────────────────────
        # Tax forms often split first/last name into separate fields, so the
        # full "Adeel Khan" string never appears together in the PDF.  Search
        # for each whitespace-delimited token individually; skip tokens under
        # 3 characters to avoid false positives on common short words.
        if match.label in _PERSON_LABELS:
            tokens = search_text.split()
            if len(tokens) > 1:
                for token in tokens:
                    if len(token) < 3 or token in seen_texts:
                        continue
                    seen_texts.add(token)
                    token_rects = _search_all_variants(page, token)
                    if token_rects:
                        logger.debug(
                            "[Reconciler]   [%s] token %r — found %d rect(s) on page %d",
                            match.label, token, len(token_rects), page_num,
                        )
                        targets.append(RedactionTarget(
                            text=token,
                            label=match.label,
                            replacement=match.replacement,
                            rects=token_rects,
                            page_num=page_num,
                        ))
                    else:
                        logger.debug(
                            "[Reconciler]   [%s] token %r — NOT FOUND in any case variant",
                            match.label, token,
                        )

    logger.debug(
        "[Reconciler] Page %d — %d redaction target(s) mapped to PDF coordinates",
        page_num, len(targets),
    )
    return targets
