"""
PyMuPDF redaction engine.

Uses add_redact_annot() + apply_redactions() for TRUE content removal —
bytes are permanently stripped, not visually overlaid.
"""

import logging
from typing import List, Dict, Callable, Optional

import fitz  # PyMuPDF

from reconciler import RedactionTarget

logger = logging.getLogger(__name__)


def apply_redactions(
    doc: fitz.Document,
    targets_by_page: Dict[int, List[RedactionTarget]],
    progress_callback: Optional[Callable[[str, int], None]] = None,
) -> Dict[str, int]:
    """
    Stamp redaction annotations on every target rect, then permanently
    apply them page by page.

    Returns a dict mapping label → count of individual redactions applied.
    """
    stats: Dict[str, int] = {}
    total_pages = doc.page_count

    for page_num in range(total_pages):
        page = doc[page_num]
        targets = targets_by_page.get(page_num, [])

        logger.debug("[Redactor] Page %d — %d target(s)", page_num, len(targets))

        for target in targets:
            logger.debug(
                "[Redactor]   [%s] %r — %d rect(s), replacement=%r",
                target.label, target.text, len(target.rects), target.replacement,
            )
            for rect in target.rects:
                # Inflate rect slightly so the fill covers any glyph descenders
                inflated = rect + (-1, -1, 1, 1)
                logger.debug("[Redactor]     add_redact_annot rect=%s", inflated)
                page.add_redact_annot(
                    quad=inflated,
                    text=target.replacement,
                    fontname="helv",
                    fontsize=7,
                    align=fitz.TEXT_ALIGN_LEFT,
                    fill=(0, 0, 0),       # black fill
                    text_color=(1, 1, 1), # white replacement label
                    cross_out=False,
                )
                stats[target.label] = stats.get(target.label, 0) + 1

        if targets:
            # images=PDF_REDACT_IMAGE_NONE  →  don't alter embedded images
            # graphics=PDF_REDACT_LINE_ART_NONE  →  keep vector art
            try:
                page.apply_redactions(
                    images=fitz.PDF_REDACT_IMAGE_NONE,
                    graphics=fitz.PDF_REDACT_LINE_ART_NONE,
                )
            except TypeError:
                # Older PyMuPDF versions don't accept keyword arguments
                page.apply_redactions()

        if progress_callback:
            pct = int((page_num + 1) / total_pages * 100)
            progress_callback("Writing PDF", pct)

    return stats
