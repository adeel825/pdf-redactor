"""
Flask server for the local PDF PII redaction tool.
All processing is offline — zero network calls.
"""

import os
import uuid
import json
import threading
import traceback
import time
import logging
from pathlib import Path

from flask import Flask, request, jsonify, send_file, Response, render_template

# ---------------------------------------------------------------------------
# Directories (created at startup)
# ---------------------------------------------------------------------------

BASE_DIR    = Path(__file__).parent
UPLOAD_DIR  = BASE_DIR / "uploads"
OUTPUT_DIR  = BASE_DIR / "outputs"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Enable DEBUG for the three pipeline modules so every stage of the
# name-detection path is visible in the console.
for _mod in ("nlppass", "reconciler", "redactor"):
    logging.getLogger(_mod).setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------

def _line_grouped_text(page) -> str:
    """Reconstruct page text by grouping words that share the same Y coordinate.

    Standard get_text() emits text in content-stream order, which on structured
    forms (e.g. IRS 1040) often places first-name and last-name tokens far apart
    because each lives in its own form field.  This function sorts every word on
    the page by (row, left-to-right) and joins words within Y_TOL points of each
    other into a single line, so "ADEEL" and "KHAN" appear adjacent and spaCy
    can recognise the full name as a PERSON entity.
    """
    words = page.get_text("words")   # (x0,y0,x1,y1,word,block,line,word_no)
    if not words:
        return ""

    Y_TOL = 4  # points — within this vertical distance = same line

    # Bucket into rows: key = Y rounded to nearest Y_TOL
    rows: dict = {}
    for w in words:
        y_key = round(w[1] / Y_TOL)
        rows.setdefault(y_key, []).append(w)

    lines = []
    for y_key in sorted(rows):
        row_words = sorted(rows[y_key], key=lambda w: w[0])  # sort left→right
        lines.append(" ".join(w[4] for w in row_words))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# In-memory job store  { job_id: { status, stage, progress, stats, ... } }
# ---------------------------------------------------------------------------

_jobs: dict = {}
_jobs_lock = threading.Lock()


def _job_update(job_id: str, **kwargs):
    with _jobs_lock:
        _jobs[job_id].update(kwargs)


def _job_get(job_id: str) -> dict:
    with _jobs_lock:
        return dict(_jobs.get(job_id, {}))


# ---------------------------------------------------------------------------
# Pipeline worker (runs in a background daemon thread)
# ---------------------------------------------------------------------------

def _run_pipeline(job_id: str, input_path: str, output_path: str):
    try:
        import fitz
        from regexpass import find_regex_pii
        from nlppass import find_nlp_pii
        from reconciler import reconcile_and_map
        from redactor import apply_redactions

        _job_update(job_id, status="processing", stage="Opening PDF", progress=2)

        doc = fitz.open(input_path)

        if doc.needs_pass:
            _job_update(job_id, status="error",
                        error="PDF is encrypted. Please decrypt it before uploading.")
            return

        if doc.page_count == 0:
            _job_update(job_id, status="error",
                        error="PDF has no pages.")
            return

        total_pages = doc.page_count
        targets_by_page: dict = {}
        all_stats: dict = {}

        for page_num in range(total_pages):
            page = doc[page_num]

            # ── Stage 1: extract text ──────────────────────────────────────
            base_pct = int(page_num / total_pages * 80)
            page_span = int(1 / total_pages * 80)

            _job_update(job_id, stage="Extracting text",
                        progress=max(2, base_pct))
            page_text = page.get_text()
            line_text = _line_grouped_text(page)

            # ── Stage 2: regex pass ────────────────────────────────────────
            _job_update(job_id, stage="Regex pass",
                        progress=max(2, base_pct + page_span // 3))
            regex_hits = find_regex_pii(page_text)

            # ── Stage 3: NLP pass ──────────────────────────────────────────
            # Run on the standard text first, then on the line-grouped text.
            # Line-grouped text reconstructs each visual row left-to-right so
            # that split-field names (e.g. first name | last name on a 1040)
            # appear adjacent and spaCy recognises the full PERSON entity.
            # reconcile_and_map()'s seen_texts set deduplicates any overlap.
            _job_update(job_id, stage="NLP pass",
                        progress=max(2, base_pct + 2 * page_span // 3))
            nlp_hits = find_nlp_pii(page_text)
            if line_text != page_text:
                nlp_hits = nlp_hits + find_nlp_pii(line_text)

            # ── Stage 4: reconcile & map to coordinates ────────────────────
            _job_update(job_id, stage="Reconciling",
                        progress=max(2, base_pct + page_span - 1))
            targets = reconcile_and_map(page, regex_hits, nlp_hits, page_num)
            targets_by_page[page_num] = targets

            for t in targets:
                all_stats[t.label] = all_stats.get(t.label, 0) + 1

        # ── Stage 5: write redacted PDF ────────────────────────────────────
        _job_update(job_id, stage="Writing PDF", progress=82)

        def _progress_cb(stage: str, pct: int):
            _job_update(job_id, stage=stage, progress=82 + int(pct * 0.17))

        page_stats = apply_redactions(doc, targets_by_page, _progress_cb)

        # Merge per-page accumulation with redactor stats (should be same)
        final_stats = {**all_stats, **page_stats}

        doc.save(output_path, garbage=4, deflate=True, clean=True)
        doc.close()

        _job_update(job_id,
                    status="complete",
                    stage="Complete",
                    progress=100,
                    stats=final_stats,
                    output_path=output_path)

    except Exception as exc:
        logger.error("Pipeline failed for job %s: %s", job_id, exc)
        _job_update(job_id,
                    status="error",
                    error=str(exc),
                    detail=traceback.format_exc())
    finally:
        # Always remove the upload temp file
        try:
            os.remove(input_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Only PDF files are accepted"}), 400

    job_id = str(uuid.uuid4())
    input_path  = str(UPLOAD_DIR / f"{job_id}.pdf")
    output_path = str(OUTPUT_DIR / f"{job_id}_redacted.pdf")

    f.save(input_path)

    with _jobs_lock:
        _jobs[job_id] = {
            "status":      "queued",
            "stage":       "Queued",
            "progress":    0,
            "stats":       {},
            "output_path": None,
            "error":       None,
            "detail":      None,
        }

    t = threading.Thread(
        target=_run_pipeline,
        args=(job_id, input_path, output_path),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/progress/<job_id>")
def progress(job_id: str):
    """Server-Sent Events stream for live pipeline progress."""

    def _generate():
        while True:
            job = _job_get(job_id)
            if not job:
                yield f"data: {json.dumps({'error': 'Job not found'})}\n\n"
                return

            payload = {
                "status":   job["status"],
                "stage":    job["stage"],
                "progress": job["progress"],
            }

            if job["status"] == "complete":
                payload["stats"] = job["stats"]
                yield f"data: {json.dumps(payload)}\n\n"
                return

            if job["status"] == "error":
                payload["error"] = job.get("error", "Unknown error")
                yield f"data: {json.dumps(payload)}\n\n"
                return

            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(0.4)

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":      "keep-alive",
        },
    )


@app.route("/download/<job_id>")
def download(job_id: str):
    job = _job_get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "complete":
        return jsonify({"error": "Job not complete yet"}), 400

    out = job.get("output_path")
    if not out or not os.path.exists(out):
        return jsonify({"error": "Output file missing"}), 404

    return send_file(
        out,
        as_attachment=True,
        download_name="redacted.pdf",
        mimetype="application/pdf",
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Import nlppass here so Presidio loads before the first request
    logger.info("Loading NLP engine (this may take a moment)…")
    import nlppass  # noqa: F401  triggers module-level Presidio init
    logger.info("NLP engine ready. Starting server on http://localhost:5000")
    app.run(debug=False, host="127.0.0.1", port=5000, threaded=True)
