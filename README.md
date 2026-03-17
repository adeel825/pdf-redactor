# PDF PII Redactor

![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e)
![100% Local](https://img.shields.io/badge/100%25%20Local-No%20data%20leaves%20your%20machine-6366f1)

A local web application that permanently removes personally identifiable information (PII) from PDF documents. Zero network calls — every byte of processing stays on your device.

---

## Project Overview

PDF PII Redactor accepts a PDF upload, scans every page for sensitive information using a multi-stage detection pipeline, and writes a new PDF with the identified content **permanently removed at the byte level**. The redacted text cannot be recovered by selecting, copying, or inspecting the file — it is not a black box painted over the original text.

Detection combines two complementary approaches:

- **Regex pass** — fast, pattern-based matching for structured PII with known formats (SSNs, credit cards, phone numbers, EINs, etc.). Credit and debit card numbers are Luhn-validated before being flagged.
- **NLP pass** — [Microsoft Presidio](https://github.com/microsoft/presidio) backed by [spaCy](https://spacy.io/) `en_core_web_lg` for entity recognition (names, addresses, and other context-dependent PII). No LLM or cloud API required — the model runs entirely on-device.

Results from both passes are merged, deduplicated, and mapped to exact bounding-box coordinates before redaction is applied.

---

## PII Types Covered

| Category | Example | Replacement Label |
|---|---|---|
| Social Security Number | `123-45-6789` | `[SSN REDACTED]` |
| Employer Identification Number | `12-3456789` | `[EIN REDACTED]` |
| Credit / Debit Card *(Luhn validated)* | `4111 1111 1111 1111` | `[CARD REDACTED]` |
| Phone Number | `(555) 867-5309` | `[PHONE REDACTED]` |
| Email Address | `user@example.com` | `[EMAIL REDACTED]` |
| Person Name | `ADEEL KHAN` | `[NAME REDACTED]` |
| Street Address | `123 Main St, Austin TX 78701` | `[ADDRESS REDACTED]` |
| Date of Birth *(context-required)* | `DOB: 01/15/1980` | `[DOB REDACTED]` |
| IP Address | `192.168.1.1` | `[IP REDACTED]` |
| Driver's License | `DL No: A1234567` | `[DL REDACTED]` |
| Passport Number | `Passport: AB1234567` | `[PASSPORT REDACTED]` |
| Bank Account / Routing Number | `Account No: 12345678901` | `[ACCT REDACTED]` |
| Medical Record Number | `MRN: A4829-X` | `[MRN REDACTED]` |

---

## How It Works

Each page passes through a five-stage pipeline:

```
┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
│  1. Extract │──▶│ 2. Regex   │──▶│  3. NLP    │──▶│ 4. Recon-  │──▶│ 5. Redact  │
│  text +    │   │    Pass    │   │    Pass    │   │   cile     │   │            │
│  word bbox │   │            │   │            │   │            │   │            │
└────────────┘   └────────────┘   └────────────┘   └────────────┘   └────────────┘
```

1. **Extract** — PyMuPDF pulls the full text string and a word-level bounding-box list from the page. A second "line-grouped" text is reconstructed by sorting words by Y coordinate so that form fields on the same row (e.g. first name and last name in separate 1040 columns) appear adjacent for the NLP pass.

2. **Regex Pass** — All patterns in `regexpass.py` are applied. Context-prefix patterns (DOB, MRN, DL, passport, bank account) use a capture group so only the sensitive value — not the surrounding label — is used for the PDF coordinate lookup.

3. **NLP Pass** — Presidio `AnalyzerEngine` runs multiple sub-passes on each text string: the original text, a title-cased copy (to surface ALL-CAPS names that spaCy's mixed-case-trained model would otherwise miss), a form-label regex pass (catches `(N) First name VALUE` table patterns), and an all-caps sequence heuristic (catches 2–3 consecutive ALL-CAPS words not found in the non-name blocklist). US address candidates are validated with the `usaddress` library.

4. **Reconcile** — Regex and NLP hits are merged and sorted; overlapping spans are deduplicated (longer span wins). Each surviving match text is located in the PDF via `page.search_for()`, tried in four case variants (original, UPPER, lower, Title). For `PERSON` entities, each individual token is also searched independently to handle split-field name layouts (first name in one form box, last name in another). Overlapping bounding rectangles from multiple variants are deduplicated before being passed forward.

5. **Redact** — `page.add_redact_annot()` stamps a redaction annotation on every bounding rectangle, then `page.apply_redactions()` permanently removes the underlying bytes. The replacement label (e.g. `[SSN REDACTED]`) is written into the blacked-out area in white 7pt text. This is **not** a visual overlay — the original content cannot be recovered.

---

## Tech Stack

| Component | Role |
|---|---|
| **Python 3.9+** | Runtime |
| **Flask** | Local web server and REST API |
| **PyMuPDF (fitz)** | PDF text extraction, coordinate search, and permanent redaction |
| **Microsoft Presidio** | NLP-based PII entity recognition engine |
| **spaCy `en_core_web_lg`** | Named entity recognition model (PERSON, LOCATION, etc.) |
| **usaddress** | US address parsing and validation |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/pdf-redactor.git
cd pdf-redactor

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Download the spaCy language model (~750 MB, one-time download)
python -m spacy download en_core_web_lg

# 4. Start the server
python app.py
```

The server starts on `http://localhost:5000`. The `uploads/` and `outputs/` directories are created automatically on first run.

---

## Usage

1. Open **http://localhost:5000** in your browser.
2. Drag and drop a PDF onto the upload zone, or click **Browse** to pick a file (max 50 MB).
3. Click **Redact PII**. A live progress bar tracks each pipeline stage.
4. When processing completes, a redaction summary table shows the count of each PII category found.
5. Click **Download Redacted PDF** to save the output.

> The uploaded file is deleted from disk immediately after the pipeline finishes. The redacted output is deleted once downloaded.

---

## Project Structure

| File / Directory | Description |
|---|---|
| `app.py` | Flask server — routes, job management, SSE progress stream, line-grouped text extraction |
| `regexpass.py` | Compiled regex patterns with Luhn card validation; returns `RegexMatch` objects |
| `nlppass.py` | Presidio + spaCy wrapper; all-caps normalisation; form-label and caps-sequence name heuristics; usaddress pass |
| `reconciler.py` | Merges regex + NLP hits, deduplicates overlapping spans, maps each match to PDF bounding rectangles via `search_for()` with 4-variant case search and per-token fallback for PERSON entities |
| `redactor.py` | Applies `add_redact_annot()` + `apply_redactions()` per page for permanent byte-level removal |
| `templates/index.html` | Single-page UI — drag-drop upload, live progress bar, redaction summary table, download button |
| `requirements.txt` | Python package dependencies |
| `uploads/` | Temporary storage for uploaded files (auto-cleared after processing) |
| `outputs/` | Storage for redacted PDF output (auto-cleared after download) |

---

## Known Limitations

- **Image-based PDFs are not supported.** The pipeline operates on the text layer only. Scanned documents or PDFs where content is stored as images will produce no redactions. Use an OCR tool (e.g. `ocrmypdf`) to add a text layer first.
- **English language only.** The spaCy model and regex patterns are tuned for US English documents and US identifier formats.
- **No guarantee of 100% detection.** The pipeline is accurate but not exhaustive. Unusual formatting, non-standard fonts, ligatures, or heavily structured layouts may cause some PII to be missed. Always review sensitive documents manually after processing.
- **Single-process server.** The app runs as a single Flask process suitable for local use. It is not designed for multi-user or production deployment.

---

## License

MIT
