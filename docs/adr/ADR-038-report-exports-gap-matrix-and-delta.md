# ADR-038: PDF and DOCX report exports, control-gap matrix and architecture delta

**Status:** Accepted. Implemented.

## Context
Reports were available as JSON and as static HTML. The rev 3 plan asks for PDF and DOCX exports, a control-gap matrix against external frameworks, and an architecture delta (current state beside target state). Adding a document library would mean a new dependency with its own licence and supply-chain review. It would also make it harder to show that an export says exactly what the hashed report says.

## Decision
- **One source.** `aisw/reporting/document.py` turns the stored report body, plus the export stamp, into a flat list of blocks: headings, paragraphs, bullets and tables. The PDF and DOCX writers render only those blocks, so neither can add content the hashed body does not hold. Each export carries the report hash and the same stamp as HTML (who exported it, when, and the approval state).
- **No new dependencies.** Both writers use the Python standard library only:
  - `pdf.py` writes PDF 1.4 with the base-14 Helvetica fonts (nothing embedded, WinAnsi encoding). It wraps text using the Adobe AFM widths, breaks tables across pages with the header row repeated, and adds a page footer. Characters outside Windows-1252 print as "?".
  - `docx.py` writes a minimal WordprocessingML package: document, styles, core and app properties, and a page header. Tables have fixed column widths and a repeating header row.
- **Deterministic.** The same body and stamp always give the same bytes: no clock, fixed zip timestamps and entry order, and a PDF file id that is a hash of the content. The document date is the report's `generated_at`.
- **Untrusted text.** Evidence-derived strings are escaped as PDF literals or as XML. Control characters, and any characters XML 1.0 forbids, are removed.
- **Draft marking.** An unapproved report carries the draft warning as the first paragraph and as a page header on every PDF page and in the DOCX header part.
- **Same rules as HTML.** `GET /api/v1/reports/{id}?format=pdf|docx[&download=1]` uses the existing endpoint: `report:read` to view, and downloading a draft needs `report:approve`. Every view, export and refusal is audited.
- **Control-gap matrix (frozen).** The worker computes it while building the report and stores it in the hashed body as `control_gaps`. For each framework control reached through the curated mappings (ADR-032) from the run's pack controls, the state is one of:
  - GAP: a mapped check failed;
  - EXCEPTION: risk accepted under an exception;
  - UNKNOWN: a mapped check was not assessed, errored or is missing;
  - NOT_APPLICABLE;
  - NO_GAP_OBSERVED: every mapped check passed or was not applicable.

  It never says "compliant". A mapping still awaiting review is marked PROPOSED, and a rejected mapping is not used. A later review changes the next report, not a stored one.
- **Architecture delta.** Derived from the report's accepted recommendations: pattern, current state (the titles of the accepted findings behind it), target pattern, assets and tier. Effort is never estimated.
- **Everywhere.** The new sections appear in HTML (new reports), PDF and DOCX. A report generated before this change still exports and says the matrix was not recorded.

## Consequences
- Fonts are plain Helvetica and non-Latin text degrades to "?" in PDF; DOCX keeps full Unicode. Embedding a Unicode font would need a reviewed font licence.
- Layout was checked by rendering with macOS PDFKit (`sips`) and reading the DOCX with `textutil`. It has not been opened in Microsoft Word or Adobe Acrobat on this machine.
- The worker reads mapping reviews through the `aisw_app` grants it already inherits; no migration was needed.
- Tests:
  - `tests/unit/test_report_exports.py`: gap states, mapping review effects, delta, PDF structure (xref offsets, page tree), escaping, page breaks with repeated headers, DOCX package validity, determinism, and old reports.
  - `tests/integration/test_report_exports.py`: matrix frozen into the hashed body, download rules and audit.
  - `web/e2e/exports.spec.ts`.
