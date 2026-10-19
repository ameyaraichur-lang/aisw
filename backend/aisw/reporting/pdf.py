"""A small deterministic PDF 1.4 writer for report blocks (standard library only).

Base-14 Helvetica fonts with WinAnsi encoding, so nothing is embedded; characters outside
Windows-1252 print as "?". The same blocks and stamp always give the same bytes: no clock, no
random ids (the file id is a hash of the content). Every string is escaped as a PDF literal.
"""

from __future__ import annotations

import hashlib
import zlib
from datetime import datetime

from aisw.reporting.document import Block, Bullets, Heading, Para, Table

PAGE_W, PAGE_H, MARGIN = 595.0, 842.0, 50.0
TEXT_W = PAGE_W - 2 * MARGIN
# Helvetica advance widths (1/1000 em) for the printable ASCII range, from the Adobe AFM.
_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556,
      556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667,
      611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667,
      667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500,
      222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]  # fmt: skip
STYLE = {  # font, size, leading, gap after
    "h1": ("F2", 17.0, 21.0, 8.0), "h2": ("F2", 13.0, 16.0, 5.0), "h3": ("F2", 10.5, 13.0, 3.0),
    "normal": ("F1", 9.0, 12.0, 5.0), "note": ("F3", 8.5, 11.0, 5.0),
    "alert": ("F2", 9.0, 12.0, 6.0), "small": ("F1", 8.0, 10.5, 4.0), "cell": ("F1", 7.5, 9.5, 0.0),
    "head": ("F2", 7.5, 9.5, 0.0),
}  # fmt: skip


def _clean(s: str) -> str:
    return "".join(" " if ord(c) < 32 else c for c in str(s))


def _width(s: str, font: str, size: float) -> float:
    w = sum(_W[ord(c) - 32] if 32 <= ord(c) < 127 else 556 for c in s) * size / 1000
    return w * 1.07 if font == "F2" else w


def _wrap(text: str, width: float, font: str, size: float) -> list[str]:
    lines: list[str] = []
    line = ""
    for word in _clean(text).split(" "):
        cand = f"{line} {word}" if line else word
        if _width(cand, font, size) <= width:
            line = cand
            continue
        if line:
            lines.append(line)
        while _width(word, font, size) > width:  # break an over-long token (hash, URL)
            cut = next((i for i in range(len(word) - 1, 0, -1)
                        if _width(word[:i], font, size) <= width), 1)  # fmt: skip
            lines.append(word[:cut])
            word = word[cut:]
        line = word
    lines.append(line)
    return lines


def _lit(s: str) -> bytes:
    raw = _clean(s).encode("cp1252", errors="replace")
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


class _Layout:
    def __init__(self, header: str | None) -> None:
        self.pages: list[list[bytes]] = []
        self.header = header
        self.y = 0.0
        self._new_page()

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = PAGE_H - MARGIN - (14 if self.header else 0)

    def need(self, h: float) -> None:
        if self.y - h < MARGIN + 16:
            self._new_page()

    def text(self, x: float, y: float, s: str, font: str, size: float) -> None:
        self.pages[-1].append(b"BT /%s %.2f Tf %.2f %.2f Td " % (font.encode(), size, x, y)
                              + _lit(s) + b" Tj ET")  # fmt: skip

    def lines(self, text: str, style: str, indent: float = 0.0, bullet: bool = False) -> None:
        font, size, lead, after = STYLE[style]
        x = MARGIN + indent + (10 if bullet else 0)
        for i, line in enumerate(_wrap(text, TEXT_W - (x - MARGIN), font, size)):
            self.need(lead)
            self.y -= lead
            if bullet and i == 0:
                self.text(x - 9, self.y, "\u2022", font, size)
            self.text(x, self.y, line, font, size)
        self.y -= after

    def table(self, t: Table) -> None:
        n = len(t.headers)
        weights = t.weights if len(t.weights) == n else [1] * n
        widths = [TEXT_W * w / sum(weights) for w in weights]
        pad = 3.0

        def row(cells: list[str], style: str, fill: bool) -> None:
            font, size, lead, _ = STYLE[style]
            wrapped = [
                _wrap(c, w - 2 * pad, font, size) for c, w in zip(cells, widths, strict=True)
            ]
            h = max(len(x) for x in wrapped) * lead + 2 * pad
            if self.y - h < MARGIN + 16:
                self._new_page()
                if style != "head":
                    row(t.headers, "head", True)
            top, x = self.y, MARGIN
            ops = self.pages[-1]
            if fill:
                ops.append(b"0.9 g %.2f %.2f %.2f %.2f re f 0 g" % (MARGIN, top - h, TEXT_W, h))
            for lines_, w in zip(wrapped, widths, strict=True):
                ops.append(b"0.6 G 0.4 w %.2f %.2f %.2f %.2f re S 0 G" % (x, top - h, w, h))
                for i, line in enumerate(lines_):
                    self.text(x + pad, top - pad - (i + 1) * lead + 2, line, font, size)
                x += w
            self.y = top - h

        self.need(40)
        row(t.headers, "head", True)
        for r in t.rows:
            row([str(c) for c in r], "cell", False)
        self.y -= 8


def render_pdf(blocks: list[Block], *, title: str, created: datetime,
               header: str | None = None) -> bytes:  # fmt: skip
    lay = _Layout(header)
    for b in blocks:
        if isinstance(b, Heading):
            lay.need(80)  # never leave a heading alone at the foot of a page
            lay.y -= 4
            lay.lines(b.text, f"h{min(b.level, 3)}")
        elif isinstance(b, Para):
            lay.lines(b.text, b.style)
        elif isinstance(b, Bullets):
            for item in b.items:
                lay.lines(item, "normal", bullet=True)
        else:
            lay.table(b)
    total = len(lay.pages)
    for i, ops in enumerate(lay.pages, start=1):
        if header:
            ops.append(b"BT /F2 8 Tf %.2f %.2f Td " % (MARGIN, PAGE_H - MARGIN + 6) + _lit(header)
                       + b" Tj ET")  # fmt: skip
        foot = f"{title} | page {i} of {total}"
        ops.append(b"BT /F1 7.5 Tf %.2f %.2f Td " % (MARGIN, MARGIN - 18) + _lit(foot) + b" Tj ET")

    objs: list[bytes] = []  # object n is objs[n - 1]
    fonts = {"F1": "Helvetica", "F2": "Helvetica-Bold", "F3": "Helvetica-Oblique"}
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"")  # pages, filled below
    for base in fonts.values():
        objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>"
                    % base.encode())  # fmt: skip
    stamp = created.strftime("D:%Y%m%d%H%M%SZ")
    objs.append(b"<< /Title " + _lit(title) + b" /Producer (AISW) /Creator (AISW report export) "
                b"/CreationDate " + _lit(stamp) + b" >>")  # fmt: skip
    info = len(objs)
    kids = []
    res = b"<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >>"
    for ops in lay.pages:
        data = zlib.compress(b"\n".join(ops), 9)
        objs.append(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data
                    + b"\nendstream")  # fmt: skip
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources %s "
                    b"/Contents %d 0 R >>" % (int(PAGE_W), int(PAGE_H), res, len(objs)))  # fmt: skip
        kids.append(len(objs))
    objs[1] = b"<< /Type /Pages /Count %d /Kids [%s] >>" % (
        len(kids),
        b" ".join(b"%d 0 R" % k for k in kids),
    )
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    fid = hashlib.sha256(bytes(out)).hexdigest()[:32].encode()
    out += (b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objs) + 1, info, fid, fid, xref))  # fmt: skip
    return bytes(out)
