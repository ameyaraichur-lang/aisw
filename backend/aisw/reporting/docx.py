"""A small deterministic DOCX (WordprocessingML) writer for report blocks (standard library only).

The package holds the document, styles, core and app properties, and a page header carrying the
draft warning when the report is not approved. Zip entries have fixed timestamps and order, so the
same blocks and stamp always give the same bytes. Text is XML-escaped, and characters XML 1.0
forbids are dropped, because evidence-derived strings are untrusted.
"""

from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
from xml.sax.saxutils import escape

from aisw.reporting.document import Block, Bullets, Heading, Para, Table

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
TEXT_TWIPS = 9638  # A4 width minus 2 cm margins on each side
_BAD_XML = re.compile("[^\t\n\r\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")
STYLE_FOR = {"normal": None, "note": "Note", "alert": "Alert", "small": "Small"}


def _t(s: str) -> str:
    return escape(_BAD_XML.sub("", str(s)))


def _run(text: str, *, bold: bool = False) -> str:
    rpr = "<w:rPr><w:b/></w:rPr>" if bold else ""
    parts = _t(text).split("\n")
    inner = "<w:br/>".join(f'<w:t xml:space="preserve">{p}</w:t>' for p in parts)
    return f"<w:r>{rpr}{inner}</w:r>"


def _p(text: str, style: str | None = None, *, bold: bool = False) -> str:
    ppr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{ppr}{_run(text, bold=bold)}</w:p>"


def _table(t: Table) -> str:
    n = len(t.headers)
    weights = t.weights if len(t.weights) == n else [1] * n
    cols = [TEXT_TWIPS * w // sum(weights) for w in weights]
    grid = "".join(f'<w:gridCol w:w="{c}"/>' for c in cols)

    def row(cells: list[str], header: bool) -> str:
        trpr = (
            "<w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>"
            if header
            else "<w:trPr><w:cantSplit/></w:trPr>"
        )
        shade = '<w:shd w:val="clear" w:color="auto" w:fill="E6E6E6"/>' if header else ""
        tcs = "".join(
            f'<w:tc><w:tcPr><w:tcW w:w="{c}" w:type="dxa"/>{shade}</w:tcPr>'
            f"{_p(str(v), 'Cell', bold=header)}</w:tc>"
            for v, c in zip(cells, cols, strict=True)
        )
        return f"<w:tr>{trpr}{tcs}</w:tr>"

    borders = "".join(f'<w:{e} w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
                      for e in ("top", "left", "bottom", "right", "insideH", "insideV"))  # fmt: skip
    return (
        f'<w:tbl><w:tblPr><w:tblW w:w="{TEXT_TWIPS}" w:type="dxa"/><w:tblBorders>{borders}'
        f'</w:tblBorders><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>{grid}</w:tblGrid>'
        + row(t.headers, True)
        + "".join(row([str(c) for c in r], False) for r in t.rows)
        + "</w:tbl>"
        + _p("", "Small")
    )


def _body(blocks: list[Block]) -> str:
    out = []
    for b in blocks:
        if isinstance(b, Heading):
            out.append(_p(b.text, "Title" if b.level == 1 else f"Heading{min(b.level - 1, 2)}"))
        elif isinstance(b, Para):
            out.append(_p(b.text, STYLE_FOR[b.style]))
        elif isinstance(b, Bullets):
            out += [_p(f"\u2022 {item}", "Bullet") for item in b.items]
        else:
            out.append(_table(b))
    return "".join(out)


def _styles() -> str:
    def style(sid: str, name: str, ppr: str = "", rpr: str = "", kind: str = "paragraph") -> str:
        return (f'<w:style w:type="{kind}" w:styleId="{sid}"><w:name w:val="{name}"/>'
                f'<w:basedOn w:val="Normal"/><w:qFormat/><w:pPr>{ppr}</w:pPr><w:rPr>{rpr}</w:rPr></w:style>')  # fmt: skip

    return (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="{W}">'
        '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" '
        'w:cs="Calibri"/><w:sz w:val="19"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>'
        '<w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr>'
        "</w:pPrDefault></w:docDefaults>"
        '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/>'
        "<w:qFormat/></w:style>"
        + style("Title", "Title", '<w:spacing w:after="160"/>', '<w:b/><w:sz w:val="34"/>')
        + style("Heading1", "heading 1", '<w:keepNext/><w:spacing w:before="240" w:after="80"/>'
                '<w:outlineLvl w:val="0"/>', '<w:b/><w:sz w:val="26"/>')
        + style("Heading2", "heading 2", '<w:keepNext/><w:spacing w:before="160" w:after="60"/>'
                '<w:outlineLvl w:val="1"/>', '<w:b/><w:sz w:val="21"/>')
        + style("Note", "AISW note", "", '<w:i/><w:sz w:val="17"/>')
        + style("Alert", "AISW alert", "", '<w:b/><w:color w:val="9C2A00"/>')
        + style("Small", "AISW small", "", '<w:sz w:val="16"/>')
        + style("Cell", "AISW table cell", '<w:spacing w:after="0"/>', '<w:sz w:val="15"/>')
        + style("Bullet", "AISW bullet", '<w:ind w:left="284" w:hanging="170"/>')
        + "</w:styles>"
    )  # fmt: skip


def render_docx(blocks: list[Block], *, title: str, created: datetime,
                header: str | None = None) -> bytes:  # fmt: skip
    when = created.strftime("%Y-%m-%dT%H:%M:%SZ")
    head_ref = '<w:headerReference w:type="default" r:id="rIdHeader"/>' if header else ""
    document = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W}" '
        f'xmlns:r="{R}"><w:body>{_body(blocks)}<w:sectPr>{head_ref}'
        '<w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" '
        'w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>'
    )
    doc_rels = [("rIdStyles", f"{R}/styles", "styles.xml")]
    if header:
        doc_rels.append(("rIdHeader", f"{R}/header", "header1.xml"))
    parts: list[tuple[str, str]] = [
        ("[Content_Types].xml",
         '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.'
         'openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType='
         '"application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" '
         'ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType='
         '"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
         '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-'
         'officedocument.wordprocessingml.styles+xml"/>'
         + ('<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-'
            'officedocument.wordprocessingml.header+xml"/>' if header else "")
         + '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-'
         'package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType='
         '"application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>'),
        ("_rels/.rels",
         f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{PKG}">'
         f'<Relationship Id="rId1" Type="{R}/officeDocument" Target="word/document.xml"/>'
         '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/'
         'relationships/metadata/core-properties" Target="docProps/core.xml"/>'
         f'<Relationship Id="rId3" Type="{R}/extended-properties" Target="docProps/app.xml"/>'
         "</Relationships>"),
        ("docProps/core.xml",
         '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp='
         '"http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc='
         '"http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
         'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
         f"<dc:title>{_t(title)}</dc:title><dc:creator>AISW</dc:creator>"
         f'<dcterms:created xsi:type="dcterms:W3CDTF">{when}</dcterms:created></cp:coreProperties>'),
        ("docProps/app.xml",
         '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.'
         'openxmlformats.org/officeDocument/2006/extended-properties"><Application>AISW report '
         "export</Application></Properties>"),
        ("word/document.xml", document),
        ("word/styles.xml", _styles()),
        ("word/_rels/document.xml.rels",
         f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="{PKG}">'
         + "".join(f'<Relationship Id="{i}" Type="{t}" Target="{tg}"/>' for i, t, tg in doc_rels)
         + "</Relationships>"),
    ]  # fmt: skip
    if header:
        parts.append(("word/header1.xml",
                      f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="{W}">'
                      f"{_p(header, 'Alert')}</w:hdr>"))  # fmt: skip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, xml in parts:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0o600 << 16
            z.writestr(info, xml.encode("utf-8"), compresslevel=9)
    return buf.getvalue()
