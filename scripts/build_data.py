#!/usr/bin/env python3
"""Build data/cwe-data.js from MITRE's CWE XML catalog.

Usage:
    python3 scripts/build_data.py                 # download cwec_latest.xml.zip
    python3 scripts/build_data.py path/to/cwec_vX.Y.xml[.zip]

The output assigns `window.CWE_DATA` so index.html works straight from disk
(file://) with no server. MITRE's observed examples (CVEs per weakness, ~450 KB) go to a
second file, data/cwe-examples.js (`window.CWE_EXAMPLES`), which the page loads after start.

Edge direction conventions (source -> target):
    ChildOf     child -> parent        (per view; View_ID kept)
    PeerOf      a -> b                 (undirected, de-duplicated)
    CanAlsoBe   a -> b                 (undirected, de-duplicated)
    CanPrecede  earlier -> later
    Requires    compound -> component
"""
from __future__ import annotations

import io
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUT = Path(__file__).resolve().parent.parent / "data" / "cwe-data.js"
OUT_EXAMPLES = OUT.with_name("cwe-examples.js")

UNDIRECTED = {"PeerOf", "CanAlsoBe"}
KEPT = {"ChildOf", "PeerOf", "CanAlsoBe", "CanPrecede", "Requires"}


def load_xml(src: str | None) -> bytes:
    if src is None:
        print(f"Downloading {URL} …", file=sys.stderr)
        req = urllib.request.Request(URL, headers={"User-Agent": "cwe-graph/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            blob = resp.read()
    else:
        blob = Path(src).read_bytes()
    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            name = next(n for n in zf.namelist() if n.endswith(".xml"))
            return zf.read(name)
    return blob


def text(el) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def build(xml: bytes) -> dict:
    root = ET.fromstring(xml)
    NS = {"c": root.tag[1:].split("}")[0]}  # cwe-7 up to 4.x, cwe-8 from 5.0

    views = {v.get("ID"): v.get("Name") for v in root.findall("c:Views/c:View", NS)}

    nodes = {}
    raw_edges = []
    deprecated = {}
    examples = {}
    for w in root.findall("c:Weaknesses/c:Weakness", NS):
        if w.get("Status") == "Deprecated":
            # MITRE's pointers to what replaces it: mapping suggestions, else CWE IDs in the description
            desc = text(w.find("c:Description", NS))
            to = [s.get("CWE_ID") for s in w.findall("c:Mapping_Notes/c:Suggestions/c:Suggestion", NS)]
            deprecated[w.get("ID")] = {
                "n": re.sub(r"^DEPRECATED:\s*", "", w.get("Name")),
                "d": desc,
                "to": to or re.findall(r"CWE-(\d+)", desc),
            }
            continue
        wid = w.get("ID")
        usage = w.find("c:Mapping_Notes/c:Usage", NS)
        nodes[wid] = {
            "n": w.get("Name"),
            "a": w.get("Abstraction"),
            "s": w.get("Status"),
            "u": usage.text if usage is not None else "",
            "d": text(w.find("c:Description", NS)),
        }
        terms = [text(t) for t in w.findall("c:Alternate_Terms/c:Alternate_Term/c:Term", NS)]
        if terms:
            nodes[wid]["k"] = terms  # MITRE's alternate terms (XSS, Information Disclosure …), for search
        if w.get("Diagram"):
            nodes[wid]["g"] = w.get("Diagram")  # MITRE's picture of the weakness, a path on cwe.mitre.org
        sugg = [[s.get("CWE_ID"), s.get("Comment") or ""]
                for s in w.findall("c:Mapping_Notes/c:Suggestions/c:Suggestion", NS)]
        if sugg:
            nodes[wid]["sg"] = sugg  # MITRE's mapping suggestions: [[cwe id, when to use it]]
        ex = [[text(o.find("c:Reference", NS)), text(o.find("c:Description", NS))]
              for o in w.findall("c:Observed_Examples/c:Observed_Example", NS)]
        if ex:
            examples[wid] = ex  # [[CVE id (a few are other references), description]]
        if w.get("Abstraction") == "Compound":
            nodes[wid]["t"] = w.get("Structure")  # Chain or Composite (MITRE draws them differently)
        for rw in w.findall("c:Related_Weaknesses/c:Related_Weakness", NS):
            nature = rw.get("Nature")
            if nature in KEPT:
                raw_edges.append((wid, rw.get("CWE_ID"), nature, rw.get("View_ID") or ""))

    edges, seen = [], set()
    for src, tgt, nature, view in raw_edges:
        if src not in nodes or tgt not in nodes or src == tgt:
            continue
        if nature in UNDIRECTED:
            key = (nature, *sorted((src, tgt)))
        elif nature == "ChildOf":
            key = (nature, src, tgt, view)
        else:
            key = (nature, src, tgt)
        if key in seen:
            continue
        seen.add(key)
        edges.append([src, tgt, nature, view if nature == "ChildOf" else ""])

    for d in deprecated.values():
        d["to"] = list(dict.fromkeys(t for t in d["to"] if t in nodes))
    for n in nodes.values():
        if "sg" in n:
            n["sg"] = [s for s in n["sg"] if s[0] in nodes]
            if not n["sg"]:
                del n["sg"]

    used_views = sorted({e[3] for e in edges if e[2] == "ChildOf"}, key=int)
    return {
        "version": root.get("Version"),
        "date": root.get("Date"),
        "views": {v: views.get(v, f"View {v}") for v in used_views},
        "nodes": nodes,
        "edges": edges,
        "deprecated": deprecated,
        "examples": examples,
    }


def main() -> None:
    data = build(load_xml(sys.argv[1] if len(sys.argv) > 1 else None))
    examples = data.pop("examples")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    OUT.write_text(f"window.CWE_DATA={payload};\n", "utf-8")
    payload = json.dumps(examples, ensure_ascii=False, separators=(",", ":"))
    OUT_EXAMPLES.write_text(f"window.CWE_EXAMPLES={payload};\n", "utf-8")
    print(f"CWE {data['version']} ({data['date']}): {len(data['nodes'])} weaknesses, "
          f"{len(data['edges'])} edges, {sum(map(len, examples.values()))} observed examples -> {OUT.parent}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
