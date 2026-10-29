# CWE Graph Explorer

A standalone, browser-only explorer for the MITRE CWE weakness hierarchy.
It is a hierarchical (layered) directed graph drawn with Cytoscape.js and a
Sugiyama-style dagre layout: parents on top, children below.

No server, database or network access is needed at runtime. The catalog is
pre-built into `data/cwe-data.js` and the libraries are vendored in `vendor/`.

## Run

Open `index.html` in a browser. To serve it instead:

```sh
python3 -m http.server 8000   # then visit http://localhost:8000
```

Deep links: `index.html#79`, `#79/ancestors`, `#79/descendants`.

## Find a CWE from a description (vc-weakling)

The top bar has two inputs: **Search CWE** (left) looks CWEs up in the catalog by ID or
name; the **description box** (right) takes a vulnerability description or CVE ID and
runs the classifier. Classifying needs the bundled server, run with the models venv (it
needs torch + transformers):

```sh
~/Desktop/models/cwe/.venv/bin/python server.py   # then open http://127.0.0.1:8800
```

**Without the model.** `python3 server.py` (any Python 3, no venv) runs the same page
without vc-weakling; no model, torch or models directory is needed. The description box
then looks up the CVE and shows the CWEs on its record, and Linux kernel text still runs
`/linux-cwe`; only the top-3 prediction is missing. It drops to this mode on its own when
`~/Desktop/models/cwe` or its model isn't there.

It serves this directory and adds `POST /api/classify`, which calls vc-weakling's own
`predict.classify()` from `~/Desktop/models/cwe` (override with `WEAKLING_DIR`). Nothing
in the models directory is modified. The model loads in the background (~10 s); the page
works meanwhile and the button enables when it's ready.

Results follow the pipeline's rules: the top 3 CWEs with confidence, **High confidence**
at ≥ 0.90 (`auto`) or **Needs review** below it, and Oracle CPU text to noinfo. A bare
CVE ID's description is fetched from the CVE API (cve.org), else the local cvelistV5
mirror, and classified. The
result appears at the top of the right panel; the graph jumps to the top pick, and all
top-3 CWEs get a soft halo wherever they appear in the graph. Opened as a plain file, the
page switches to the server if it's running, and otherwise works with classifying disabled.

**Assigned vs model.** Each result starts by setting the model's answer beside the CWEs
currently on the CVE's record (`cve_lookup.py`). The CVE is the ID in the text, or the
CVE in the mirror whose description matches the paste (an index of every CVE, built in
the background in ~1 min and cached in `~/.cache/cwe-graph/`); that
match is the one part that needs the mirror, since the CVE API can't search descriptions,
so without it paste the CVE ID. The record is fetched live
from cve.org (CVE Services API), falling back to the local mirror. It lists each CWE with
who assigned it (CNA or an ADP such as CISA-ADP) and flags Discouraged ones, then gives a
verdict: **Agrees** (top pick is assigned), **Close** (an assigned CWE is in the top 3),
**Related** (parent/child of an assigned CWE), **Differs**, or no CWE on the record yet.

**Linux kernel text runs the `/linux-cwe` skill** (`linux_cwe.py`), through headless
Claude Code on your account (~30 s–2 min and roughly $0.20 per lookup; one at a time):

1. The server finds the evidence the skill needs: a CVE ID or kernel commit URL/SHA in
   the text; else the kernel CVE in the mirror whose description matches the paste
   (index of ~18k kernel CVEs, built in the background and cached in
   `~/.cache/cwe-graph/`); else the pasted text alone, flagged as weaker evidence.
2. It runs the skill in its own directory, limited to the skill's scripts and read-only
   git on the kernel clone, and shows progress live (with Cancel).
3. The page shows the CWE, confidence, root cause and the CWEs considered. **Every
   decision is recorded to `linux-cwe-results/results.jsonl`** like any other run;
   re-running a CVE replaces its earlier decision.

The Claude Code CLI is found automatically (on this laptop, the copy bundled with the
VS Code extension); set `CLAUDE_BIN` to override, `LINUX_CWE_MODEL` to pick a model.

## Refresh the catalog

```sh
python3 scripts/build_data.py                    # downloads cwec_latest.xml.zip from MITRE
python3 scripts/build_data.py cwec_v5.0.xml.zip  # or build from a local copy
```

Deprecated weaknesses are not graph nodes, but their names and MITRE's suggested replacements are kept: when the model, a CVE record or an old `#613` link names one, the page marks it deprecated and links the replacements (a deep link opens the first). Categories and views are not nodes; views
only select which `ChildOf` hierarchy is drawn.

## Using it

- **Search CWE** finds CWEs by ID or name (arrow keys + Enter pick a result).
- **The description box** classifies a description or CVE ID (Enter or **Find CWE**;
  Shift+Enter adds a line).
- **The toolbar** above the graph:
  - **Neighborhood** shows everything within *Depth* hops over the enabled
    relationship types. **Ancestors** and **Descendants** follow `ChildOf` only,
    all the way to the Pillar or the leaves.
  - **View** picks which MITRE view's `ChildOf` edges are used: all views merged by
    default, or a single view such as Research Concepts (CWE-1000) or Weaknesses for
    Simplified Mapping (CWE-1003, NVD's view; it covers only ~125 CWEs).
  - **Depth** (default 3) is how many hops the Neighborhood reaches.
  - **Relationships** toggles which edge types the graph draws; only `ChildOf` is
    on by default. The layout always ranks by `ChildOf` alone, so lateral edges
    (PeerOf, CanPrecede …) never distort it. The details panel lists every
    relationship whatever is toggled.
  - **Fit**, **Layout** and **PNG** (export the current graph).
- **The right panel** shows the classifier result (× clears it), then the selected
  CWE: description, status, mapping usage and every relation. Clicking a node
  redraws the graph around it, in the current mode.
- **The key** in the graph's corner names each abstraction icon.

## Encoding

Nodes use MITRE's own CWE-site icons, so they read the way cwe.mitre.org does:

| Type | Icon | Colour |
|---|---|---|
| Pillar | gray column with **P** | `#919191` |
| Class | circle **C** | `#358d33` |
| Base | circle **B** | `#3c5292` |
| Variant | circle **V** | `#c06abd` |
| Compound (Composite) | three spheres | `#3c5292` |
| Compound (Chain) | linked rings | `#3c5292` |

Colours are MITRE's, except Variant's purple, lightened from MITRE's `#944093`, which
is indistinguishable from Base's blue under protanopia. The palette was checked
all-pairs for colour-vision deficiency; the letter or glyph is the secondary encoding,
so no node depends on colour alone. Icons are drawn in `KINDS` / `iconSvg()`
(`js/app.js`); the CSS variables in `css/app.css` mirror the colours.

## License

[PolyForm Noncommercial 1.0.0](LICENSE): free for noncommercial use, and every copy must
keep the license and its `Required Notice: Copyright 2026 VulnCheck, Inc.` line. For
commercial use, contact VulnCheck.

The vc-weakling model is not part of this repository; the server runs without it (see
**Without the model** above).

Third-party parts keep their own terms:

- `vendor/cytoscape.min.js`: Cytoscape.js, MIT, Copyright (c) 2016-2024 The Cytoscape Consortium.
- `vendor/dagre.min.js`: dagre and graphlib, MIT, Copyright (c) 2012-2014 Chris Pettitt
  (it also bundles lodash, MIT); the licenses are inside the file.
- `vendor/cytoscape-dagre.js`: cytoscape-dagre, MIT, The Cytoscape Consortium.
- `data/cwe-data.js`: built from the CWE catalog, Copyright (c) 2006-2026 The MITRE
  Corporation, used under the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
  CWE and the CWE logo (`images/cwe-20-years.png`) are trademarks of The MITRE Corporation.
- `images/vc.png`: the VulnCheck logo is a trademark of VulnCheck, Inc. and is not licensed
  under the PolyForm terms.
