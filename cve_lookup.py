"""Which CVE a pasted description is, and which CWEs its record carries on cve.org.

Used by /api/classify to set the model's answer beside the CWE currently assigned:

- resolve(text): a CVE ID written in the text, else an exact (whitespace- and
  case-insensitive) match of the pasted description against every CVE in the local
  cvelistV5 mirror, else a match on its first 160 characters (a truncated paste).
  The index is built in the background (~1-2 min cold) and cached until the
  mirror's deltaLog changes.
- record(cve_id): the live record from the CVE Services API (cve.org), falling back
  to the local mirror when cve.org can't be reached.
- assigned(rec): the CWEs on the record, per container: the CNA's, then each ADP's
  (e.g. CISA-ADP).

Env: LINUX_CWE_CVELIST (cvelistV5 mirror, shared with linux_cwe.py), CVE_API
(https://cveawg.mitre.org/api/cve).
"""
import hashlib
import json
import os
import pathlib
import re
import threading
import urllib.request

HOME = pathlib.Path.home()
CVELIST = pathlib.Path(os.environ.get("LINUX_CWE_CVELIST", HOME / "Desktop/github/cve-services/cvelistV5"))
CVE_API = os.environ.get("CVE_API", "https://cveawg.mitre.org/api/cve")
CACHE = HOME / ".cache/cwe-graph/description_index.json"
PREFIX_LEN = 160

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
CWE_RE = re.compile(r"\b(CWE-\d+|NVD-CWE-(?:noinfo|Other))\b", re.I)


def _norm(text):
    return " ".join((text or "").split()).lower()


def _h(text):
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def _english(descs):
    return next((d.get("value") for d in descs or [] if d.get("lang", "").startswith("en")), None)


def _path(cve_id):
    _, year, num = cve_id.upper().split("-")
    return CVELIST / "cves" / year / f"{num[:-3]}xxx" / f"{cve_id.upper()}.json"


# ── Description index over the whole mirror ─────────────────────────────────

class DescIndex:
    def __init__(self):
        self.full = {}    # hash of the normalized description → [cve ids]
        self.prefix = {}  # hash of its first PREFIX_LEN normalized chars → [cve ids]
        self.ready = threading.Event()
        self.error = None
        self.count = 0

    def _stamp(self):
        p = CVELIST / "cves" / "deltaLog.json"
        return p.stat().st_mtime if p.exists() else 0

    def build(self):
        if not (CVELIST / "cves").is_dir():
            self.error = f"no CVE mirror at {CVELIST}"
            self.ready.set()
            return
        try:
            stamp = self._stamp()
            if CACHE.exists():
                cached = json.loads(CACHE.read_text())
                if cached.get("stamp") == stamp:
                    self.full, self.prefix, self.count = cached["full"], cached["prefix"], cached["count"]
                    self.ready.set()
                    return
            full, prefix, n = {}, {}, 0
            for path in (CVELIST / "cves").rglob("CVE-*.json"):
                try:
                    d = json.loads(path.read_bytes())
                except ValueError:
                    continue
                text = _english(d.get("containers", {}).get("cna", {}).get("descriptions"))
                if not text:
                    continue
                cid, t = d["cveMetadata"]["cveId"], _norm(text)
                full.setdefault(_h(t), []).append(cid)
                if len(t) >= PREFIX_LEN:
                    prefix.setdefault(_h(t[:PREFIX_LEN]), []).append(cid)
                n += 1
            self.full, self.prefix, self.count = full, prefix, n
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            CACHE.write_text(json.dumps({"stamp": stamp, "count": n, "full": full, "prefix": prefix}))
            self.ready.set()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.ready.set()

    def lookup(self, text):
        t = _norm(text)
        ids = self.full.get(_h(t))
        if ids:
            return ids, "description"
        if len(t) >= PREFIX_LEN:
            ids = self.prefix.get(_h(t[:PREFIX_LEN]))
            if ids:
                return ids, "start of the description"
        return [], None


INDEX = DescIndex()


def resolve(text):
    """→ {'cve_id', 'how', 'others'?} or {'cve_id': None, 'how': reason}."""
    m = CVE_RE.search(text or "")
    if m:
        return {"cve_id": m.group(0).upper(), "how": "CVE ID in the text"}
    if not INDEX.ready.is_set():
        return {"cve_id": None, "how": "the CVE description index is still building; try again in a minute"}
    if INDEX.error:
        return {"cve_id": None, "how": f"descriptions can't be matched to a CVE ({INDEX.error}); paste the CVE ID"}
    ids, how = INDEX.lookup(text)
    if not ids:
        return {"cve_id": None, "how": "no CVE in the mirror has this description"}
    ids = sorted(set(ids), key=lambda c: [int(x) for x in c.split("-")[1:]], reverse=True)
    return {"cve_id": ids[0], "how": f"matched the {how} in the CVE mirror", "others": ids[1:6]}


# ── The record and its CWEs ──────────────────────────────────────────────────

def record(cve_id):
    """→ (record dict or None, source label)."""
    try:
        req = urllib.request.Request(f"{CVE_API}/{cve_id}", headers={"Accept": "application/json",
                                                                      "User-Agent": "cwe-graph/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read()), "cve.org"
    except Exception:
        pass
    p = _path(cve_id)
    if p.exists():
        return json.loads(p.read_text()), "local CVE mirror (cve.org unreachable)"
    return None, None


def description(cve_id):
    """A CVE's English CNA description, as predict.from_cvelist() returns it, from cve.org (or the mirror)."""
    rec, _ = record(cve_id)
    if rec is None:
        return None
    return {"cve_id": cve_id, "text": _english(rec.get("containers", {}).get("cna", {}).get("descriptions")),
            "assigner": rec.get("cveMetadata", {}).get("assignerShortName")}


def _cwes(container):
    out = []
    for pt in container.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId") or next(iter(CWE_RE.findall(d.get("description") or "")), None)
            if cwe and cwe.upper() not in (c["cwe"] for c in out):
                out.append({"cwe": cwe.upper() if cwe.upper().startswith("CWE-") else cwe,
                            "text": d.get("description") or ""})
    return out


def assigned(rec):
    """CWEs per container: [{'by': 'CNA (apache)' | 'CISA-ADP', 'cwes': [...]}] (containers with none omitted)."""
    c = rec.get("containers", {})
    out = []
    cna = c.get("cna", {})
    if _cwes(cna):
        out.append({"by": f"CNA ({cna.get('providerMetadata', {}).get('shortName') or rec.get('cveMetadata', {}).get('assignerShortName', '?')})",
                    "cwes": _cwes(cna)})
    for adp in c.get("adp") or []:
        if _cwes(adp):
            out.append({"by": adp.get("providerMetadata", {}).get("shortName") or "ADP", "cwes": _cwes(adp)})
    return out


def lookup(text):
    """Everything /api/classify adds under 'cve'."""
    res = resolve(text)
    if not res["cve_id"]:
        return res
    rec, source = record(res["cve_id"])
    if rec is None:
        res.update(found=False, how=res["how"] + "; the record was not found on cve.org or in the mirror")
        return res
    meta = rec.get("cveMetadata", {})
    res.update(found=True, source=source, state=meta.get("state"),
               assigner=meta.get("assignerShortName"), assigned=assigned(rec))
    return res


def status():
    return {"index": "error" if INDEX.error else "ready" if INDEX.ready.is_set() else "building",
            "cves": INDEX.count}


if __name__ == "__main__":  # quick check: python3 cve_lookup.py "<text>"
    import sys
    INDEX.build()
    print(json.dumps(lookup(" ".join(sys.argv[1:])), indent=2))
