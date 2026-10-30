#!/usr/bin/env python3
"""Serve the CWE Graph Explorer with description → CWE classification by vc-weakling.

    ~/Desktop/models/cwe/.venv/bin/python server.py      # then open http://127.0.0.1:8800
    python3 server.py                                    # no model: everything but the top 3

Run it with the models venv (it needs torch + transformers). Static files come from this
directory; the model is used through vc-weakling's own predict.classify(), so scope routing
(kernel → linux-cwe, Oracle → noinfo) and the auto/review threshold match the pipeline.

Without vc-weakling (no WEAKLING_DIR, no model in it, or no torch/transformers) the server
still runs: CVE lookup, the assigned-CWE comparison and /linux-cwe work, and classify answers
with status "nomodel" and no top 3. Routing then uses the copy of scope.py's rules below.

Linux kernel text (route 'linux-cwe') is handed to the /linux-cwe skill through headless
Claude Code; see linux_cwe.py. Without the skill or the Claude Code CLI, kernel text answers
with status "noskill" (and "no_skill": why) and POST /api/linux-cwe returns 503.

  GET  /api/health              {"ok", "model", "ready", "error"?, "linux": {...}}
  POST /api/classify            {"text": "..."} → predict.classify() result (route, status, pred,
                                conf, top3). A bare CVE ID's description comes from the CVE API
                                (cveawg.mitre.org), else the cvelistV5 mirror.
                                Plus "cve": which CVE the text is and the CWEs on its record
                                (cve.org), from cve_lookup.py.
  POST /api/linux-cwe           {"text": "..."} → a skill job {"id", "state", ...}; answered from
                                linux-cwe-results/results.jsonl when already decided ("cached"),
                                unless ?fresh=1
  GET  /api/linux-cwe/<id>      the job: state, progress, resolution, result, summary, cost_usd
  POST /api/linux-cwe/<id>/cancel

Env: WEAKLING_DIR (default ~/Desktop/models/cwe; must hold scripts/predict.py),
     CWE_MODEL (passed through to predict.py), CWE_GRAPH_HOST (127.0.0.1), CWE_GRAPH_PORT (8800),
     plus linux_cwe.py's (CLAUDE_BIN, LINUX_CWE_*).
"""
import json
import os
import pathlib
import sys
import re
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parent
WEAKLING_DIR = pathlib.Path(os.environ.get("WEAKLING_DIR", pathlib.Path.home() / "Desktop/models/cwe"))
HOST = os.environ.get("CWE_GRAPH_HOST", "127.0.0.1")
PORT = int(os.environ.get("CWE_GRAPH_PORT", "8800"))
MAX_TEXT = 12000

import cve_lookup  # noqa: E402
import linux_cwe  # noqa: E402

sys.path.insert(0, str(WEAKLING_DIR / "scripts"))
try:
    from predict import MODEL, _load, classify  # noqa: E402
    import importlib.util
    missing = [m for m in ("torch", "transformers") if importlib.util.find_spec(m) is None]
    NO_MODEL = (f"{', '.join(missing)} not installed" if missing
                else None if (MODEL / "config.json").exists() else f"no model at {MODEL}")
except ImportError:
    MODEL, NO_MODEL = None, f"vc-weakling not found at {WEAKLING_DIR}"

if NO_MODEL and MODEL is None:
    # vc-weakling's scope.py rules, copied so routing still works without it. Keep in sync.
    _KERNEL = re.compile(r"\bLinux kernel\b", re.I)

    def _route(text, assigner=None):
        a = (assigner or "").lower()
        if "kernel.org" in a or a == "linux" or _KERNEL.search(text or ""):
            return "linux-cwe"
        if "oracle" in a or ("Oracle" in (text or "")[:300] and "exploitable vulnerability allows" in text):
            return "noinfo"
        return "model"

elif NO_MODEL:
    from scope import route as _route  # noqa: E402

if NO_MODEL:
    def classify(rows):
        """predict.classify() without the model: routing only; 'model' routes get status 'nomodel'."""
        out = []
        for r in rows:
            rt = _route(r["text"], r.get("assigner"))
            status = {"linux-cwe": "linux-cwe", "noinfo": "noinfo"}.get(rt, "nomodel")
            o = {"cve_id": r["cve_id"], "model": None, "route": rt, "status": status}
            if rt == "noinfo":
                o["pred"] = "noinfo"
            out.append(o)
        return out

BARE_CVE = re.compile(r"^\s*CVE-\d{4}-\d{4,}\s*$", re.I)
JOB_PATH = re.compile(r"^/api/linux-cwe/([0-9a-f]{12})(/cancel)?$")

_ready = threading.Event()
_error = None
_lock = threading.Lock()  # one inference at a time


def _warm():
    """Load the model in the background so the page is usable while it loads."""
    global _error
    if NO_MODEL:
        print(f"[cwe-graph] no model ({NO_MODEL}): classify does CVE lookup (and /linux-cwe if installed)",
              file=sys.stderr, flush=True)
        _ready.set()
        return
    try:
        _load(str(MODEL))
        classify([{"cve_id": None, "text": "SQL injection in login.php via the id parameter"}])
        _ready.set()
        print(f"[cwe-graph] {MODEL.name} ready", file=sys.stderr, flush=True)
    except Exception as exc:  # surfaced through /api/health
        _error = f"{type(exc).__name__}: {exc}"
        print(f"[cwe-graph] model failed to load: {_error}", file=sys.stderr, flush=True)


class Handler(SimpleHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.path == "/api/health":
            # Lets a copy of the page opened as a file find this server and switch to it.
            self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = JOB_PATH.match(self.path)
        if self.path == "/api/health":
            health = {"ok": _error is None, "model": None if NO_MODEL else MODEL.name, "ready": _ready.is_set(),
                      "linux": linux_cwe.status(), "cve_index": cve_lookup.status()}
            if _error:
                health["error"] = _error
            if NO_MODEL:
                health["no_model"] = NO_MODEL
            self._json(200, health)
        elif m and not m.group(2):
            job = linux_cwe.JOBS.get(m.group(1))
            self._json(200, job.view()) if job else self._json(404, {"error": "no such job"})
        else:
            super().do_GET()

    def _text(self):
        """The request's text field, or None after answering 400."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n) or b"{}")
            text = str(req.get("text") or "").strip()[:MAX_TEXT]
        except (ValueError, TypeError):
            self._json(400, {"error": "body must be JSON with a text field"})
            return None
        if not text:
            self._json(400, {"error": "empty description"})
            return None
        return text

    def do_POST(self):
        m = JOB_PATH.match(self.path)
        if m and m.group(2):
            job = linux_cwe.JOBS.get(m.group(1))
            if job:
                job.cancel()
            self._json(200, job.view()) if job else self._json(404, {"error": "no such job"})
        elif self.path in ("/api/linux-cwe", "/api/linux-cwe?fresh=1"):
            text = self._text()
            no_skill = linux_cwe.unavailable()
            if no_skill and text is not None:
                self._json(503, {"error": no_skill})
            elif text is not None:
                self._json(200, linux_cwe.start(text, fresh=self.path.endswith("fresh=1")).view())
        elif self.path == "/api/classify":
            self._classify()
        else:
            self._json(404, {"error": "not found"})

    def _classify(self):
        text = self._text()
        if text is None:
            return
        row = {"cve_id": None, "text": text, "assigner": None}
        if BARE_CVE.match(text):  # a CVE ID alone: classify its description from the mirror
            cve_id = text.strip().upper()
            found = cve_lookup.description(cve_id)  # the CVE API, else the mirror
            if not found or not found.get("text"):
                self._json(404, {"error": f"{cve_id} was not found in the CVE mirror or on cve.org"})
                return
            row = found
        if _error:
            self._json(503, {"error": f"model failed to load: {_error}"})
            return
        if not _ready.wait(timeout=120):
            self._json(503, {"error": "model is still loading"})
            return
        with _lock:
            res = classify([row])[0]
        if res["status"] == "linux-cwe":
            no_skill = linux_cwe.unavailable()
            if no_skill:
                res["status"], res["no_skill"] = "noskill", no_skill
        if row["cve_id"]:
            res["looked_up"] = {"cve_id": row["cve_id"], "text": row["text"], "assigner": row["assigner"]}
        # The CWEs currently on the CVE's record (cve.org), to set beside the model's answer.
        try:
            res["cve"] = cve_lookup.lookup(text)
        except Exception as exc:
            res["cve"] = {"cve_id": None, "how": f"lookup failed: {exc}"}
        self._json(200, res)

    def log_message(self, fmt, *args):
        # Log API calls and errors only (not job polling); args[0] is the request line, or an
        # HTTPStatus on errors.
        line = str(args[0]) if args else ""
        if not isinstance(args[0] if args else None, str) or ("/api/" in line and not line.startswith("GET /api/linux-cwe/")):
            sys.stderr.write("[cwe-graph] %s\n" % (fmt % args))


def main():
    threading.Thread(target=_warm, daemon=True).start()
    no_skill = linux_cwe.unavailable()
    if no_skill:
        print(f"[cwe-graph] no /linux-cwe ({no_skill}): kernel text is routed but not run",
              file=sys.stderr, flush=True)
    else:
        threading.Thread(target=linux_cwe.INDEX.build, daemon=True).start()
    threading.Thread(target=cve_lookup.INDEX.build, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), partial(Handler, directory=str(ROOT)))
    print(f"[cwe-graph] serving {ROOT} on http://{HOST}:{PORT}  "
          f"({'no model' if NO_MODEL else f'loading {MODEL.name} …'})",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
