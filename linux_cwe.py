"""Kernel descriptions → the /linux-cwe skill, run through headless Claude Code.

vc-weakling routes Linux kernel text away (scope.py): the kernel CWE is decided from the fix
commit's diff by the linux-cwe skill. This module does what the web page needs for that:

1. resolve() turns the pasted text into the best evidence the skill can use:
   a CVE ID or kernel commit URL/SHA in the text, else a kernel CVE in the local cvelistV5
   mirror whose description matches the paste, else the pasted text itself (weaker: no diff).
2. Job runs `claude -p` with the skill in the skill's own directory, restricted to the tools
   the skill uses, streams progress, and parses the RESULT_JSON line it is asked to end with.
   The skill records its decision to linux-cwe-results/results.jsonl as usual (Scott,
   2026-10-19: web lookups go into the main corpus).

Env: CLAUDE_BIN (claude executable), LINUX_CWE_SKILL (~/.claude/skills/linux-cwe),
     LINUX_CWE_CVELIST (cvelistV5 mirror), LINUX_CWE_REPO (kernel clone),
     LINUX_CWE_MODEL (optional --model), LINUX_CWE_TIMEOUT (seconds, 900).
"""
import glob
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

HOME = pathlib.Path.home()
SKILL_DIR = pathlib.Path(os.environ.get("LINUX_CWE_SKILL", HOME / ".claude/skills/linux-cwe"))
CVELIST = pathlib.Path(os.environ.get("LINUX_CWE_CVELIST", HOME / "Desktop/github/cve-services/cvelistV5"))
REPO = os.environ.get("LINUX_CWE_REPO", str(HOME / "Desktop/Projects/linux/kernel"))
RESULTS_DIR = os.environ.get("LINUX_CWE_RESULTS", str(HOME / "Desktop/Projects/linux/linux-cwe-results"))
TIMEOUT = int(os.environ.get("LINUX_CWE_TIMEOUT", "900"))
CACHE = HOME / ".cache/cwe-graph/kernel_index.json"

PREFIX = re.compile(r"^\s*In the Linux kernel, the following vulnerability has been resolved:\s*", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
URL_SHA_RE = re.compile(
    r"(?:git\.kernel\.org/\S*?/c/|git\.kernel\.org/\S*?[?&]id=|github\.com/torvalds/linux/commit/)([0-9a-f]{7,40})", re.I)
BARE_SHA_RE = re.compile(r"^\s*(?:commit\s+)?([0-9a-f]{7,40})\s*$", re.I)


def find_claude():
    """The Claude Code CLI. On this laptop the only copy is the one bundled with the VS Code
    extension, whose path changes with every extension update, so search for the newest."""
    for cand in (os.environ.get("CLAUDE_BIN"), shutil.which("claude"), str(HOME / ".local/bin/claude"),
                 os.environ.get("CLAUDE_CODE_EXECPATH")):
        if cand and os.access(cand, os.X_OK):
            return cand
    bundled = glob.glob(str(HOME / ".vscode/extensions/anthropic.claude-code-*/resources/native-binary/claude"))
    bundled = [b for b in bundled if os.access(b, os.X_OK)]
    return max(bundled, key=os.path.getmtime) if bundled else None


def unavailable():
    """Why /linux-cwe can't run on this machine, or None. The skill lives outside this repo
    (~/.claude/skills/linux-cwe), so a clone without it still serves the page; kernel text
    then gets routed but not run."""
    if not (SKILL_DIR / "SKILL.md").exists():
        return f"linux-cwe skill not installed at {SKILL_DIR}"
    if not find_claude():
        return "Claude Code CLI not found; set CLAUDE_BIN"
    return None


def _norm(text):
    return " ".join(PREFIX.sub("", text or "").split()).lower()


def _title(text):
    body = PREFIX.sub("", text or "").strip()
    return " ".join(body.splitlines()[0].split()).lower() if body else ""


# ── Kernel CVE index (cvelistV5 mirror) ─────────────────────────────────────

class KernelIndex:
    """Linux-CNA CVEs in the mirror: id → normalized description and title.
    Built in the background (~35 s cold) and cached until the mirror's deltaLog changes."""

    def __init__(self):
        self.rows = []  # [cve_id, title, norm_desc]
        self.ready = threading.Event()
        self.error = None

    def _stamp(self):
        p = CVELIST / "cves" / "deltaLog.json"
        return p.stat().st_mtime if p.exists() else 0

    def build(self):
        try:
            stamp = self._stamp()
            if CACHE.exists():
                cached = json.loads(CACHE.read_text())
                if cached.get("stamp") == stamp:
                    self.rows = cached["rows"]
                    self.ready.set()
                    return
            rows = []
            for year in sorted(p.name for p in (CVELIST / "cves").iterdir() if p.name.isdigit()):
                if int(year) < 2019:
                    continue
                for path in (CVELIST / "cves" / year).rglob("CVE-*.json"):
                    raw = path.read_bytes()
                    if b'"assignerShortName": "Linux"' not in raw and b'"assignerShortName":"Linux"' not in raw:
                        continue
                    d = json.loads(raw)
                    descs = d.get("containers", {}).get("cna", {}).get("descriptions", [])
                    text = next((x["value"] for x in descs if x.get("lang", "").startswith("en")), "")
                    if text:
                        rows.append([d["cveMetadata"]["cveId"], _title(text), _norm(text)])
            self.rows = rows
            CACHE.parent.mkdir(parents=True, exist_ok=True)
            CACHE.write_text(json.dumps({"stamp": stamp, "rows": rows}))
            self.ready.set()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.ready.set()

    def lookup(self, text):
        """→ (cve_ids, how): exact description, the paste as a prefix of one, or same title."""
        n, t = _norm(text), _title(text)
        if not n:
            return [], None
        hits = [r[0] for r in self.rows if r[2] == n]
        if hits:
            return hits, "description"
        if len(n) >= 60:
            hits = [r[0] for r in self.rows if r[2].startswith(n[:300])]
            if hits:
                return hits, "description prefix"
        if len(t) >= 15:
            hits = [r[0] for r in self.rows if r[1] == t]
            if hits:
                return hits, "commit title"
        return [], None


INDEX = KernelIndex()


def resolve(text):
    """What to hand the skill: {'kind': 'cve'|'commit'|'text', 'target', 'how', 'others'}."""
    m = CVE_RE.search(text)
    if m:
        return {"kind": "cve", "target": m.group(0).upper(), "how": "CVE ID in the text"}
    m = URL_SHA_RE.search(text) or BARE_SHA_RE.match(text)
    if m:
        return {"kind": "commit", "target": m.group(1).lower(), "how": "commit in the text"}
    INDEX.ready.wait(timeout=120)
    ids, how = INDEX.lookup(text)
    if ids:
        ids = sorted(ids, key=lambda c: [int(x) for x in c.split("-")[1:]], reverse=True)
        return {"kind": "cve", "target": ids[0], "how": f"matched {how} in the CVE mirror",
                "others": ids[1:]}
    return {"kind": "text", "target": None, "how": "no CVE or commit found; pasted text only"}


# ── Running the skill ────────────────────────────────────────────────────────

RESULT_FIELDS = ("key, commit, status (MAPPED or UNDETERMINED), cwe (\"CWE-n\" or \"\"), confidence "
                 "(high/medium/low or \"\"), root_cause, considered (CWEs weighed and why rejected, one "
                 "string), impact_cwe (or \"\"), adp_cwe (any ADP CWE on the record, or \"\"), title")


def paste_key(text):
    return "paste-" + hashlib.sha1(text.encode()).hexdigest()[:10]


def build_prompt(res, text):
    if res["kind"] == "cve":
        subject = f"kernel CVE {res['target']}"
    elif res["kind"] == "commit":
        subject = f"kernel fix commit {res['target']}"
    else:
        subject = (f"the pasted kernel commit text below (no CVE or commit SHA could be found for it; "
                   f"work from the text alone, say so in the root cause, and record it with "
                   f"--key {paste_key(text)} and confidence no higher than medium):\n\n<pasted>\n{text}\n</pasted>")
    return (
        f"Use the linux-cwe skill to assign the CWE for {subject}\n\n"
        "You are running non-interactively behind the CWE Graph web page. Your working directory is "
        "the skill's directory, so run its scripts exactly as `python3 -I scripts/<name>.py ...` with no "
        "`cd`. Follow the skill's workflow in full, including recording the decision with "
        "`scripts/results.py add` (do not run `export`).\n\n"
        "Finish your reply with exactly one line, the last line, of the form\n"
        "RESULT_JSON: {...}\n"
        f"where the JSON object has these keys: {RESULT_FIELDS}."
    )


def allowed_tools():
    tools = ["Skill", "Read", "Grep", "Glob"]
    tools += [f"Bash(python3 -I scripts/{s}.py:*)" for s in ("gather", "cwe_lookup", "results")]
    tools += [f"Bash(git -C {REPO} {c}:*)" for c in ("show", "log", "grep", "cat-file", "rev-parse", "fetch")]
    return tools


def _progress(block):
    name, inp = block.get("name"), block.get("input") or {}
    if name == "Skill":
        return "Loading the linux-cwe skill"
    if name == "Bash":
        cmd = inp.get("command", "")
        for script, label in (("gather.py", "Gathering the fix commit and diff"),
                              ("cwe_lookup.py", "Checking CWE entries against MITRE's rules"),
                              ("results.py", "Recording the decision")):
            if script in cmd:
                return label
        if " show " in cmd or " grep " in cmd:
            return "Reading pre-fix kernel source"
        return inp.get("description") or cmd[:80]
    if name == "Read":
        return f"Reading {pathlib.Path(inp.get('file_path', '')).name}"
    return name


class Job:
    def __init__(self, text, fresh=False):
        self.id = uuid.uuid4().hex[:12]
        self.text = text
        self.fresh = fresh  # skip the results cache and run the skill again
        self.cached = None  # the cached decision's timestamp when served from results.jsonl
        self.state = "queued"  # queued → resolving → running → done | error | cancelled
        self.progress = []
        self.resolution = None
        self.result = None
        self.summary = ""
        self.error = None
        self.cost_usd = None
        self.started = time.time()
        self.finished = None
        self.proc = None

    def view(self):
        return {"id": self.id, "state": self.state, "progress": self.progress[-8:],
                "resolution": self.resolution, "result": self.result, "summary": self.summary,
                "error": self.error, "cost_usd": self.cost_usd, "cached": self.cached,
                "elapsed_s": round((self.finished or time.time()) - self.started)}

    def cancel(self):
        if self.state in ("done", "error", "cancelled"):
            return
        self.state = "cancelled"
        if self.proc and self.proc.poll() is None:
            self.proc.kill()


JOBS = {}
_RUN_LOCK = threading.Lock()  # one skill run at a time


def start(text, fresh=False):
    job = Job(text, fresh)
    JOBS[job.id] = job
    threading.Thread(target=_run, args=(job,), daemon=True).start()
    return job


def _run(job):
    # Resolve and check the cache outside the lock, so a cached answer never waits on a live run.
    try:
        job.state = "resolving"
        job.resolution = resolve(job.text)
        if job.state == "cancelled":
            return
        rec = None if job.fresh else _from_results_file(job.resolution, job.text)
        if rec:
            job.result, job.cached = rec, rec.get("decided") or "earlier"
            job.state = "done"
            job.finished = time.time()
            return
    except Exception as exc:
        job.error = str(exc)
        job.state = "error"
        job.finished = time.time()
        return
    with _RUN_LOCK:
        if job.state == "cancelled":
            return
        try:
            claude = find_claude()
            if not claude:
                raise RuntimeError("Claude Code CLI not found; set CLAUDE_BIN to the claude executable")
            if job.state == "cancelled":
                return
            job.state = "running"
            cmd = [claude, "-p", build_prompt(job.resolution, job.text),
                   "--output-format", "stream-json", "--verbose",
                   "--permission-mode", "dontAsk",
                   "--allowedTools", *allowed_tools(),
                   "--add-dir", REPO, RESULTS_DIR]
            if os.environ.get("LINUX_CWE_MODEL"):
                cmd += ["--model", os.environ["LINUX_CWE_MODEL"]]
            # A nested Claude Code refuses to start if it thinks it's inside a session.
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith("CLAUDECODE") and k != "CLAUDE_CODE_ENTRYPOINT"}
            job.proc = subprocess.Popen(cmd, cwd=SKILL_DIR, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            timer = threading.Timer(TIMEOUT, job.proc.kill)
            timer.start()
            final = None
            for line in job.proc.stdout:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "assistant":
                    for block in ev.get("message", {}).get("content", []):
                        if block.get("type") == "tool_use":
                            job.progress.append(_progress(block))
                elif ev.get("type") == "result":
                    final = ev
            job.proc.wait()
            timer.cancel()
            if job.state == "cancelled":
                return
            if not final:
                err = job.proc.stderr.read().strip()
                raise RuntimeError(err[-500:] or f"claude exited with code {job.proc.returncode}")
            job.cost_usd = final.get("total_cost_usd")
            text = final.get("result") or ""
            if final.get("is_error"):
                raise RuntimeError(text[-500:] or "the skill run failed")
            m = re.search(r"^RESULT_JSON:\s*(\{.*\})\s*$", text, re.M)
            job.summary = text[:m.start()].strip() if m else text.strip()
            if m:
                try:
                    job.result = json.loads(m.group(1))
                except ValueError:
                    pass
            if job.result is None:
                job.result = _from_results_file(job.resolution, job.text)
            job.state = "done"
        except Exception as exc:
            if job.state != "cancelled":
                job.error = str(exc)
                job.state = "error"
        finally:
            job.finished = time.time()


def _from_results_file(res, text=""):
    """The skill's latest record for this CVE, commit or paste: the cache checked before a run,
    and the fallback when a run's reply lacks RESULT_JSON."""
    if not res:
        return None
    target = (res.get("target") or paste_key(text)).lower()
    path = pathlib.Path(RESULTS_DIR) / "results.jsonl"
    if not path.exists():
        return None
    rec = None
    for line in path.read_text().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        commit = r.get("commit", "").lower()
        if r.get("key", "").lower() == target or (
                res.get("kind") == "commit" and commit and (commit.startswith(target[:12]) or target.startswith(commit))):
            rec = r
    if rec:
        rec["considered"] = rec.get("children_rejected") or rec.get("note") or ""
    return rec


def status():
    why = unavailable()
    return {"claude": bool(find_claude()), "skill": SKILL_DIR.exists(), "unavailable": why,
            "index": "off" if why else "error" if INDEX.error else "ready" if INDEX.ready.is_set() else "building",
            "kernel_cves": len(INDEX.rows)}


if __name__ == "__main__":  # quick check: python3 linux_cwe.py "<pasted text>"
    INDEX.build()
    print(json.dumps(resolve(" ".join(sys.argv[1:])), indent=2))
