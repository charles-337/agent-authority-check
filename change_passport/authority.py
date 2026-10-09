"""Agent Authority Check (https://github.com/charles-337/agent-authority-check): a read-only look at what stands between an AI coding agent and a repository's main branch, and what one
credential (for example, the token your agent uses) is permitted to do to those protections.

    python -m change_passport.authority --repo OWNER/NAME [--branch BRANCH] [--out DIR] [--anonymize] [--json FILE] [--fail-on-high]

It needs no admin rights and no write access. With no credential at all it checks any public repository as the public sees it. With
GITHUB_TOKEN or GH_TOKEN set (use the agent's own token to assess the agent), or with a gh login, it also reports what that credential may do.

It only reads: every request is a GET, nothing is changed, and no token is written anywhere. Each finding is a configuration fact with the
request it came from and a command to check it yourself. Seeing a setting is not the power to change it, and a setting is not proof that
GitHub refuses anything in practice: what this check cannot determine, it says. Python standard library only."""
import argparse
import base64
import hashlib
import html
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "OK": 3}
CONTACT = "charles_337@me.com"


class CheckError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ read-only transports: GET only

def _split(raw):
    raw = raw.replace(b"\r\n", b"\n")
    while raw.startswith(b"HTTP/") and b"\n\n" in raw and raw.split(b"\n", 1)[0].split()[1:2] in ([b"100"], [b"301"], [b"302"]):
        raw = raw.split(b"\n\n", 1)[1]                                        # skip interim and redirect responses
    head, _, body = raw.partition(b"\n\n")
    m = re.match(rb"HTTP/[\d.]+ (\d{3})", head)
    if not m:
        raise CheckError("unreadable response from GitHub")
    hdr = {k.strip().lower(): v.strip() for k, _, v in (l.decode(errors="replace").partition(":") for l in head.split(b"\n")[1:])}
    return int(m.group(1)), body, hdr


class GhTransport:
    """The gh CLI's own login; this program never sees the token."""
    name, authenticated = "your gh login", True

    def get(self, path):
        p = subprocess.run(["gh", "api", "-i", "-H", "Accept: application/vnd.github+json", path.lstrip("/")], capture_output=True)
        if not p.stdout.startswith(b"HTTP/"):
            raise CheckError(f"gh could not reach GitHub: {p.stderr.decode(errors='replace').strip()[:200]}")
        return _split(p.stdout)


class HttpTransport:
    """A token from the environment, or none (the public view). A token goes only into a request header; if this machine's Python cannot
    make TLS connections, curl is used and reads the header from standard input, so the token never appears in a process listing."""

    def __init__(self, token=None):
        self._token = token
        self.name = "a token from the environment" if token else "no credential (the public view)"
        self.authenticated = bool(token)

    def get(self, path):
        url = API + path
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "haven-agent-authority-check"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method="GET", headers=headers), timeout=30) as r:
                return r.status, r.read(), {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            return e.code, e.read(), {k.lower(): v for k, v in e.headers.items()}
        except urllib.error.URLError as e:
            if not isinstance(e.reason, ssl.SSLError) or not shutil.which("curl"):
                raise CheckError(f"cannot reach GitHub: {e.reason}")
        cfg = f'url = "{url}"\n' + "".join(f'header = "{k}: {v}"\n' for k, v in headers.items())
        p = subprocess.run(["curl", "-sS", "-i", "-K", "-"], input=cfg.encode(), capture_output=True)
        if p.returncode != 0:
            raise CheckError(f"cannot reach GitHub: {p.stderr.decode(errors='replace').strip()[:200]}")
        return _split(p.stdout)


def transport(anonymous=False):
    token = None if anonymous else (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    if token or anonymous:
        return HttpTransport(token)
    if shutil.which("gh") and subprocess.run(["gh", "auth", "status"], capture_output=True).returncode == 0:
        return GhTransport()
    return HttpTransport()                                                    # no credential anywhere: the public view


# ------------------------------------------------------------------------------------------------ reading GitHub, with an evidence log

class Reader:
    def __init__(self, t):
        self.t, self.log = t, []

    def get(self, path, essential=False):
        status, body, hdr = self.t.get(path)
        rid = f"R{len(self.log) + 1}"
        self.log.append({"id": rid, "method": "GET", "endpoint": path, "status": status, "sha256": hashlib.sha256(body or b"").hexdigest(),
                         "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        if status == 401 and essential:
            raise CheckError("GitHub rejected the credential (HTTP 401): check that the token is valid and not expired")
        if status in (403, 429) and hdr.get("x-ratelimit-remaining") == "0":
            raise CheckError("GitHub's rate limit is used up (unauthenticated: 60 requests an hour); set GITHUB_TOKEN or log in with gh, or try later")
        try:
            data = json.loads(body) if body else None
        except ValueError:
            data = None
        return rid, status, data, hdr


def collect(t, repo, branch=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
        raise CheckError(f"--repo must look like OWNER/NAME, not {repo!r}")
    R = Reader(t)
    login = None
    if t.authenticated:
        _, s, user, _ = R.get("/user", essential=True)
        login = (user or {}).get("login") if s == 200 else None
    rid_repo, s, r, hdr = R.get(f"/repos/{repo}", essential=True)
    if s == 404:
        raise CheckError(f"{repo} was not found, or {t.name} cannot see it (HTTP 404)" + ("" if t.authenticated else "; for a private repository set GITHUB_TOKEN or log in with gh"))
    if s != 200:
        raise CheckError(f"could not read {repo} (HTTP {s})")
    branch = branch or r.get("default_branch")
    b = urllib.parse.quote(branch, safe="")
    rid_branch, s, br, _ = R.get(f"/repos/{repo}/branches/{b}")
    if s == 404:
        raise CheckError(f"branch {branch!r} was not found in {repo}")
    rid_prot, s_prot, prot, _ = R.get(f"/repos/{repo}/branches/{b}/protection")
    rid_rules, s_rules, rules, _ = R.get(f"/repos/{repo}/rules/branches/{b}")
    co = {"text": None, "path": None, "rids": []}
    for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        rid, s, c, _ = R.get(f"/repos/{repo}/contents/{path}?ref={b}")
        co["rids"].append(rid)
        if s == 200 and isinstance(c, dict) and c.get("content"):
            co = {"text": base64.b64decode(c["content"]).decode("utf-8", "replace"), "path": path, "rids": [rid]}
            break
    return {"repo": repo, "branch": branch, "login": login, "via": t.name, "authenticated": t.authenticated,
            "scopes": hdr.get("x-oauth-scopes"), "repo_rid": rid_repo, "permissions": r.get("permissions"), "private": r.get("private"),
            "protected": (br or {}).get("protected"), "classic_enabled": ((br or {}).get("protection") or {}).get("enabled"), "branch_rid": rid_branch,
            "protection": prot if s_prot == 200 else None, "protection_status": s_prot, "protection_rid": rid_prot,
            "rules": rules if s_rules == 200 and isinstance(rules, list) else None, "rules_status": s_rules, "rules_rid": rid_rules,
            "codeowners": co, "log": R.log}


# ------------------------------------------------------------------------------------------------ the findings: configuration facts only

def _covered(text, path):
    """Whether any CODEOWNERS line names an owner for this path (simple patterns; the last matching line wins)."""
    owner = None
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, owners = line.split()[0], line.split()[1:]
        p = pattern.strip("/")
        if pattern in ("*", "/*", "**") or path == p or path.startswith(p.rstrip("*").rstrip("/") + "/") or (pattern.startswith("*.") and path.endswith(pattern[1:])):
            owner = owners
    return bool(owner)


BLOCKING = {"pull_request", "update", "required_status_checks", "merge_queue", "required_deployments"}
RULE_WORDS = {"deletion": "block deletion", "non_fast_forward": "block force-pushes", "pull_request": "require a pull request", "update": "restrict who may push",
              "required_status_checks": "require status checks", "required_signatures": "require signed commits", "required_linear_history": "require linear history",
              "merge_queue": "require a merge queue", "required_deployments": "require deployments", "creation": "restrict creation"}


def _curl(d, path, grep=None, auth=False, raw=False):
    """A command anyone can run to check a finding: curl, with the address quoted (zsh-safe); a token header only where one is needed."""
    h = (' -H "Authorization: Bearer $GITHUB_TOKEN"' if auth or d["private"] else "") + (' -H "Accept: application/vnd.github.raw"' if raw else "")
    return f'curl -s{"i" if grep and "scopes" in grep else ""}{h} "{API}{path}"' + (f" | grep -i -E '{grep}'" if grep else "")


def _protects(d):
    """What the check could see protecting the branch, in words."""
    rules, prot = d["rules"] or [], d["protection"]
    words = []
    for r in rules:
        w = RULE_WORDS.get(r.get("type"), r.get("type"))
        prm = r.get("parameters") or {}
        if r.get("type") == "pull_request":
            w += f" ({prm.get('required_approving_review_count', 0)} approvals" + (", code-owner review" if prm.get("require_code_owner_review") else "") + ")"
        if w not in words:
            words.append(w)
    if d["classic_enabled"] is False:
        classic = "off (public branch data: protection.enabled = false)"
    elif prot:
        rv = prot.get("required_pull_request_reviews")
        classic = "on: " + (f"pull request with {rv.get('required_approving_review_count', 0)} approvals" + (", code-owner review" if rv.get("require_code_owner_reviews") else "")
                            if rv else "no pull request required") + ("; administrators included" if (prot.get("enforce_admins") or {}).get("enabled") else "; administrators not included")
    elif d["classic_enabled"]:
        classic = "on (its settings are visible only to repository admins)"
    else:
        classic = "unknown"
    return [f"Classic branch protection: {classic}", "Rulesets: " + ("; ".join(words) if words else "none apply")]


def findings(d):
    F, repo, br = [], d["repo"], d["branch"]
    qb = urllib.parse.quote(br, safe="")
    prot, rules = d["protection"], d["rules"] or []
    pr = [x.get("parameters") or {} for x in rules if x.get("type") == "pull_request"]
    rv = (prot or {}).get("required_pull_request_reviews")

    def add(sev, key, title, detail, evidence, verify, fix, expect=""):
        F.append({"severity": sev, "id": key, "title": title, "detail": detail, "evidence": evidence, "verify": verify, "expect": expect, "fix": fix})

    # 1. Is there anything between an agent's commit and the branch?
    if d["protected"] is False and not rules:
        add("HIGH", "branch-unprotected", f"Nothing stops a direct push to `{br}`.",
            f"`{br}` has no branch protection and no ruleset. Any credential with write access, including a token you give a coding agent, can push "
            "straight to it: no pull request, review or check is required." + (f" The repository has a {d['codeowners']['path']} file, but nothing enforces it on `{br}`."
                                                                              if d["codeowners"]["text"] else ""),
            [f"{d['branch_rid']}: protected = false", f"{d['rules_rid']}: no rules apply to this branch"],
            _curl(d, f"/repos/{repo}/branches/{qb}", '"protected"|"enabled"') + "; " + _curl(d, f"/repos/{repo}/rules/branches/{qb}"),
            f"Protect `{br}` (Settings › Rules or Branches): require a pull request with at least one approval, and block force-pushes and deletion.",
            '"protected": false and "enabled": false, then [] (no rules)')
    if d["protected"] and d["classic_enabled"] is False and rules and not BLOCKING & {x.get("type") for x in rules}:
        add("HIGH", "no-pull-request-required", f"Nothing requires a pull request before commits land on `{br}`.",
            f"The only rules on `{br}` are: {'; '.join(_protects(d)[1][len('Rulesets: '):].split('; '))}. Classic branch protection is off, so any credential with write "
            "access, including a token you give a coding agent, can push commits straight to it.",
            [f"{d['branch_rid']}: protected = true, protection.enabled = false", f"{d['rules_rid']}: rule types = {', '.join(sorted({x.get('type') for x in rules}))}"],
            _curl(d, f"/repos/{repo}/branches/{qb}", '"enabled"') + "; " + _curl(d, f"/repos/{repo}/rules/branches/{qb}", '"type"'),
            f"Add a ruleset rule for `{br}` that requires a pull request with at least one approval.",
            f'"enabled": false, then only the types {", ".join(sorted({x.get("type") for x in rules}))}')
    # 2. Review rules, where they are visible (rulesets are visible to anyone who can read the repository; classic settings need admin to read)
    reviews = [rv.get("required_approving_review_count", 0)] if rv else []
    reviews += [x.get("required_approving_review_count", 0) for x in pr]
    if (rv or pr) and max(reviews) == 0 and not ((rv or {}).get("require_code_owner_reviews") or any(x.get("require_code_owner_review") for x in pr)):
        add("MEDIUM", "no-approval-required", f"Pull requests into `{br}` need no approval.",
            "A pull request is required, but with zero approvals and no code-owner review its author, human or agent, can merge it alone.",
            [f"{d['protection_rid'] if rv else d['rules_rid']}: required approvals = 0, code-owner review off"],
            _curl(d, f"/repos/{repo}/rules/branches/{qb}"), "Require at least one approval from someone other than the author.")
    if reviews and max(reviews) >= 1 and not ((rv or {}).get("dismiss_stale_reviews") or (rv or {}).get("require_last_push_approval")
                                              or any(x.get("dismiss_stale_reviews_on_push") or x.get("require_last_push_approval") for x in pr)):
        add("MEDIUM", "approval-survives-new-commits", "An approval stays valid after new commits are pushed.",
            "Neither 'dismiss stale approvals' nor 'require approval of the most recent push' is on, so a change can be altered after a person approved it.",
            [f"{d['protection_rid'] if rv else d['rules_rid']}: stale-approval dismissal off, most-recent-push approval off"],
            _curl(d, f"/repos/{repo}/rules/branches/{qb}"), "Turn on 'Require approval of the most recent reviewable push'.")
    if prot and (prot.get("allow_force_pushes") or {}).get("enabled"):
        add("MEDIUM", "force-push-allowed", f"Force-pushes to `{br}` are allowed.", "Its history can be rewritten.",
            [f"{d['protection_rid']}: allow_force_pushes.enabled = true"], _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"allow_force_pushes"', auth=True), "Block force-pushes.")
    if prot and (prot.get("enforce_admins") or {}).get("enabled") is False:
        add("MEDIUM", "admins-bypass", f"Administrators are not held to `{br}`'s protection.", "'Include administrators' is off.",
            [f"{d['protection_rid']}: enforce_admins.enabled = false"], _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"enforce_admins"', auth=True),
            "Turn on 'Do not allow bypassing the above settings'.")
    # 3. What the credential is permitted to do. A role is not a token's power: classic tokens show their scopes; fine-grained and app tokens do not.
    perms, scopes = d["permissions"] or {}, d["scopes"]
    who = f"`{d['login']}`" if d["login"] else "This credential"
    if perms.get("admin"):
        scope_list = [s.strip() for s in (scopes or "").split(",") if s.strip()]
        usable = "repo" in scope_list or ("public_repo" in scope_list and d["private"] is False)
        if usable:
            add("HIGH", "credential-can-change-protection", f"This credential can change or remove the protection on `{br}`.",
                f"{who} is an admin of {repo}, and the token carries the `{'repo' if 'repo' in scope_list else 'public_repo'}` scope, which lets it use those admin rights: "
                "it can edit or delete branch protection and rulesets. If an agent uses this credential, no branch rule holds against it.",
                [f"{d['repo_rid']}: permissions.admin = true", f"{d['repo_rid']}: response header X-OAuth-Scopes = {scopes}"],
                _curl(d, f"/repos/{repo}", 'x-oauth-scopes|"admin"', auth=True), expect='x-oauth-scopes listing repo, and "admin": true',
                fix="Give the agent its own identity (a machine account or a GitHub App) with write access only, never admin. Keep admin with people, "
                "and run the agent where it cannot reach their credentials.")
        else:
            add("MEDIUM", "account-is-admin", f"{who} belongs to an admin of {repo}; whether this token can use those rights cannot be determined here.",
                "The account is an admin. Fine-grained and app tokens do not reveal their own permissions to a read-only check, so whether this token "
                "could change protection is unknown. If it was created with 'Administration: write', it can.",
                [f"{d['repo_rid']}: permissions.admin = true", f"{d['repo_rid']}: X-OAuth-Scopes = {scopes or 'absent (not a classic token)'}"],
                _curl(d, f"/repos/{repo}", '"admin"', auth=True), "Use an identity that is not an admin for agents.")
    elif perms:
        add("OK", "credential-cannot-change-protection", "This credential cannot change the repository's protections.",
            f"{who} has {'write' if perms.get('push') else 'read'} access, without admin or maintain rights.",
            [f"{d['repo_rid']}: permissions = {json.dumps(perms, sort_keys=True)}"], _curl(d, f"/repos/{repo}", '"admin"|"push"', auth=True), "Nothing to change.")
    # 4. Who owns the files that govern the repository
    co = d["codeowners"]
    if co["text"] is None:
        add("LOW", "no-codeowners", "No code owner is assigned to the workflows or review rules.",
            "There is no CODEOWNERS file, so changes to .github/ (including the workflows that run your checks) cannot require an owner's review. "
            "GitHub's guidance is to name an owner for the CODEOWNERS file itself.", [f"{', '.join(co['rids'])}: no CODEOWNERS file found"],
            _curl(d, f"/repos/{repo}/contents/.github/CODEOWNERS?ref={qb}", '"message"'), "Add .github/CODEOWNERS naming a person for /.github/ and for the file itself.",
            '"message": "Not Found"')
    else:
        bare = [p for p in (".github/workflows/ci.yml", co["path"]) if not _covered(co["text"], p)]
        if bare:
            add("LOW", "governance-files-unowned", "The workflows or review rules have no code owner.",
                f"No CODEOWNERS line covers {', '.join(bare)}, so code-owner review cannot protect the files that govern the repository.",
                [f"{co['rids'][0]}: {co['path']} has no line covering {', '.join(bare)}"], _curl(d, f"/repos/{repo}/contents/{co['path']}?ref={qb}", raw=True),
                "Add lines for /.github/ and for the CODEOWNERS file, owned by a person.")
    F.sort(key=lambda f: ORDER[f["severity"]])
    unknown = []
    if d["protected"] and prot is None and d["classic_enabled"] is not False:
        unknown.append(f"`{br}`'s classic branch-protection settings (HTTP {d['protection_status']}): only repository admins can read them.")
    if not d["authenticated"]:
        unknown.append("What any particular credential may do: run with GITHUB_TOKEN set to your agent's token (read access is enough) to see that.")
    elif not d["permissions"]:
        unknown.append("This credential's role: GitHub did not report one (workflow and app tokens get their permissions from the workflow or app settings).")
    unknown.append("Whether GitHub refuses a change in practice: this check reads settings and never tries one. Ruleset bypass lists are not visible here either.")
    return F, unknown


def build(d):
    F, unknown = findings(d)
    risky = [f for f in F if f["severity"] in ("HIGH", "MEDIUM")]
    if risky:
        verdict = risky[0]["title"]
    elif d["protected"] and d["protection"] is None and d["classic_enabled"] is not False:
        verdict = (f"`{d['branch']}` is protected, but its settings are visible only to repository admins. No gap found in what is visible"
                   + ("." if d["authenticated"] else "; run with your agent's token to see what that credential may do."))
    else:
        verdict = "No authority gap found in what this check can see. See what it could not determine below."
    return {"tool": "Haven Agent Authority Check", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "repository": d["repo"],
            "branch": d["branch"], "credential": (f"{d['login'] or 'a token with no user (for example a workflow token)'} (via {d['via']})" if d["authenticated"]
                                                   else "none: the public view"),
            "verdict": verdict, "protects": _protects(d), "findings": F, "cannot_determine": unknown,
            "counts": {s: sum(1 for f in F if f["severity"] == s) for s in ORDER},
            "limits": "Read-only: only GET requests, nothing changed. Findings are configuration facts read from GitHub; they show what is configured and what a "
                      "credential is permitted to do, not what GitHub will refuse in practice.", "evidence": d["log"]}


def anonymize(rep, d):
    names = {d["repo"]: "<repository>", d["repo"].split("/")[0]: "<owner>"}
    if d["login"]:
        names.setdefault(d["login"], "<credential-user>")
    for m in re.findall(r"@([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)", d["codeowners"]["text"] or ""):
        names.setdefault(m, f"<code-owner-{len(names)}>")
    text = json.dumps(rep, ensure_ascii=False)
    for real in sorted(names, key=len, reverse=True):
        text = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(real)}(?![A-Za-z0-9_-])", names[real], text)
    return json.loads(text)


FOOTER = "Generated by the Haven Agent Authority Check: read-only, no data sent anywhere but GitHub's API."


def markdown(rep):
    L = [f"# Agent Authority Check: {rep['repository']} @ `{rep['branch']}`", "", f"**{rep['verdict']}**", "",
         f"Credential: {rep['credential']} · {rep['generated_at']}", "", f"**What protects `{rep['branch']}`** (as visible to this credential)", ""]
    L += [f"- {x}" for x in rep["protects"]] + [""]
    for f in rep["findings"]:
        L += [f"### {f['severity']}: {f['title']}", "", f["detail"], "", f"- Evidence: {'; '.join(f['evidence'])}",
              f"- Check it yourself: `{f['verify']}`" + (f" (expect {f['expect']})" if f.get("expect") else ""),
              f"- Fix: {f['fix']}", ""]
    L += ["### Cannot be determined from here", ""] + [f"- {x}" for x in rep["cannot_determine"]] + [""]
    L += ["### How this was checked", "", rep["limits"], "", "| | Request | HTTP |", "|---|---|---|"]
    L += [f"| {r['id']} | `GET {r['endpoint']}` | {r['status']} |" for r in rep["evidence"]]
    return "\n".join(L + ["", f"_{FOOTER}_", ""])


def page(rep):
    """The same report as one self-contained HTML file (no external resources), for sending to someone outside GitHub."""
    e = lambda x: html.escape(str(x))
    md = lambda x: re.sub(r"`([^`]+)`", r"<code>\1</code>", re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", e(x)))
    css = (":root{--bg:#fbfaf7;--fg:#1d232b;--mut:#5f6b78;--line:#dde2e8;--card:#fff;--HIGH:#b42318;--MEDIUM:#9a5b00;--LOW:#5f6b78;--OK:#1f7a4d}"
           "@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e8ecf0;--mut:#9aa6b2;--line:#2b323a;--card:#1b2026;--HIGH:#f97066;--MEDIUM:#e6a23c;--LOW:#9aa6b2;--OK:#4cc38a}}"
           "body{background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,sans-serif;margin:0}main{max-width:860px;margin:0 auto;padding:24px 16px 56px}"
           "h1{font-size:1.3rem}.v{font-size:1.15rem;font-weight:700}.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;"
           "padding:12px 16px;margin:12px 0}.s{font-weight:700;font-size:.8rem}.HIGH{color:var(--HIGH)}.MEDIUM{color:var(--MEDIUM)}.LOW{color:var(--LOW)}.OK{color:var(--OK)}"
           "code{font-size:.85em;word-break:break-all}table{border-collapse:collapse;width:100%;font-size:.85rem}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left}"
           ".wrap{overflow-x:auto}")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Agent Authority Check</title>"
           f"<style>{css}</style></head><body><main><h1>Agent Authority Check · {e(rep['repository'])} @ <code>{e(rep['branch'])}</code></h1>"
           f"<p class='v'>{md(rep['verdict'])}</p><p class='mut'>Credential: {e(rep['credential'])} · {e(rep['generated_at'])}</p>"
           f"<div class='card'><strong>What protects <code>{e(rep['branch'])}</code></strong> <span class='mut'>(as visible to this credential)</span><ul>"
           + "".join(f"<li>{e(x)}</li>" for x in rep["protects"]) + "</ul></div>"]
    for f in rep["findings"]:
        out.append(f"<div class='card'><span class='s {f['severity']}'>{f['severity']}</span> <strong>{md(f['title'])}</strong><p>{md(f['detail'])}</p>"
                   f"<p class='mut'>Evidence: {md('; '.join(f['evidence']))}</p><p>Check it yourself: <code>{e(f['verify'])}</code>"
                   + (f" <span class='mut'>(expect {e(f['expect'])})</span>" if f.get("expect") else "") + f"</p><p>Fix: {md(f['fix'])}</p></div>")
    out.append("<h2>Cannot be determined from here</h2><ul>" + "".join(f"<li>{md(x)}</li>" for x in rep["cannot_determine"]) + "</ul>")
    out.append(f"<h2>How this was checked</h2><p>{e(rep['limits'])}</p><div class='wrap'><table><tr><th></th><th>Request</th><th>HTTP</th></tr>")
    out += [f"<tr><td>{r['id']}</td><td><code>GET {e(r['endpoint'])}</code></td><td>{r['status']}</td></tr>" for r in rep["evidence"]]
    out.append(f"</table></div><p class='mut'><em>{e(FOOTER)}</em></p></main></body></html>")
    return "\n".join(out)


def main(argv=None, t=None):
    ap = argparse.ArgumentParser(prog="agent-authority-check", description="Read-only: what stands between an AI agent and this repository's main branch?")
    ap.add_argument("--repo", required=True, help="OWNER/NAME")
    ap.add_argument("--branch", help="the branch to check (default: the repository's default branch)")
    ap.add_argument("--out", help="folder for report.md and report.html (default: ./agent-authority-OWNER-NAME-BRANCH)")
    ap.add_argument("--json", help="also write the report as JSON to this file")
    ap.add_argument("--anonymous", action="store_true", help="use no credential: check a public repository as the public sees it")
    ap.add_argument("--anonymize", action="store_true", help="replace repository, owner and user names with placeholders before sharing")
    ap.add_argument("--summary", action="store_true", help="inside GitHub Actions: add the report to the run summary")
    ap.add_argument("--fail-on-high", action="store_true", help="exit 1 when a HIGH finding exists (for CI)")
    a = ap.parse_args(argv)
    try:
        d = collect(t or transport(a.anonymous), a.repo, a.branch)
    except CheckError as e:
        print(f"agent-authority-check: {e}", file=sys.stderr)
        return 2
    rep = build(d)
    if a.anonymize:
        rep = anonymize(rep, d)
    out = Path(a.out or "agent-authority-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{d['repo']}-{d['branch']}"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(markdown(rep), encoding="utf-8")
    (out / "report.html").write_text(page(rep), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
    if a.summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(markdown(rep) + "\n")
    print(f"{rep['verdict']}\n{rep['counts']['HIGH']} high, {rep['counts']['MEDIUM']} medium, {rep['counts']['LOW']} low, "
          f"{len(rep['cannot_determine'])} thing{'' if len(rep['cannot_determine']) == 1 else 's'} this credential could not see · open {out / 'report.html'}")
    return 1 if a.fail_on_high and rep["counts"]["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
