"""Agent Authority Check (https://github.com/charles-337/agent-authority-check): a read-only look at what stands between an AI coding agent and a repository's main branch, and what one
credential (for example, the token your agent uses) is permitted to do to those protections.

    python -m change_passport.authority --repo OWNER/NAME [--branch BRANCH] [--out DIR] [--anonymize] [--json FILE] [--fail-on-high]

It needs no admin rights and no write access. With no credential at all it checks any public repository as the public sees it. With
GITHUB_TOKEN or GH_TOKEN set (use the agent's own token to assess the agent), or with a gh login, it also reports what that credential may do.

It only reads: every request is a GET, nothing is changed, and no token is written anywhere. Each finding is a configuration fact with the
request it came from and a command to check it yourself. Seeing a setting is not the power to change it, and a setting is not proof that
GitHub refuses anything in practice: what this check cannot determine, it says. Python standard library only."""
import argparse
from dataclasses import replace
import base64
import hashlib
import html
import fnmatch
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import evidence_frame as EF

API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "OK": 3}
CONTACT = "charles_337@me.com"
GUARD_URL = "https://github.com/charles-337/agent-authority-check#beyond-branch-settings"


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
        try:
            status, body, hdr = self.t.get(path)
        except CheckError:
            if essential:
                raise
            status, body, hdr = None, b"", {}          # no answer at all: framed as SOURCE_UNAVAILABLE, never as an empty result
        rid = f"R{len(self.log) + 1}"
        self.log.append({"id": rid, "method": "GET", "endpoint": path, "status": status, "sha256": hashlib.sha256(body or b"").hexdigest(),
                         "at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
        if status == 401 and essential:
            raise CheckError("GitHub rejected the credential (HTTP 401): check that the token is valid and not expired")
        if status in (403, 429) and hdr.get("x-ratelimit-remaining") == "0" and essential:
            raise CheckError("GitHub's rate limit is used up (unauthenticated: 60 requests an hour); set GITHUB_TOKEN or log in with gh, or try later")
        try:
            data = json.loads(body) if body else None
        except ValueError:
            data = None
        return rid, status, data, hdr

    def observe(self, path, scope, **kw):
        """One read as an evidence_frame Observation: whether GitHub answered stays apart from what it returned."""
        rid, status, data, hdr = self.get(path)
        return EF.observe_http(path, status, data, hdr, scope, at=self.log[-1]["at"], evidence=(rid,), **kw)


def _unread(path, status, data, hdr):
    o = EF.observe_http(path, status, data, hdr, "")
    return f"{o.reason}, {o.detail}"


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
    if s != 200 or not isinstance(r, dict):
        raise CheckError(f"could not read {repo} ({_unread(f'/repos/{repo}', s, r, hdr)})")
    branch = branch or r.get("default_branch")
    b = urllib.parse.quote(branch, safe="")
    path = f"/repos/{repo}/branches/{b}"
    rid_branch, s, br, bh = R.get(path, essential=True)
    if s == 404:
        raise CheckError(f"branch {branch!r} was not found in {repo}")
    if s != 200 or not isinstance(br, dict):                 # nothing below may stand on a branch that was not read
        raise CheckError(f"could not read branch {branch!r} in {repo} ({_unread(path, s, br, bh)}); no report is built without it")
    obs = {"branch": EF.observed(path, br, f"GitHub's data for branch {branch}", at=R.log[-1]["at"], evidence=(rid_branch,)),
           "protection": R.observe(f"{path}/protection", f"classic branch-protection settings of {branch}", expect=dict, on_404=EF.PERMISSION_DENIED),
           "rules": R.observe(f"/repos/{repo}/rules/branches/{b}", f"active ruleset rules for {branch}", expect=list), "codeowners": []}
    co = {"text": None, "path": None, "rids": []}
    for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        o = R.observe(f"/repos/{repo}/contents/{p}?ref={b}", f"{p} on {branch}", expect=dict, absent=True)
        obs["codeowners"].append(o)
        co["rids"].append(o.evidence[0])
        if o.status == EF.COMPLETE and o.value is not EF.ABSENT:
            co = {"text": base64.b64decode(o.value.get("content") or "").decode("utf-8", "replace"), "path": p, "rids": [o.evidence[0]]}
            break
    return {"repo": repo, "branch": branch, "default_branch": r.get("default_branch"), "login": login, "via": t.name, "authenticated": t.authenticated,
            "scopes": hdr.get("x-oauth-scopes"), "repo_rid": rid_repo, "permissions": r.get("permissions"), "private": r.get("private"),
            "protected": br.get("protected"), "classic_enabled": (br.get("protection") or {}).get("enabled"), "branch_rid": rid_branch,
            "protection_rid": obs["protection"].evidence[0], "rules_rid": obs["rules"].evidence[0], "obs": obs, "codeowners": co, "log": R.log}


def _settings(d):
    """Classic protection settings when the admin-only read succeeded; None when they were not read (see d['obs']['protection'])."""
    return d["obs"]["protection"].value if d["obs"]["protection"].status == EF.COMPLETE else None


def _classic_frame(d):
    """Resolve classic protection consistently before deriving any broader claim."""
    o, br = d["obs"], d["branch"]
    on = f"Classic branch protection is enabled on `{br}`"
    return EF.agree(on, [
        EF.frame(on, o["protection"], lambda v: True, says_true=f"Classic protection settings for `{br}` were read.",
                 show=lambda v: sorted(k for k, x in v.items() if isinstance(x, dict))),
        EF.frame(on, o["branch"], lambda v: _bool((v.get("protection") or {}).get("enabled")),
                 says_true=f"GitHub's branch data shows classic protection on for `{br}`.", says_false=f"GitHub's branch data shows classic protection off for `{br}`.",
                 show=lambda v: {"protection.enabled": (v.get("protection") or {}).get("enabled")}),
        EF.frame(on, o["branch"], lambda v: False if v.get("protected") is False else None,
                 says_false=f"GitHub reports `{br}` as not protected, which it documents as not protected by branch protections or rulesets.",
                 show=lambda v: {"protected": v.get("protected")})])


def _classic_off(d):
    return _classic_frame(d).state == EF.KNOWN_FALSE


def _conflicted_claim(claim, conflict):
    return replace(conflict, claim=claim, does_not_permit=f"Any answer to: {claim}")


def _rules_seen(d):
    """The ruleset rules GitHub returned. On a failed read this is empty because nothing was SEEN, not because none exist: every
    conclusion from a rule's absence goes through d['obs']['rules'].status (gap() and _frames())."""
    o = d["obs"]["rules"]
    return o.value if o.status in (EF.COMPLETE, EF.PARTIAL) else ()


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
        if (pattern in ("*", "/*", "**") or path == p or path.startswith(p.rstrip("*").rstrip("/") + "/")
                or (pattern.startswith("*.") and path.endswith(pattern[1:])) or fnmatch.fnmatch(path, p) or fnmatch.fnmatch(path, p + "/*")):
            owner = owners
    return bool(owner)


CHECK_GATE = {"required_status_checks", "merge_queue", "required_deployments"}  # automated gates: each can block a change, but none requires a human review
PUSH_GATE = {"update"}                                                          # restricts who may push to the branch — a partial gate, still not a review
BLOCKING = {"pull_request"} | PUSH_GATE | CHECK_GATE                            # any rule type that stands between a commit and the branch
RULE_WORDS = {"deletion": "block deletion", "non_fast_forward": "block force-pushes", "pull_request": "require a pull request", "update": "restrict who may push",
              "required_status_checks": "require status checks", "required_signatures": "require signed commits", "required_linear_history": "require linear history",
              "merge_queue": "require a merge queue", "required_deployments": "require deployments", "creation": "restrict creation"}


def _curl(d, path, grep=None, auth=False, raw=False):
    """A command anyone can run to check a finding: curl, with the address quoted (zsh-safe); a token header only where one is needed."""
    h = (' -H "Authorization: Bearer $GITHUB_TOKEN"' if auth or d["private"] else "") + (' -H "Accept: application/vnd.github.raw"' if raw else "")
    return f'curl -s{"i" if grep and "scopes" in grep else ""}{h} "{API}{path}"' + (f" | grep -i -E '{grep}'" if grep else "")


PR_RULE = {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": True, "require_code_owner_review": True,
                                                  "require_last_push_approval": True, "required_review_thread_resolution": False}}
REVIEW = ("a pull request with at least one approval, from a code owner where a CODEOWNERS file names one; a new push dismisses earlier approvals, "
          "and the last push must be approved by someone other than whoever pushed it")                # PR_RULE, in words
ADMIN_MERGES = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}]   # role 5 is the repository admin role
SOLO = ("Working alone? Nobody else can approve your pull requests, so run this instead. It lets repository admins, meaning you, merge a pull "
        "request without another approval, and nothing else: no one may push directly, and anyone without admin rights, an agent included, "
        "still needs someone else's approval, which in a repository you run alone means yours. An agent holding an admin's credential could "
        "merge the same way, which is why the credential finding matters.")


def _ruleset(d, name, rules, bypass=None):
    """The command that adds the missing ruleset (POST /repos/{owner}/{repo}/rulesets, fields as GitHub documents them). The reader runs it as a
    repository admin; this check itself never writes."""
    body = {"name": name, "target": "branch", "enforcement": "active", "conditions": {"ref_name": {"include": [f"refs/heads/{d['branch']}"], "exclude": []}},
            "rules": rules, **({"bypass_actors": bypass} if bypass else {})}
    return f'echo {shlex.quote(json.dumps(body, separators=(",", ":")))} | gh api --method POST "repos/{d["repo"]}/rulesets" --input -'


AGENT_IDENTITY = ("Give the agent its own GitHub identity, with write access and never admin: a machine account added as a collaborator with write access, "
                  "or a GitHub App with Contents and Pull requests set to read and write and Administration set to no access. Give the agent only that "
                  "identity's token, keep admin with people, and run the agent where it cannot reach their credentials.")


def _private(d):
    return " On a private repository, GitHub's free plans may not offer rulesets; its answer will say so." if d["private"] else ""


def _rerun(d, token=False):
    return ('GITHUB_TOKEN="$AGENT_TOKEN" ' if token else "") + f"agent-authority-check --repo {d['repo']}" + (
        f" --branch {shlex.quote(d['branch'])}" if d["branch"] != d.get("default_branch") else "")


def _approvals(n):
    return f"{n} approval" + ("" if n == 1 else "s")


def _co(d):
    """A code-owner rule, in words; with no CODEOWNERS file it requires nothing, and says so."""
    return ", code-owner review" + ("" if d["codeowners"]["text"] else " (no CODEOWNERS file, so no owner is required)")


def _protects(d):
    """What the check could see protecting the branch, in words."""
    rules, prot = _rules_seen(d), _settings(d)
    words = []
    for r in rules:
        w = RULE_WORDS.get(r.get("type"), r.get("type"))
        prm = r.get("parameters") or {}
        if r.get("type") == "pull_request":
            w += f" ({_approvals(prm.get('required_approving_review_count', 0))}" + (_co(d) if prm.get("require_code_owner_review") else "") + ")"
        if w not in words:
            words.append(w)
    classic_frame = _classic_frame(d)
    if classic_frame.reason == EF.CONFLICTING_OBSERVATIONS:
        classic = "unknown (CONFLICTING_OBSERVATIONS: the branch data and protection settings disagree)"
    elif d["classic_enabled"] is False:
        classic = "off (public branch data: protection.enabled = false)"
    elif d["protected"] is False:
        classic = "off (public branch data: protected = false)"
    elif prot:
        rv = prot.get("required_pull_request_reviews")
        classic = "on: " + (f"pull request with {_approvals(rv.get('required_approving_review_count', 0))}" + (_co(d) if rv.get("require_code_owner_reviews") else "")
                            if rv else "no pull request required") + ("; administrators included" if (prot.get("enforce_admins") or {}).get("enabled") else "; administrators not included")
    elif d["classic_enabled"]:
        classic = "on (its settings are visible only to repository admins)"
    else:
        classic = "unknown"
    o = d["obs"]["rules"]
    if o.status == EF.COMPLETE:
        listed = "; ".join(words) if words else "none apply"
    elif o.status == EF.PARTIAL:
        listed = ("; ".join(words) + "; " if words else "") + f"more not read ({o.reason}: {o.detail})"
    else:
        listed = f"unknown ({o.reason}: GitHub answered {o.detail})"     # a failed read is never "none apply"
    return [f"Classic branch protection: {classic}", "Rulesets: " + listed]


def _usable(d):
    """Whether the token visibly carries a scope that lets an admin role act (classic tokens only; others do not show their power)."""
    scopes = [s.strip() for s in (d["scopes"] or "").split(",") if s.strip()]
    return "repo" in scopes or ("public_repo" in scopes and d["private"] is False)


def assess(d):
    """Configuration facts as findings. A finding that concludes from something's absence (no rule, no review, no file) is added only when
    every read it needs completed; otherwise it is held as an unresolved claim with the reason (evidence_frame), never reported as fact."""
    F, held, repo, br = [], [], d["repo"], d["branch"]
    qb = urllib.parse.quote(br, safe="")
    prot, rules = _settings(d), _rules_seen(d)
    branch_rules = [x for x in rules if not str(x.get("type") or "").startswith("repository_")]  # repository_* rules govern the repo (visibility, rename, deletion), not pushes to this branch
    pr = [x.get("parameters") or {} for x in rules if x.get("type") == "pull_request"]
    rv = (prot or {}).get("required_pull_request_reviews")

    classic_frame = _classic_frame(d)

    def add(sev, key, title, detail, evidence, verify, fix, expect="", ruleset=None):
        if (classic_frame.reason == EF.CONFLICTING_OBSERVATIONS and sev in ("HIGH", "MEDIUM")
                and key not in ("credential-can-change-protection", "account-is-admin")):
            held.append({"id": key, "severity_if_confirmed": sev, "question": f"whether this claim holds: {title}",
                         "frame": _conflicted_claim(title, classic_frame)})
            return
        name, rs = ruleset or (None, None)
        F.append({"severity": sev, "id": key, "title": title, "detail": detail, "evidence": evidence, "verify": verify, "expect": expect, "fix": fix,
                  "apply": _ruleset(d, name, rs) if rs else None, "apply_solo": _ruleset(d, name, rs, ADMIN_MERGES) if rs else None,
                  "apply_note": _private(d) if rs else ""})

    def unsettled(needs):
        """The first read this conclusion needs that did not complete, or None. Classic settings are settled when the branch data shows
        classic protection off, or when the admin-only read succeeded; CODEOWNERS when all three places answered."""
        for n in needs:
            if n == "classic" and not _classic_off(d) and _settings(d) is None:
                return d["obs"]["protection"]
            if n == "rules" and d["obs"]["rules"].status != EF.COMPLETE:
                return d["obs"]["rules"]
            if n == "codeowners" and d["codeowners"]["text"] is None:
                return next((r for r in d["obs"]["codeowners"] if r.status != EF.COMPLETE), None)
        return None

    def gap(needs, question, sev, key, title, *rest, **kw):
        """An absence-based finding: added when its reads completed, otherwise held, unresolved, with the severity it would have."""
        blocker = unsettled(needs)
        if blocker is None:
            return add(sev, key, title, *rest, **kw)
        held.append({"id": key, "severity_if_confirmed": sev, "question": question, "frame": EF.frame(title, blocker, lambda v: False)})

    # 1. Is there anything between an agent's commit and the branch?
    if d["protected"] is False and not branch_rules:
        gap(("rules",), f"whether anything stops a direct push to `{br}`",
            "HIGH", "branch-unprotected", f"Nothing stops a direct push to `{br}`.",
            f"`{br}` has no branch protection and " + ("only a repository-level ruleset — it governs repository settings such as visibility, renaming or "
            "deletion, not pushes to this branch" if rules else "no ruleset") + ". Any credential with write access, including a token you give a coding "
            "agent, can push straight to it: no pull request, review or check is required." + (f" The repository has a {d['codeowners']['path']} file, but "
            f"nothing enforces it on `{br}`." if d["codeowners"]["text"] else ""),
            [f"{d['branch_rid']}: protected = false", f"{d['rules_rid']}: no rule governs pushes to this branch"
             + (f" (only repository-level rules: {', '.join(sorted({x.get('type') for x in rules}))})" if rules else "")],
            _curl(d, f"/repos/{repo}/branches/{qb}", '"protected"|"enabled"') + "; " + _curl(d, f"/repos/{repo}/rules/branches/{qb}"),
            f"Protect `{br}` (Settings › Rules or Branches): require {REVIEW}; block force-pushes and deletion.",
            '"protected": false and "enabled": false, then no rule whose type governs pushes to this branch',
            (f"Protect {br}", [{"type": "deletion"}, {"type": "non_fast_forward"}, PR_RULE]))
    if d["protected"] and d["classic_enabled"] is False and branch_rules and not BLOCKING & {x.get("type") for x in branch_rules}:
        gap(("rules",), f"whether anything requires a pull request before commits land on `{br}`",
            "HIGH", "no-pull-request-required", f"Nothing requires a pull request before commits land on `{br}`.",
            f"The only rules on `{br}` are: {'; '.join(_protects(d)[1][len('Rulesets: '):].split('; '))}. Classic branch protection is off, so any credential with write "
            "access, including a token you give a coding agent, can push commits straight to it.",
            [f"{d['branch_rid']}: protected = true, protection.enabled = false", f"{d['rules_rid']}: rule types = {', '.join(sorted({x.get('type') for x in branch_rules}))}"],
            _curl(d, f"/repos/{repo}/branches/{qb}", '"protected"|"enabled"') + "; " + _curl(d, f"/repos/{repo}/rules/branches/{qb}", '"type"'),
            f"Add a ruleset rule for `{br}` that requires {REVIEW}.",
            f'"protected": true and "enabled": false, then only the types {", ".join(sorted({x.get("type") for x in rules}))}',
            (f"Require a pull request on {br}", [PR_RULE]))
    types = {x.get("type") for x in branch_rules}
    if d["protected"] and d["classic_enabled"] is False and branch_rules and "pull_request" not in types and (CHECK_GATE | PUSH_GATE) & types:
        gates = ", ".join(RULE_WORDS.get(t, t) for t in sorted((CHECK_GATE | PUSH_GATE) & types))
        gap(("rules",), f"whether changes to `{br}` require a human review",
            "MEDIUM", "no-review-required", f"Changes to `{br}` require no human review.",
            f"`{br}` has rules that {gates}, but none that requires a pull request or an approving review. Classic branch protection is off, so any "
            f"identity that satisfies those rules, including a token you give a coding agent, can land commits on `{br}` with no human review.",
            [f"{d['branch_rid']}: protected = true, protection.enabled = false",
             f"{d['rules_rid']}: rule types = {', '.join(sorted(types))} (no pull_request rule)"],
            _curl(d, f"/repos/{repo}/branches/{qb}", '"protected"|"enabled"') + "; " + _curl(d, f"/repos/{repo}/rules/branches/{qb}", '"type"'),
            f"Add a ruleset rule for `{br}` that requires {REVIEW}.",
            f'"protected": true and "enabled": false, with rule types {", ".join(sorted(types))} but no pull_request',
            (f"Require a pull request on {br}", [PR_RULE]))
    # 2. Review rules, where they are visible (rulesets are visible to anyone who can read the repository; classic settings need admin to read)
    reviews = [rv.get("required_approving_review_count", 0)] if rv else []
    reviews += [x.get("required_approving_review_count", 0) for x in pr]
    if (rv or pr) and max(reviews) == 0 and not ((rv or {}).get("require_code_owner_reviews") or any(x.get("require_code_owner_review") for x in pr)):
        gap(("rules", "classic"), f"whether pull requests into `{br}` need an approval",             # an unread rule set may require one
            "MEDIUM", "no-approval-required", f"Pull requests into `{br}` need no approval.",
            "A pull request is required, but with zero approvals and no code-owner review its author, human or agent, can merge it alone.",
            [f"{d['protection_rid'] if rv else d['rules_rid']}: required approvals = 0, code-owner review off"],
            _curl(d, f"/repos/{repo}/rules/branches/{qb}"), "Require at least one approval from someone other than the author.")
    if reviews and max(reviews) >= 1 and not ((rv or {}).get("dismiss_stale_reviews") or (rv or {}).get("require_last_push_approval")
                                              or any(x.get("dismiss_stale_reviews_on_push") or x.get("require_last_push_approval") for x in pr)):
        gap(("rules", "classic"), f"whether an approval on `{br}` stays valid after new commits",
            "MEDIUM", "approval-survives-new-commits", "An approval stays valid after new commits are pushed.",
            "Neither 'dismiss stale approvals' nor 'require approval of the most recent push' is on, so a change can be altered after a person approved it.",
            [f"{d['protection_rid'] if rv else d['rules_rid']}: stale-approval dismissal off, most-recent-push approval off"],
            _curl(d, f"/repos/{repo}/rules/branches/{qb}"), "Turn on 'Require approval of the most recent reviewable push'.")
    bp = (rv or {}).get("bypass_pull_request_allowances") or {}
    bypass_actors = (bp.get("users") or []) + (bp.get("teams") or []) + (bp.get("apps") or [])
    if rv and bypass_actors:
        add("HIGH", "review-bypass-allowed", f"Listed actors can bypass the required review on `{br}`.",
            f"`{br}` requires a pull-request review, but {len(bypass_actors)} actor(s) are allowed to bypass it (an "
            "'allow specified actors to bypass required pull requests' list of users, teams or apps). Any of them — often an automation "
            "app or a machine account a coding agent uses — can merge into the branch with no approval, so the branch is not as protected "
            "as its review rule suggests.",
            [f"{d['protection_rid']}: required_pull_request_reviews.bypass_pull_request_allowances names {len(bypass_actors)} actor(s)"],
            _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"bypass_pull_request_allowances"', auth=True),
            "Remove the bypass actors, or make sure no identity a coding agent can use is among them.")
    if d["classic_enabled"] and prot is not None and not rv and not pr:
        reqd = "status checks" if (prot.get("required_status_checks") or {}) else "some non-review controls"
        gap(("rules",), f"whether `{br}` requires a human review",                                     # an unread ruleset may require it
            "MEDIUM", "no-review-required-classic", f"Classic protection on `{br}` requires no human review.",
            f"`{br}` has classic branch protection, but it does not require a pull-request review (it requires {reqd}). "
            f"Any identity that satisfies those controls, including a token you give a coding agent, can land commits on "
            f"`{br}` with no human approval.",
            [f"{d['protection_rid']}: required_pull_request_reviews absent while classic protection is enabled"],
            _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"required_pull_request_reviews"', auth=True),
            "Require a pull request with at least one approving review before merging.")
    rule_types = {r.get("type") for r in branch_rules}
    # A ruleset `non_fast_forward` overrides classic allow_force_pushes (GitHub applies both; the stricter wins), so
    # the classic finding must not fire when the ruleset already blocks force-pushes.
    if prot and (prot.get("allow_force_pushes") or {}).get("enabled") and "non_fast_forward" not in rule_types:
        gap(("rules",), f"whether force-pushes to `{br}` are blocked",                                 # an unread ruleset may block them
            "MEDIUM", "force-push-allowed", f"Force-pushes to `{br}` are allowed.", "Its history can be rewritten.",
            [f"{d['protection_rid']}: allow_force_pushes.enabled = true"], _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"allow_force_pushes"', auth=True), "Block force-pushes.")
    # On the ruleset path, `non_fast_forward` blocks force-pushes and `update` restricts who may push (both gate it).
    if d["classic_enabled"] is False and branch_rules and not ({"non_fast_forward", "update"} & rule_types):
        gap(("rules",), f"whether force-pushes to `{br}` are blocked",
            "MEDIUM", "force-push-allowed-ruleset", f"Force-pushes to `{br}` are allowed.",
            "A ruleset protects this branch, but nothing blocks force-pushes (no `non_fast_forward`) and nothing restricts who may push, so its history can be rewritten.",
            [f"{d['rules_rid']}: rule types = {', '.join(sorted(t for t in rule_types if t))}; no non_fast_forward or update; classic protection off"],
            _curl(d, f"/repos/{repo}/rules/branches/{qb}", '"type"'),
            "In the ruleset for this branch, enable 'Block force pushes' (a `non_fast_forward` rule).")
    if prot and (prot.get("enforce_admins") or {}).get("enabled") is False:
        add("MEDIUM", "admins-bypass", f"Administrators are not held to `{br}`'s protection.", "'Include administrators' is off.",
            [f"{d['protection_rid']}: enforce_admins.enabled = false"], _curl(d, f"/repos/{repo}/branches/{qb}/protection", '"enforce_admins"', auth=True),
            "Turn on 'Do not allow bypassing the above settings'.")
    # 3. What the credential is permitted to do. A role is not a token's power: classic tokens show their scopes; fine-grained and app tokens do not.
    perms, scopes = d["permissions"] or {}, d["scopes"]
    who = f"`{d['login']}`" if d["login"] else "This credential"
    if perms.get("admin"):
        scope_list = [s.strip() for s in (scopes or "").split(",") if s.strip()]
        if _usable(d):
            add("HIGH", "credential-can-change-protection", f"This credential can change or remove the protection on `{br}`.",
                f"{who} is an admin of {repo}, and the token carries the `{'repo' if 'repo' in scope_list else 'public_repo'}` scope, which lets it use those admin rights: "
                "it can edit or delete branch protection and rulesets. If an agent uses this credential, no branch rule holds against it.",
                [f"{d['repo_rid']}: permissions.admin = true", f"{d['repo_rid']}: response header X-OAuth-Scopes = {scopes}"],
                _curl(d, f"/repos/{repo}", 'x-oauth-scopes|"admin"', auth=True), expect='x-oauth-scopes listing repo, and "admin": true',
                fix=AGENT_IDENTITY)
        else:
            add("MEDIUM", "account-is-admin", f"{who} belongs to an admin of {repo}; whether this token can use those rights cannot be determined here.",
                "The account is an admin. Fine-grained and app tokens do not reveal their own permissions to a read-only check, so whether this token "
                "could change protection is unknown. If it was created with 'Administration: write', it can.",
                [f"{d['repo_rid']}: permissions.admin = true", f"{d['repo_rid']}: X-OAuth-Scopes = {scopes or 'absent (not a classic token)'}"],
                _curl(d, f"/repos/{repo}", '"admin"', auth=True), AGENT_IDENTITY)
    elif perms:
        add("OK", "credential-cannot-change-protection", "This credential cannot change the repository's protections.",
            f"{who} has {'write' if perms.get('push') else 'read'} access, without the admin rights needed to change protection.",
            [f"{d['repo_rid']}: permissions = {json.dumps(perms, sort_keys=True)}"], _curl(d, f"/repos/{repo}", '"admin"|"push"', auth=True), "Nothing to change.")
    # 4. Who owns the files that govern the repository
    co = d["codeowners"]
    if co["text"] is None:
        asks = (rv or {}).get("require_code_owner_reviews") or any(x.get("require_code_owner_review") for x in pr)
        gap(("codeowners",), "whether a CODEOWNERS file exists",
            "LOW", "no-codeowners", "No code owner is assigned to the workflows or review rules.",
            "There is no CODEOWNERS file, so " + (f"the rule on `{br}` that asks for code-owner review requires nothing, and " if asks else "")
            + "changes to .github/ (including the workflows that run your checks) cannot require an owner's review. "
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
    o = d["obs"]["rules"]
    if o.status != EF.COMPLETE:
        unknown.append(f"Which rulesets apply to `{br}` ({o.reason}: GitHub answered {o.detail}): ruleset rules are shown only as far as they were read, "
                       "and nothing here is concluded from a rule's absence. " + (EF.RESOLVE[EF.PLAN_LIMITED] if o.reason == EF.PLAN_LIMITED else "Run the check again to read them."))
    co_open = next((r for r in d["obs"]["codeowners"] if r.status != EF.COMPLETE), None) if d["codeowners"]["text"] is None else None
    if co_open:
        unknown.append(f"Whether a CODEOWNERS file exists ({co_open.reason}: GitHub answered {co_open.detail} for {co_open.source}).")
    if d["protected"] and prot is None and d["classic_enabled"] is not False:
        unknown.append(f"`{br}`'s classic branch-protection settings ({d['obs']['protection'].detail}): only repository admins can read them.")
    if not d["authenticated"]:
        unknown.append("What any particular credential may do: run with GITHUB_TOKEN set to your agent's token (read access is enough) to see that.")
    elif not d["permissions"]:
        unknown.append("This credential's role: GitHub did not report one (workflow and app tokens get their permissions from the workflow or app settings).")
    unknown.append("Whether GitHub refuses a change in practice: this check reads settings and never tries one. A ruleset's bypass list — which actors may skip its "
                   "pull-request rule — is not returned by GitHub's rules API, so ruleset bypass actors are not visible here (classic bypass allowances, when readable, are reported above).")
    return F, unknown, held


def findings(d):
    """(findings, cannot_determine), as before; assess() also returns the claims held back as unresolved."""
    F, unknown, _ = assess(d)
    return F, unknown


def _bool(x):
    return x if isinstance(x, bool) else None


def _frames(d):
    """The claims the verdict rests on, each framed against what was actually read (evidence_frame): known, or unknown and why."""
    o, br, repo = d["obs"], d["branch"], d["repo"]
    flag = EF.frame(f"GitHub reports `{br}` as protected", o["branch"], lambda v: _bool(v.get("protected")),
                    says_true=f"GitHub's branch data reports `{br}` as protected.", says_false=f"GitHub's branch data reports `{br}` as not protected.",
                    beyond="Which rules, bypasses or other controls apply: the flag is GitHub's summary of the branch, not a list of them.",
                    show=lambda v: {"protected": v.get("protected")})
    classic = _classic_frame(d)
    governs = f"A ruleset rule governs pushes to `{br}`"
    rules = EF.frame(governs, o["rules"], lambda v: any(not str(x.get("type") or "").startswith("repository_") for x in v),
                     says_true=f"At least one ruleset rule applies to pushes to `{br}`.",
                     says_false=f"No ruleset rule applies to pushes to `{br}`: GitHub's rules endpoint answered, and every rule it returned was read.",
                     beyond="Who may bypass a ruleset: GitHub's rules endpoint does not return bypass lists.", show=lambda v: sorted({x.get("type") for x in v}))
    prq = f"A pull request is required before changes land on `{br}`"
    classic_off = _classic_off(d)
    classic_pr = (EF.frame(prq, o["branch"], lambda v: False,
                           says_false=f"Classic protection is off on `{br}`, so it requires nothing.")
                  if classic_off else
                  EF.frame(prq, o["protection"], lambda v: bool(v.get("required_pull_request_reviews")),
                           says_true=f"Classic protection on `{br}` requires a pull request.",
                           says_false=f"Classic protection on `{br}` does not require a pull request."))
    if classic.reason == EF.CONFLICTING_OBSERVATIONS:
        classic_pr = _conflicted_claim(prq, classic)
    pr = EF.derive(prq, {
        "rulesets": EF.frame(prq, o["rules"], lambda v: any(x.get("type") == "pull_request" for x in v),
                             says_true=f"A ruleset requires a pull request on `{br}`.", says_false=f"No ruleset requires a pull request on `{br}`."),
        "classic protection": classic_pr}, needs=("rulesets", "classic protection"))
    cq = "A CODEOWNERS file exists"
    reads, co = o["codeowners"], d["codeowners"]
    if co["text"] is not None:
        codeowners = EF.frame(cq, next(r for r in reads if co["rids"][0] in r.evidence), lambda v: True, says_true=f"{co['path']} exists.",
                              show=lambda v: co["path"])
    elif all(r.status == EF.COMPLETE for r in reads):
        codeowners = EF.frame(cq, EF.observed(" + ".join(r.source for r in reads), EF.ABSENT, "the three places GitHub looks for CODEOWNERS",
                                              at=reads[0].observed_at, evidence=tuple(e for r in reads for e in r.evidence)),
                              lambda v: False, says_false="No CODEOWNERS file exists in any of the three places GitHub looks.", show=lambda v: "ABSENT")
    else:
        codeowners = EF.frame(cq, next(r for r in reads if r.status != EF.COMPLETE), lambda v: None)
    can = f"This credential can change or remove `{br}`'s protection"
    beyond = "Whether GitHub refuses a change in practice: this check reads settings and never tries one."
    if not d["authenticated"]:
        cred = EF.frame(can, EF.not_attempted(f"/repos/{repo}", "this credential's role", detail="no credential was used"), lambda v: None,
                        beyond=beyond, resolve="Run again with GITHUB_TOKEN set to your agent's token (read access is enough).")
    elif not d["permissions"]:
        cred = EF.frame(can, EF.failed(f"/repos/{repo}", EF.NOT_OBSERVED, "this credential's role", detail="GitHub reported no role for this credential",
                                       evidence=(d["repo_rid"],)), lambda v: None, beyond=beyond,
                        resolve="Read the permissions in the workflow or app settings that issued the token.")
    else:
        cred = EF.frame(can, EF.observed(f"/repos/{repo}", {"permissions": d["permissions"], "scopes": d["scopes"]},
                                         "the role and token scopes GitHub reported for this credential", evidence=(d["repo_rid"],)),
                        lambda v: (True if _usable(d) else None) if v["permissions"].get("admin") else False,
                        says_true="The credential is a repository admin and its token carries a scope that uses those rights.",
                        says_false="The credential has no admin role on the repository.", beyond=beyond, show=lambda v: v,
                        resolve="Check the token's own settings: one created with 'Administration: write' can change protection.")
    bq = f"Someone can bypass the review required on `{br}`"
    bypass_classic = (EF.frame(bq, o["branch"], lambda v: False, says_false="Classic protection is off, so there is no classic bypass list.")
                      if classic_off else
                      EF.frame(bq, o["protection"], lambda v: bool(((v.get("required_pull_request_reviews") or {}).get("bypass_pull_request_allowances") or {})
                                                                    and any(((v["required_pull_request_reviews"]["bypass_pull_request_allowances"]).get(k))
                                                                            for k in ("users", "teams", "apps"))),
                               says_true=f"Classic protection on `{br}` lists actors who may bypass its required review.",
                               says_false=f"Classic protection on `{br}` lists no one who may bypass its review."))
    if classic.reason == EF.CONFLICTING_OBSERVATIONS:
        bypass_classic = _conflicted_claim(bq, classic)
    r = o["rules"]
    if r.status == EF.COMPLETE and not any(x.get("type") == "pull_request" for x in r.value):
        bypass_rules = EF.frame(bq, r, lambda v: False, says_false="No ruleset requires a review, so no ruleset review can be bypassed.")
    elif r.status in (EF.COMPLETE, EF.PARTIAL):
        bypass_rules = EF.frame(bq, EF.observed(r.source, r.value, "ruleset bypass lists", partial=True, at=r.observed_at, evidence=r.evidence,
                                                detail="GitHub's rules endpoint does not return who may bypass a ruleset"), lambda v: False,
                                resolve="Read the ruleset's bypass list in Settings › Rules, as a repository admin.")
    else:
        bypass_rules = EF.frame(bq, r, lambda v: None)
    bypass = EF.derive(bq, {"classic bypass list": bypass_classic, "ruleset bypass lists": bypass_rules},
                       needs=("classic bypass list", "ruleset bypass lists"))
    return [("branch-protected-flag", flag), ("classic-protection", classic), ("rulesets", rules), ("pull-request-required", pr),
            ("codeowners", codeowners), ("credential-can-change-protection", cred), ("review-bypass", bypass)]


def build(d):
    F, unknown, held = assess(d)
    core = _frames(d)
    frames = ([{"id": k, **f.to_dict(), "severity_if_confirmed": None} for k, f in core]
              + [{"id": h["id"], **h["frame"].to_dict(), "severity_if_confirmed": h["severity_if_confirmed"]} for h in held])
    pr = dict(core)["pull-request-required"]
    risky = [f for f in F if f["severity"] in ("HIGH", "MEDIUM")]
    if risky:
        verdict = risky[0]["title"]
    elif held or pr.state == EF.UNKNOWN:                  # unknown is never "no gap found"
        q, fr = (held[0]["question"], held[0]["frame"]) if held else (f"whether a pull request is required before changes land on `{d['branch']}`", pr)
        verdict = f"{q[0].upper()}{q[1:]} cannot be determined here ({fr.reason}: {fr.limitation}). See what is known and what is not, below."
    elif d["protected"] and _settings(d) is None and d["classic_enabled"] is not False:
        verdict = (f"`{d['branch']}` is protected, but its settings are visible only to repository admins. No gap found in what is visible"
                   + ("." if d["authenticated"] else "; run with your agent's token to see what that credential may do."))
    else:
        verdict = "No authority gap found in what this check can see. See what it could not determine below."
    recheck = [f"Run the check again: `{_rerun(d)}`. The finding you fixed should be gone."] if risky else []
    if {"credential-can-change-protection", "account-is-admin"} & {f["id"] for f in F}:
        recheck.append(f"With the agent's new token: `{_rerun(d, token=True)}`. A machine account with write access should show "
                       "\"This credential cannot change the repository's protections.\"")
    return {"tool": "Haven Agent Authority Check", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "repository": d["repo"],
            "branch": d["branch"], "credential": (f"{d['login'] or 'a token with no user (for example a workflow token)'} (via {d['via']})" if d["authenticated"]
                                                   else "none (the public view)"),
            "verdict": verdict, "protects": _protects(d), "findings": F, "recheck": recheck, "cannot_determine": unknown,
            "counts": {s: sum(1 for f in F if f["severity"] == s) for s in ORDER},
            "frames": frames, "unresolved": sum(1 for f in frames if f["state"] == EF.UNKNOWN),
            "limits": "Read-only: only GET requests, nothing changed. Findings are configuration facts read from GitHub; they show what is configured and what a "
                      "credential is permitted to do, not what GitHub will refuse in practice.", "evidence": d["log"]}


def anonymize(rep, d):
    names = {d["repo"]: "<repository>", d["repo"].split("/")[0]: "<owner>"}
    if d["login"]:
        names.setdefault(d["login"], "<credential-user>")
    if d.get("branch"):                              # branch names routinely carry teammate handles (user/feature) or internal codenames
        names.setdefault(d["branch"], "<branch>")
        qb = urllib.parse.quote(d["branch"], safe="")   # the url-quoted form also appears in the curl commands
        if qb != d["branch"]:
            names.setdefault(qb, "<branch>")
    for m in re.findall(r"@([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)", d["codeowners"]["text"] or ""):
        names.setdefault(m, f"<code-owner-{len(names)}>")
    text = json.dumps(rep, ensure_ascii=False)
    for real in sorted(names, key=len, reverse=True):
        text = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(real)}(?![A-Za-z0-9_-])", names[real], text)
    return json.loads(text)


FOOTER = "Generated by the Haven Agent Authority Check: read-only, no data sent anywhere but GitHub's API."
APPLY = "Apply it as a repository admin, logged in with `gh` (this check itself changes nothing):"
BEYOND = ("This check is free. Haven, which publishes it, also builds a guard for coding agents, because branch rules treat every pull request the "
          "same, whoever wrote it: one authority rule per agent (what it may merge itself, what needs a person's signed approval of that exact change, "
          "and what it may never touch), a check inside the agent's session that stops a protected action before it runs, and a receipt for every decision.")
BEYOND_LAST = f"Shown in a sandbox, not yet on GitHub. Details: {GUARD_URL}"
DIAGNOSTIC_OFFER = ("If you would rather have it mapped for your repository — exactly what your coding agent's credential can do to this branch, whether it "
                    "could switch the rules off, who can bypass them, the fix, and a re-check under the agent's own read-only token confirming the finding is "
                    "gone and that token cannot switch the rules off — that is Haven's opt-in Agent Authority Diagnostic: fixed $1,500, five business days "
                    "after access and scope are agreed, invoiced on delivery.")


def _beyond(rep):
    """The last section: what branch settings cannot do, the guard, and — when there is something to fix — the opt-in paid diagnostic.
    Fixing the findings comes first, because the guard holds only where the agent's own credential cannot switch the branch rules off."""
    actionable = bool((rep.get("counts") or {}).get("HIGH") or (rep.get("counts") or {}).get("MEDIUM"))
    first = ("Fix the findings above first: the guard does not replace branch rules, and it holds only where the agent's own credential cannot "
             "switch them off. " if actionable else "")
    last = (DIAGNOSTIC_OFFER + " " + BEYOND_LAST) if actionable else BEYOND_LAST
    return first + BEYOND, last


def epistemic(rep):
    """The 'what is known and what is not' section, from rep['frames'] alone, so every output says the same thing: (heading, lines)."""
    fr = rep.get("frames") or []
    known = [f for f in fr if f["state"] != "UNKNOWN"]
    open_ = [f for f in fr if f["state"] == "UNKNOWN"]
    sev = lambda f: f" (would be {f['severity_if_confirmed']} if confirmed)" if f.get("severity_if_confirmed") else ""
    return [("Known", [f"{f['permits']} [{f['state']}]" for f in known] or ["Nothing settled."]),
            ("Unknown", [f"{f['claim']}{sev(f)}" for f in open_] or ["Nothing within this check's scope."]),
            ("Why unknown", [f"{f['claim']}: {f['reason']} — {f['limitation']} ({f['source']})" for f in open_]),
            ("Safe conclusion", list(dict.fromkeys(f["permits"] for f in open_))),
            ("Claims this evidence does not support", list(dict.fromkeys(f["does_not_permit"] for f in fr if f["does_not_permit"]))),
            ("How to resolve the uncertainty", list(dict.fromkeys(f["resolve"] for f in open_ if f["resolve"])))]


def markdown(rep):
    L = [f"# Agent Authority Check: {rep['repository']} @ `{rep['branch']}`", "", f"**{rep['verdict']}**", "",
         f"Credential: {rep['credential']} · {rep['generated_at']}", "", f"**What protects `{rep['branch']}`** (as visible to this credential)", ""]
    L += [f"- {x}" for x in rep["protects"]] + [""]
    for f in rep["findings"]:
        L += [f"### {f['severity']}: {f['title']}", "", f["detail"], "", f"- Evidence: {'; '.join(f['evidence'])}",
              f"- Check it yourself: `{f['verify']}`" + (f" (expect {f['expect']})" if f.get("expect") else ""),
              f"- Fix: {f['fix']}", ""]
        if f.get("apply"):
            L += [APPLY, "", "```bash", f["apply"], "```", "", SOLO, "", "```bash", f["apply_solo"], "```", ""]
            L += [f["apply_note"].strip(), ""] if f.get("apply_note") else []
    if rep.get("recheck"):
        L += ["### After a fix", ""] + [f"- {x}" for x in rep["recheck"]] + [""]
    L += ["### Cannot be determined from here", ""] + [f"- {x}" for x in rep["cannot_determine"]] + [""]
    L += ["### What is known and what is not", ""]
    for head, lines in epistemic(rep):
        L += [f"**{head}**", ""] + ([f"- {x}" for x in lines] or ["- Nothing."]) + [""]
    L += ["### How this was checked", "", rep["limits"], "", "| | Request | HTTP |", "|---|---|---|"]
    L += [f"| {r['id']} | `GET {r['endpoint']}` | {r['status'] or 'no response'} |" for r in rep["evidence"]]
    lead, last = _beyond(rep)
    L += ["", "### Beyond branch settings", "", lead, "", last]
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
           ".wrap{overflow-x:auto}pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;white-space:pre-wrap;word-break:break-all}"
           "a{color:inherit}")
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Agent Authority Check</title>"
           f"<style>{css}</style></head><body><main><h1>Agent Authority Check · {e(rep['repository'])} @ <code>{e(rep['branch'])}</code></h1>"
           f"<p class='v'>{md(rep['verdict'])}</p><p class='mut'>Credential: {e(rep['credential'])} · {e(rep['generated_at'])}</p>"
           f"<div class='card'><strong>What protects <code>{e(rep['branch'])}</code></strong> <span class='mut'>(as visible to this credential)</span><ul>"
           + "".join(f"<li>{e(x)}</li>" for x in rep["protects"]) + "</ul></div>"]
    for f in rep["findings"]:
        out.append(f"<div class='card'><span class='s {f['severity']}'>{f['severity']}</span> <strong>{md(f['title'])}</strong><p>{md(f['detail'])}</p>"
                   f"<p class='mut'>Evidence: {md('; '.join(f['evidence']))}</p><p>Check it yourself: <code>{e(f['verify'])}</code>"
                   + (f" <span class='mut'>(expect {e(f['expect'])})</span>" if f.get("expect") else "") + f"</p><p>Fix: {md(f['fix'])}</p>"
                   + (f"<p>{md(APPLY)}</p><pre><code>{e(f['apply'])}</code></pre><p>{md(SOLO)}</p><pre><code>{e(f['apply_solo'])}</code></pre>"
                      + (f"<p class='mut'>{md(f['apply_note'].strip())}</p>" if f.get("apply_note") else "") if f.get("apply") else "") + "</div>")
    if rep.get("recheck"):
        out.append("<h2>After a fix</h2><ul>" + "".join(f"<li>{md(x)}</li>" for x in rep["recheck"]) + "</ul>")
    out.append("<h2>Cannot be determined from here</h2><ul>" + "".join(f"<li>{md(x)}</li>" for x in rep["cannot_determine"]) + "</ul>")
    out.append("<h2>What is known and what is not</h2>" + "".join(
        f"<h3>{e(head)}</h3><ul>" + ("".join(f"<li>{md(x)}</li>" for x in lines) or "<li>Nothing.</li>") + "</ul>" for head, lines in epistemic(rep)))
    out.append(f"<h2>How this was checked</h2><p>{e(rep['limits'])}</p><div class='wrap'><table><tr><th></th><th>Request</th><th>HTTP</th></tr>")
    out += [f"<tr><td>{r['id']}</td><td><code>GET {e(r['endpoint'])}</code></td><td>{r['status'] or 'no response'}</td></tr>" for r in rep["evidence"]]
    lead, last = _beyond(rep)
    link = f"<a href='{e(GUARD_URL)}'>{e(GUARD_URL)}</a>"
    out.append(f"</table></div><h2>Beyond branch settings</h2><p>{md(lead)}</p><p>{md(last).replace(e(GUARD_URL), link)}</p>")
    out.append(f"<p class='mut'><em>{e(FOOTER)}</em></p></main></body></html>")
    return "\n".join(out)


def passport_starter(d):
    """A Change Passport policy tailored to this repository, so the check's finding flows straight into the fix. Every change into the
    assessed branch needs an approval, the common coding agents are recognised at A3 (may prepare on their own branch, never merge on their
    own), the governance paths need two approvers, and secrets are refused outright. The reader sets a real approver and runs
    `change-passport init`. It is a fixed template written as plain text, so the check stays standard-library only; it parses under
    policy.parse and any YAML reader."""
    q = lambda s: "'" + str(s).replace("'", "''") + "'"       # single-quoted YAML scalar, apostrophes doubled
    return (f"# Haven Change Passport starter for {d['repo']} (branch {d['branch']}), generated by agent-authority-check.\n"
            f"# It closes the gap this check reports: every change into {d['branch']} needs an approval, and no agent merges on its own.\n"
            "# This is a proposed policy template. To enforce it, set up the Haven Change Passport guard - see the 'Beyond branch settings' section of the README.\n"
            "\nversion: 1\n"
            f"target_branches: [{q(d['branch'])}]\n"
            "agents:\n"
            "  - name: Claude Code\n    trailers: ['Co-Authored-By: Claude']\n    branch_prefixes: ['claude/']\n    authority: A3\n"
            "  - name: Devin\n    branch_prefixes: ['devin/']\n    authority: A3\n"
            "  - name: Cursor\n    branch_prefixes: ['cursor/']\n    authority: A3\n"
            "  - name: Codex\n    branch_prefixes: ['codex/']\n    authority: A3\n"
            "scope: all_changes\n"
            "approvers: [repository-owner]\n"
            "second_approval_paths:\n  - '.haven/**'\n  - '.github/**'\n"
            "refuse_paths:\n  - 'secrets/**'\n"
            "autonomous_paths: []\n"
            "test_command: null\n")


def main(argv=None, t=None):
    ap = argparse.ArgumentParser(prog="agent-authority-check", description="Read-only: what stands between an AI agent and this repository's main branch?")
    ap.add_argument("--repo", required=True, help="OWNER/NAME")
    ap.add_argument("--branch", help="the branch to check (default: the repository's default branch)")
    ap.add_argument("--out", help="folder for report.md and report.html (default: ./agent-authority-OWNER-NAME-BRANCH)")
    ap.add_argument("--json", help="also write the report as JSON to this file")
    ap.add_argument("--anonymous", action="store_true", help="use no credential: check a public repository as the public sees it")
    ap.add_argument("--anonymize", action="store_true", help="replace repository, owner and user names with placeholders before sharing")
    ap.add_argument("--emit-passport", dest="emit_passport", metavar="PATH", help="also write a Change Passport policy starter tailored to this repository (feeds change-passport init)")
    ap.add_argument("--summary", action="store_true", help="inside GitHub Actions: add the report to the run summary")
    ap.add_argument("--fail-on-high", action="store_true", help="exit 1 when a HIGH finding exists, and 3 when none is confirmed but a claim that "
                    "would be HIGH could not be settled (for CI: unknown is neither a pass nor a HIGH)")
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
    if a.emit_passport:
        Path(a.emit_passport).write_text(passport_starter(d), encoding="utf-8")
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=1, ensure_ascii=False), encoding="utf-8")
    if a.summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(markdown(rep) + "\n")
    print(f"{rep['verdict']}\n{rep['counts']['HIGH']} high, {rep['counts']['MEDIUM']} medium, {rep['counts']['LOW']} low, "
          f"{rep['unresolved']} unresolved, "
          f"{len(rep['cannot_determine'])} thing{'' if len(rep['cannot_determine']) == 1 else 's'} this credential could not see · open {out / 'report.html'}")
    if a.fail_on_high and rep["counts"]["HIGH"]:
        return 1
    if a.fail_on_high and any(f["state"] == "UNKNOWN" and f.get("severity_if_confirmed") == "HIGH" for f in rep["frames"]):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
