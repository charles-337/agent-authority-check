"""Evidence framing: what a read actually observed, and what a claim built on it may say.

A limitation of observation is never a fact about the thing observed. A read that failed is not an empty result, a name that did not match
byte for byte is not a missing item, and a summary flag is not the list it summarizes. This module keeps those apart mechanically.

An Observation keeps whether the source answered (status) apart from what it returned (value); asking a FAILED or NOT_ATTEMPTED read for its
value raises Unread, so a failed read cannot drift into [] or None. A Frame records one claim against its evidence: the claim, its state,
the observation status it rests on, the reason when unresolved, the source, the observed value, the scope inspected, when, the evidence ids,
the exact limitation, what the evidence permits saying and what it does not.

The rules, each enforced here and tested in tests/test_evidence_frame.py:
1. KNOWN_FALSE from absence needs a COMPLETE read. FAILED, PARTIAL and NOT_ATTEMPTED reads never give KNOWN_FALSE.
2. Phrase a claim so it is true because of something seen; then presence in a PARTIAL read is still KNOWN_TRUE.
3. Identities are compared after normalization. A match only after normalization is UNKNOWN/NORMALIZATION_MISMATCH until confirmed.
4. A claim that needs scope its parts do not cover is UNKNOWN/UNSUPPORTED_INFERENCE: no claim is broader than its evidence.
5. Known answers that disagree are UNKNOWN/CONFLICTING_OBSERVATIONS unless a recorded precedence rule decides.
6. An observation older than the caller's limit, or with no timestamp when a limit is set, is UNKNOWN/STALE_OBSERVATION.
Severity is not part of a frame: what a confirmed claim is worth is the caller's decision, and an unresolved claim stays unresolved.
Standard library only, so the public check can ship it."""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta

COMPLETE, PARTIAL, FAILED, NOT_ATTEMPTED = "COMPLETE", "PARTIAL", "FAILED", "NOT_ATTEMPTED"
KNOWN_TRUE, KNOWN_FALSE, UNKNOWN = "KNOWN_TRUE", "KNOWN_FALSE", "UNKNOWN"
PERMISSION_DENIED, SOURCE_UNAVAILABLE, RATE_LIMITED = "PERMISSION_DENIED", "SOURCE_UNAVAILABLE", "RATE_LIMITED"
PARTIAL_SCOPE, NORMALIZATION_MISMATCH, STALE_OBSERVATION = "PARTIAL_SCOPE", "NORMALIZATION_MISMATCH", "STALE_OBSERVATION"
UNSUPPORTED_INFERENCE, NOT_OBSERVED, CONFLICTING_OBSERVATIONS = "UNSUPPORTED_INFERENCE", "NOT_OBSERVED", "CONFLICTING_OBSERVATIONS"
PLAN_LIMITED = "PLAN_LIMITED"           # GitHub says the feature needs a paid plan or a public repository: no credential will read it
STATUSES = (COMPLETE, PARTIAL, FAILED, NOT_ATTEMPTED)
STATES = (KNOWN_TRUE, KNOWN_FALSE, UNKNOWN)
REASONS = (PERMISSION_DENIED, SOURCE_UNAVAILABLE, RATE_LIMITED, PARTIAL_SCOPE, NORMALIZATION_MISMATCH, STALE_OBSERVATION,
           UNSUPPORTED_INFERENCE, NOT_OBSERVED, CONFLICTING_OBSERVATIONS, PLAN_LIMITED)
RESOLVE = {
    PERMISSION_DENIED: "Read it again with a credential that has access to it.",
    SOURCE_UNAVAILABLE: "Read it again later: the source did not answer.",
    RATE_LIMITED: "Read it again after the rate limit resets, or with a credential that has a higher limit.",
    PARTIAL_SCOPE: "Read the part of the source that was not read.",
    NORMALIZATION_MISMATCH: "Confirm whether the two spellings name the same item.",
    STALE_OBSERVATION: "Observe it again.",
    UNSUPPORTED_INFERENCE: "Observe the missing scope directly.",
    NOT_OBSERVED: "Observe it.",
    CONFLICTING_OBSERVATIONS: "Read both sources again, or record which one takes precedence and why.",
    PLAN_LIMITED: "GitHub says this needs GitHub Pro or a public repository. Reading it again will not change that: make the repository public, or move it to a plan that includes the feature.",
}


class Unread(Exception):
    """A failed or unattempted read was asked for its value."""


class _Absent:
    def __repr__(self):
        return "ABSENT"


ABSENT = _Absent()   # the value of a COMPLETE read whose answer was "not there" (a 404 for a file), never of a failed one


@dataclass(frozen=True)
class Observation:
    source: str
    status: str
    scope: str
    reason: str | None = None
    detail: str = ""
    observed_at: str | None = None
    evidence: tuple = ()
    _value: object = field(default=None, repr=False)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        if (self.status == COMPLETE) != (self.reason is None) or (self.reason is not None and self.reason not in REASONS):
            raise ValueError("a COMPLETE read has no reason; every other read names one of REASONS")

    @property
    def value(self):
        if self.status not in (COMPLETE, PARTIAL):
            raise Unread(f"{self.source} was not read ({self.status}, {self.reason}: {self.detail}); it has no value, empty or otherwise")
        return self._value


def observed(source, value, scope, *, partial=False, detail="", at=None, evidence=()):
    return Observation(source, PARTIAL if partial else COMPLETE, scope, PARTIAL_SCOPE if partial else None, detail, at, tuple(evidence), value)


def failed(source, reason, scope, *, detail="", at=None, evidence=()):
    return Observation(source, FAILED, scope, reason, detail, at, tuple(evidence))


def not_attempted(source, scope, *, detail="not read"):
    return Observation(source, NOT_ATTEMPTED, scope, NOT_OBSERVED, detail)


def observe_http(source, status, body, headers, scope, *, expect=(dict, list), absent=None, on_404=NOT_OBSERVED, at=None, evidence=()):
    """Classify one HTTP read. `absent` is for a source where 404 is itself the answer ("that file is not there"): the read is then
    COMPLETE with the value ABSENT. Anywhere else a 404 is a failed read with reason `on_404`. A 200 whose body is not of the `expect`
    type is a failed read, and a `Link: rel="next"` header makes the read PARTIAL: the rest was not read."""
    headers, kw = headers or {}, {"at": at, "evidence": evidence}
    detail = "no response" if status is None else f"HTTP {status}"
    message = str((body or {}).get("message", "")).lower() if isinstance(body, dict) else ""
    if status is None or status >= 500:
        return failed(source, SOURCE_UNAVAILABLE, scope, detail=detail, **kw)
    if status == 429 or (status in (401, 403) and (headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers
                                                   or "rate limit" in message)):
        return failed(source, RATE_LIMITED, scope, detail=detail, **kw)
    if status in (401, 403) and ("upgrade to github pro" in message or "make this repository public" in message):
        return failed(source, PLAN_LIMITED, scope, detail=f"{detail}: GitHub says the feature needs GitHub Pro or a public repository", **kw)
    if status in (401, 403):
        return failed(source, PERMISSION_DENIED, scope, detail=detail, **kw)
    if status == 404:
        return observed(source, ABSENT, scope, detail=detail, **kw) if absent else failed(source, on_404, scope, detail=detail, **kw)
    if status != 200:
        return failed(source, NOT_OBSERVED, scope, detail=detail, **kw)
    if not isinstance(body, expect):
        return failed(source, SOURCE_UNAVAILABLE, scope, detail="HTTP 200 with a body of the wrong shape", **kw)
    more = 'rel="next"' in headers.get("link", "")
    return observed(source, body, scope, partial=more, detail=detail + ("; further pages not read" if more else ""), **kw)


@dataclass(frozen=True)
class Frame:
    claim: str
    state: str
    status: str
    reason: str | None
    source: str
    observed: object
    scope: str
    observed_at: str | None
    evidence: tuple
    limitation: str
    permits: str
    does_not_permit: str
    resolve: str = ""

    def to_dict(self):
        return {"claim": self.claim, "state": self.state, "observation_status": self.status, "reason": self.reason, "source": self.source,
                "observed_value": self.observed, "scope_inspected": self.scope, "observed_at": self.observed_at, "evidence": list(self.evidence),
                "limitation": self.limitation, "permits": self.permits, "does_not_permit": self.does_not_permit, "resolve": self.resolve}


def _also(first, beyond):
    return f"{first} {beyond}".strip() if beyond else first


def _older(at, now, max_age):
    if not at:
        return True                                     # freshness that cannot be shown is not assumed
    return now - datetime.fromisoformat(at) > max_age


def frame(claim, obs, test, *, says_true="", says_false="", beyond="", show=None, now=None, max_age: timedelta | None = None, resolve=""):
    """Frame `claim` against one observation. `test(value)` answers True, False, or None when the value cannot settle the claim.
    `says_true` / `says_false` are what a KNOWN_TRUE / KNOWN_FALSE frame permits saying; `beyond` is what no answer from this source
    permits; `show(value)` gives the observed value as JSON; `now` with `max_age` refuses an observation older than the limit."""
    base = {"source": obs.source, "scope": obs.scope, "observed_at": obs.observed_at, "evidence": tuple(obs.evidence), "limitation": obs.detail}
    if obs.status in (FAILED, NOT_ATTEMPTED):
        return Frame(claim, UNKNOWN, obs.status, obs.reason, observed=None, permits=f"Only that {obs.source} was not read ({obs.detail}).",
                     does_not_permit=_also(f"Any answer to: {claim}", beyond), resolve=resolve or RESOLVE[obs.reason], **base)
    shown = show(obs.value) if show else None
    if now is not None and max_age is not None and _older(obs.observed_at, now, max_age):
        return Frame(claim, UNKNOWN, obs.status, STALE_OBSERVATION, observed=shown,
                     permits=f"Only what {obs.source} returned at {obs.observed_at or 'an unrecorded time'}.",
                     does_not_permit=_also(f"Any current answer to: {claim}", beyond), resolve=resolve or RESOLVE[STALE_OBSERVATION],
                     **{**base, "limitation": f"observed at {obs.observed_at or 'an unrecorded time'}, older than {max_age}"})
    answer = test(obs.value)
    if answer is True:
        return Frame(claim, KNOWN_TRUE, obs.status, None, observed=shown, permits=says_true or claim, does_not_permit=beyond, **base)
    if answer is False and obs.status == COMPLETE:
        return Frame(claim, KNOWN_FALSE, obs.status, None, observed=shown, permits=says_false or f"Not so: {claim}", does_not_permit=beyond, **base)
    if answer is False:                                 # absent from a partial read: the unread part may hold it
        return Frame(claim, UNKNOWN, obs.status, PARTIAL_SCOPE, observed=shown, permits=f"Only that the part of {obs.source} that was read does not show it.",
                     does_not_permit=_also(f"That it is not so: {claim}", beyond), resolve=resolve or RESOLVE[PARTIAL_SCOPE], **base)
    return Frame(claim, UNKNOWN, obs.status, UNSUPPORTED_INFERENCE, observed=shown, permits=f"Only what {obs.source} returned; it does not settle this claim.",
                 does_not_permit=_also(f"Any answer to: {claim}", beyond), resolve=resolve or RESOLVE[UNSUPPORTED_INFERENCE], **base)


def nfc(name):
    return unicodedata.normalize("NFC", name)


def present(claim, obs, item, *, key=nfc, same=None, says_true="", says_false="", beyond=""):
    """Is `item` among what `obs` returned? Names are compared after `key` normalizes them. An exact match is KNOWN_TRUE; a match only
    after normalization is KNOWN_TRUE once `same(item, match)` confirms one identity and UNKNOWN/NORMALIZATION_MISMATCH until then;
    no match is KNOWN_FALSE only on a COMPLETE read."""
    if obs.status not in (COMPLETE, PARTIAL):
        return frame(claim, obs, lambda v: None, beyond=beyond)
    matches = [x for x in obs.value if key(x) == key(item)]
    if item in matches or not matches:
        return frame(claim, obs, lambda v: item in matches, says_true=says_true, says_false=says_false, beyond=beyond,
                     show=lambda v: [item] if item in matches else [])
    base = {"source": obs.source, "status": obs.status, "scope": obs.scope, "observed_at": obs.observed_at, "evidence": tuple(obs.evidence),
            "observed": matches, "does_not_permit": beyond}
    if same and any(same(item, m) for m in matches):
        return Frame(claim, KNOWN_TRUE, reason=None, limitation=f"spelled {matches[0]!r} at the source, confirmed the same item",
                     permits=says_true or claim, **base)
    return Frame(claim, UNKNOWN, reason=NORMALIZATION_MISMATCH, limitation=f"{item!r} matches {matches!r} only after normalization",
                 permits=f"Only that {obs.source} holds {matches!r}, which normalizes to the same name as {item!r}.",
                 resolve=RESOLVE[NORMALIZATION_MISMATCH], **{**base, "does_not_permit": _also(f"That {item!r} is missing.", beyond)})


def derive(claim, parts, *, needs, mode="any", says_true="", says_false="", beyond="", resolve=""):
    """A claim built from narrower ones. mode "any": it holds when any part holds, and fails only when every part was settled false.
    mode "all": it holds only when every part holds, and fails when any part was settled false. `parts` maps a scope name to its Frame;
    a scope in `needs` with no Frame makes the claim UNKNOWN/UNSUPPORTED_INFERENCE, so a claim is never broader than its evidence."""
    if mode not in ("any", "all"):
        raise ValueError('mode is "any" or "all"')
    used = [parts[n] for n in needs if parts.get(n) is not None]
    known = " ".join(f.permits for f in used if f.state != UNKNOWN) or "Nothing beyond what each source returned."
    base = {"source": "; ".join(f.source for f in used) or "(none)", "observed": {n: parts[n].state for n in needs if parts.get(n) is not None},
            "scope": " + ".join(needs), "observed_at": min((f.observed_at for f in used if f.observed_at), default=None),
            "evidence": tuple(dict.fromkeys(e for f in used for e in f.evidence))}
    missing = [n for n in needs if parts.get(n) is None]
    if missing:
        return Frame(claim, UNKNOWN, NOT_ATTEMPTED, UNSUPPORTED_INFERENCE, limitation=f"no evidence for: {', '.join(missing)}", permits=known,
                     does_not_permit=_also(f"Any answer to: {claim}", beyond), resolve=resolve or RESOLVE[UNSUPPORTED_INFERENCE], **base)
    decisive = KNOWN_TRUE if mode == "any" else KNOWN_FALSE
    hit = next((f for f in used if f.state == decisive), None)
    if hit:
        return Frame(claim, decisive, hit.status, None, limitation=hit.limitation,
                     permits=(says_true or hit.permits) if mode == "any" else (says_false or f"Not so: {claim}"),
                     does_not_permit=beyond, **base)
    open_ = next((f for f in used if f.state == UNKNOWN), None)
    if open_:
        return Frame(claim, UNKNOWN, open_.status, open_.reason, limitation=open_.limitation, permits=known,
                     does_not_permit=_also(f"Any answer to: {claim}", beyond), resolve=resolve or open_.resolve, **base)
    state = KNOWN_FALSE if mode == "any" else KNOWN_TRUE
    return Frame(claim, state, COMPLETE, None, limitation="",
                 permits=(says_false or f"Not so: {claim}") if mode == "any" else (says_true or claim),
                 does_not_permit=beyond, **base)


def agree(claim, frames, *, precedence=None):
    """One claim read from several sources. Known answers that disagree make it UNKNOWN/CONFLICTING_OBSERVATIONS, unless `precedence`,
    a (source, recorded reason) pair, names the source that wins. With no known answer, the first unresolved frame stands."""
    known = [f for f in frames if f.state != UNKNOWN]
    if not known:
        return frames[0]
    if len({f.state for f in known}) == 1:
        return known[0]
    if precedence:
        win = next(f for f in known if f.source == precedence[0])
        return Frame(**{**win.__dict__, "permits": f"{win.permits} ({win.source} takes precedence: {precedence[1]})"})
    return Frame(claim, UNKNOWN, COMPLETE, CONFLICTING_OBSERVATIONS, source="; ".join(f.source for f in known),
                 observed={f.source: f.state for f in known}, scope=" + ".join(f.scope for f in known),
                 observed_at=min((f.observed_at for f in known if f.observed_at), default=None),
                 evidence=tuple(dict.fromkeys(e for f in known for e in f.evidence)), limitation="the sources disagree",
                 permits=f"Only that {' and '.join(f.source for f in known)} disagree.", does_not_permit=f"Any answer to: {claim}",
                 resolve=RESOLVE[CONFLICTING_OBSERVATIONS])
