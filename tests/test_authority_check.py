"""The Agent Authority Check against simulated GitHub responses: what it finds, what it says it cannot determine, how it fails, and that it
only reads and never leaks a credential."""
import base64
import io
import json
import os
import shlex
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from change_passport import authority as A  # noqa: E402

REPO = "acme/app"


class Fake:
    """Answers GETs from a table of endpoint -> (status, json body, headers); anything not in the table is a 404."""

    def __init__(self, table, authenticated=True):
        self.table, self.authenticated, self.name, self.calls = table, authenticated, "a fake", []

    def get(self, path):
        self.calls.append(path)
        status, body, hdr = self.table.get(path, (404, {"message": "Not Found"}, {}))
        return status, json.dumps(body).encode(), hdr


def codeowners(text):
    return (200, {"content": base64.b64encode(text.encode()).decode()}, {})


def repo(perms=None, scopes=None, private=False):
    return (200, {"default_branch": "main", "private": private, **({"permissions": perms} if perms else {})}, {"x-oauth-scopes": scopes} if scopes else {})


def run(table, authenticated=True, extra=()):
    with tempfile.TemporaryDirectory() as d:
        code = A.main(["--repo", REPO, "--out", d, "--json", f"{d}/r.json", *extra], t=Fake(table, authenticated))
        rep = json.loads(Path(d, "r.json").read_text()) if Path(d, "r.json").exists() else None
        files = {p.name: p.read_text() for p in Path(d).iterdir()}
    return code, rep, files


class Findings(unittest.TestCase):
    def test_public_unprotected_repository_with_no_credential(self):
        code, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}),
                                f"/repos/{REPO}/branches/main/protection": (401, {}, {}), f"/repos/{REPO}/rules/branches/main": (200, [], {})}, authenticated=False)
        self.assertEqual(code, 0)
        self.assertEqual(rep["verdict"], "Nothing stops a direct push to `main`.")
        self.assertEqual([f["id"] for f in rep["findings"]], ["branch-unprotected", "no-codeowners"])
        self.assertTrue(any("GITHUB_TOKEN" in u for u in rep["cannot_determine"]))          # says what it could not see, and how to see it
        self.assertEqual(rep["credential"], "none (the public view)")
        self.assertIn("report.md", files)
        self.assertIn("report.html", files)

    def test_admin_with_a_classic_repo_scope_can_change_protection(self):
        _, rep, _ = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": True, "push": True}, "repo, read:org"),
                         f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}),
                         f"/repos/{REPO}/branches/main/protection": (200, {"enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
                                                                            "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True}}, {}),
                         f"/repos/{REPO}/rules/branches/main": (200, [], {}), f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("/.github/ @lead\n")})
        self.assertEqual(rep["findings"][0]["id"], "credential-can-change-protection")
        self.assertEqual(rep["findings"][0]["severity"], "HIGH")
        self.assertTrue(any("X-OAuth-Scopes = repo, read:org" in e for e in rep["findings"][0]["evidence"]))

    def test_an_admin_account_behind_a_fine_grained_token_is_not_claimed_to_be_able_to_change_anything(self):
        _, rep, _ = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": True, "push": True}),
                         f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, [], {})})
        ids = [f["id"] for f in rep["findings"]]
        self.assertNotIn("credential-can-change-protection", ids)                           # seeing a role is not the power to use it
        self.assertIn("account-is-admin", ids)
        self.assertIn("cannot be determined", [f for f in rep["findings"] if f["id"] == "account-is-admin"][0]["title"])

    def test_a_well_configured_branch_with_a_write_only_agent(self):
        rules = [{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                         "require_last_push_approval": True, "dismiss_stale_reviews_on_push": True}}, {"type": "non_fast_forward"}]
        code, rep, _ = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "maintain": False, "push": True, "pull": True}, "repo"),
                            f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/branches/main/protection": (404, {}, {}),
                            f"/repos/{REPO}/rules/branches/main": (200, rules, {}),
                            f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("* @lead\n/.github/ @lead @sec\n")}, extra=["--fail-on-high"])
        self.assertEqual(code, 0)
        self.assertEqual([f["severity"] for f in rep["findings"]], ["OK"])
        self.assertIn("Rulesets: require a pull request (1 approval, code-owner review); block force-pushes", rep["protects"])
        self.assertEqual(rep["verdict"], "`main` is protected, but its settings are visible only to repository admins. No gap found in what is visible.")
        self.assertTrue(any("only repository admins can read them" in u for u in rep["cannot_determine"]))

    def test_rulesets_with_no_approval_and_approvals_that_survive_new_commits(self):
        # classic protection must be known off for these to be facts: hidden classic settings could require an approval (UnreadableRules)
        off = (200, {"protected": True, "protection": {"enabled": False}}, {})
        none = [{"type": "pull_request", "parameters": {"required_approving_review_count": 0, "require_code_owner_review": False}}]
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": off, f"/repos/{REPO}/rules/branches/main": (200, none, {})}, False)
        self.assertIn("no-approval-required", [f["id"] for f in rep["findings"]])
        stale = [{"type": "pull_request", "parameters": {"required_approving_review_count": 2}}]
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": off, f"/repos/{REPO}/rules/branches/main": (200, stale, {})}, False)
        self.assertIn("approval-survives-new-commits", [f["id"] for f in rep["findings"]])

    def test_protected_only_by_rulesets_that_require_nothing_before_commits_land(self):
        """Found by the stranger test: 'protected' can mean only that force-pushes and deletion are blocked."""
        code, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True, "protection": {"enabled": False}}, {}),
                                f"/repos/{REPO}/branches/main/protection": (401, {}, {}),
                                f"/repos/{REPO}/rules/branches/main": (200, [{"type": "deletion"}, {"type": "non_fast_forward"}], {})}, authenticated=False)
        self.assertEqual(rep["verdict"], "Nothing requires a pull request before commits land on `main`.")
        self.assertIn("Rulesets: block deletion; block force-pushes", rep["protects"])
        self.assertTrue(rep["protects"][0].startswith("Classic branch protection: off"))
        self.assertFalse(any("classic branch-protection settings" in u for u in rep["cannot_determine"]))   # off is known, not hidden

    def test_checks_anyone_can_run_and_a_report_worth_forwarding(self):
        _, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}),
                             f"/repos/{REPO}/rules/branches/main": (200, [], {})}, authenticated=False)
        self.assertIn("branch-unprotected", [f["id"] for f in rep["findings"]])
        for f in rep["findings"]:
            self.assertTrue(f["verify"].startswith('curl -s'), f["verify"])
            self.assertIn('"https://', f["verify"])                                              # quoted: safe in zsh
            self.assertNotIn("gh api", f["verify"])
        for name in ("report.md", "report.html"):
            self.assertNotIn(A.CONTACT, files[name])                                              # no sales pitch in what gets forwarded
            self.assertNotIn("sha256", files[name])                                               # no evidence a reader cannot check

    def test_fail_on_high_for_ci(self):
        # a confirmed HIGH needs the rules read: before evidence framing this table had no rules endpoint, and its 404 was read as "no rules"
        code, _, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}),
                          f"/repos/{REPO}/rules/branches/main": (200, [], {})}, False, ["--fail-on-high"])
        self.assertEqual(code, 1)


UNPROTECTED = {f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}), f"/repos/{REPO}/rules/branches/main": (200, [], {})}


def ruleset(cmd):
    """The body and the request of a printed fix command, read back the way a shell would."""
    toks = shlex.split(cmd)
    return json.loads(toks[1]), toks[2:]


class FixPath(unittest.TestCase):
    """From a finding to its fix, to the agent's own identity, to the guard (entry 197)."""

    def test_an_unprotected_branch_comes_with_the_command_that_protects_it(self):
        _, rep, files = run(UNPROTECTED, authenticated=False)
        f = rep["findings"][0]
        body, req = ruleset(f["apply"])
        self.assertEqual(req, ["|", "gh", "api", "--method", "POST", f"repos/{REPO}/rulesets", "--input", "-"])
        self.assertEqual((body["target"], body["enforcement"], body["conditions"]["ref_name"]["include"]), ("branch", "active", ["refs/heads/main"]))
        self.assertEqual([r["type"] for r in body["rules"]], ["deletion", "non_fast_forward", "pull_request"])
        prm = body["rules"][2]["parameters"]                                                     # every parameter GitHub's API marks required
        self.assertEqual(set(prm), {"required_approving_review_count", "dismiss_stale_reviews_on_push", "require_code_owner_review",
                                    "require_last_push_approval", "required_review_thread_resolution"})
        self.assertEqual((prm["required_approving_review_count"], prm["require_code_owner_review"]), (1, True))   # a declared code owner must approve
        self.assertIn(A.REVIEW, f["fix"])                                                        # the words name every review setting the command applies
        for words, key in (("code owner", "require_code_owner_review"), ("dismisses earlier approvals", "dismiss_stale_reviews_on_push"),
                           ("someone other than whoever pushed it", "require_last_push_approval")):
            self.assertIn(words, A.REVIEW)
            self.assertTrue(prm[key], key)
        self.assertNotIn("bypass_actors", body)                                                 # for a team, no one skips review
        solo, solo_req = ruleset(f["apply_solo"])
        self.assertEqual(solo_req, req)
        self.assertEqual(solo["bypass_actors"], [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}])   # admins, pull requests only
        self.assertEqual({k: v for k, v in solo.items() if k != "bypass_actors"}, body)          # otherwise the same rules: one approval, no direct push
        self.assertEqual(f["apply_note"], "")                                                    # a public repository: no plan caveat
        self.assertIn(f"```bash\n{f['apply']}\n```\n\n{A.SOLO}\n\n```bash\n{f['apply_solo']}\n```", files["report.md"])
        self.assertEqual(files["report.html"].count("<pre><code>echo "), 2)
        private = run({**UNPROTECTED, f"/repos/{REPO}": repo(private=True)}, authenticated=False)[1]
        self.assertIn("free plans may not offer rulesets", private["findings"][0]["apply_note"])
        self.assertEqual(rep["recheck"], [f"Run the check again: `agent-authority-check --repo {REPO}`. The finding you fixed should be gone."])

    def test_a_branch_protected_only_against_deletion_gets_only_the_missing_rule(self):
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True, "protection": {"enabled": False}}, {}),
                         f"/repos/{REPO}/rules/branches/main": (200, [{"type": "deletion"}, {"type": "non_fast_forward"}], {})}, authenticated=False)
        body, _ = ruleset(rep["findings"][0]["apply"])
        self.assertEqual([r["type"] for r in body["rules"]], ["pull_request"])

    def test_a_code_owner_rule_without_a_codeowners_file_is_not_shown_as_protection(self):
        """Found by the third stand-in stranger: the tool's own repository listed 'code-owner review' before it had a CODEOWNERS file."""
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True, "protection": {"enabled": False}}, {}),
                         f"/repos/{REPO}/rules/branches/main": (200, [PR], {})}, authenticated=False)
        self.assertIn("Rulesets: require a pull request (1 approval, code-owner review (no CODEOWNERS file, so no owner is required))", rep["protects"])
        self.assertIn("asks for code-owner review requires nothing", [f for f in rep["findings"] if f["id"] == "no-codeowners"][0]["detail"])

    def test_branch_names_survive_the_shell(self):
        b = "release/it's"
        q = "release%2Fit%27s"
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/{q}": (200, {"protected": False}, {}),
                         f"/repos/{REPO}/rules/branches/{q}": (200, [], {})}, False, ["--branch", b])
        body, _ = ruleset(rep["findings"][0]["apply"])
        self.assertEqual(body["conditions"]["ref_name"]["include"], [f"refs/heads/{b}"])
        self.assertEqual(shlex.split(rep["recheck"][0].split("`")[1])[-2:], ["--branch", b])

    def test_a_credential_that_can_switch_protection_off_leads_to_the_agents_own_identity(self):
        _, rep, _ = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": True, "push": True}, "repo"),
                         f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, [PR], {})})
        f = rep["findings"][0]
        self.assertEqual((f["id"], f["fix"], f["apply"]), ("credential-can-change-protection", A.AGENT_IDENTITY, None))   # no command can do this for you
        self.assertIn('GITHUB_TOKEN="$AGENT_TOKEN" agent-authority-check --repo acme/app', rep["recheck"][1])
        ok = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "push": True}, "repo"),
                  f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, [PR], {})})[1]
        title = [x["title"] for x in ok["findings"] if x["id"] == "credential-cannot-change-protection"][0]
        self.assertIn(f'"{title}"', rep["recheck"][1])                                          # the promised result is the check's own words

    def test_the_report_ends_with_the_guard_and_the_terminal_stays_plain(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            _, rep, files = run(UNPROTECTED, authenticated=False)
        md = files["report.md"]
        self.assertGreater(md.index("### Beyond branch settings"), md.index("### How this was checked"))
        self.assertIn("Fix the findings above first", md)
        for name in ("report.md", "report.html"):
            self.assertIn(A.GUARD_URL, files[name])
            self.assertNotIn(A.CONTACT, files[name])
        self.assertIn(f"<a href='{A.GUARD_URL}'>", files["report.html"])
        self.assertNotIn("guard", out.getvalue().lower())
        clean = [{"type": "pull_request", "parameters": PR["parameters"]}, {"type": "non_fast_forward"}]
        _, _, files = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "push": True}, "repo"),
                           f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, clean, {}),
                           f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("* @lead\n/.github/ @lead\n")})
        self.assertIn("### Beyond branch settings", files["report.md"])
        self.assertNotIn("Fix the findings above first", files["report.md"])
        self.assertNotIn("### After a fix", files["report.md"])


PR = {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True, "require_last_push_approval": True,
                                             "dismiss_stale_reviews_on_push": True}}


class Failures(unittest.TestCase):
    def test_failures_write_no_report_and_explain_themselves(self):
        cases = {"rejected": ({"/user": (401, {}, {})}, True), "missing": ({}, False),
                 "rate limit": ({f"/repos/{REPO}": (403, {"message": "rate limit"}, {"x-ratelimit-remaining": "0"})}, False)}
        for name, (table, auth) in cases.items():
            with self.subTest(name), mock.patch("sys.stderr") as err:
                code, rep, files = run(table, auth)
                self.assertEqual(code, 2)
                self.assertEqual(files, {})
                self.assertIn("agent-authority-check:", "".join(c.args[0] for c in err.write.call_args_list))

    def test_unreachable_network(self):
        with mock.patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError("no route")), mock.patch("sys.stderr"):
            self.assertEqual(A.main(["--repo", REPO, "--anonymous", "--out", tempfile.mkdtemp()]), 2)

    def test_bad_repository_names_are_refused_before_any_request(self):
        t = Fake({})
        with mock.patch("sys.stderr"):
            self.assertEqual(A.main(["--repo", "acme/app/../../x", "--out", tempfile.mkdtemp()], t=t), 2)
        self.assertEqual(t.calls, [])

    def test_a_failed_branch_read_stops_the_check(self):
        with mock.patch("sys.stderr") as err:
            code, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (502, {"message": "Bad Gateway"}, {})}, False)
        self.assertEqual(code, 2)
        self.assertEqual(files, {})                                                              # no report built on a branch it could not read
        self.assertIn("HTTP 502", "".join(c.args[0] for c in err.write.call_args_list))


class Flaky(Fake):
    """A Fake whose listed endpoints never answer, as a dropped connection would."""

    def __init__(self, table, down, authenticated=True):
        super().__init__(table, authenticated)
        self.down = down

    def get(self, path):
        if path in self.down:
            self.calls.append(path)
            raise A.CheckError("cannot reach GitHub: timed out")
        return super().get(path)


def frames(rep):
    return {f["id"]: f for f in rep["frames"]}


RULES = f"/repos/{REPO}/rules/branches/main"
RULESET_ONLY = {f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True, "protection": {"enabled": False}}, {})}
UNPROTECTED_FLAG = {f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {})}


class EvidenceFraming(unittest.TestCase):
    """A limitation of observation is never a fact about the repository: a read that failed is unknown, not empty (evidence_frame)."""

    def test_regression_the_original_false_certainty_cannot_return(self):
        """Before evidence framing, a failed rules read became `[]`: 'Rulesets: none apply', and a HIGH citing the failed request as proof."""
        _, rep, files = run({**UNPROTECTED_FLAG, RULES: (503, {"message": "Service Unavailable"}, {})}, False)
        everything = json.dumps(rep) + files["report.md"] + files["report.html"]
        self.assertNotIn("none apply", everything)
        self.assertNotIn("no rule governs pushes", everything)
        self.assertNotIn("branch-unprotected", [f["id"] for f in rep["findings"]])
        self.assertEqual(rep["counts"]["HIGH"], 0)

    def test_a_private_repository_on_a_plan_without_rules_says_so_and_does_not_advise_reading_again(self):
        """Seen live on 2026-11-07 (charles-337/haven-authority-baseline, private): GitHub answers the rules read with a plan message, not a permission one."""
        plan = (403, {"message": "Upgrade to GitHub Pro or make this repository public to enable this feature.", "status": "403"}, {})
        _, rep, files = run({**UNPROTECTED_FLAG, RULES: plan}, False)
        f = frames(rep)["rulesets"]
        self.assertEqual((f["state"], f["reason"], f["observed_value"]), ("UNKNOWN", "PLAN_LIMITED", None))     # still unknown, never "none apply"
        said = " ".join(rep["cannot_determine"])
        self.assertIn("needs GitHub Pro or a public repository", said)
        self.assertNotIn("Run the check again", said)
        self.assertNotIn("none apply", json.dumps(rep) + files["report.md"])
        _, plain, _ = run({**UNPROTECTED_FLAG, RULES: (403, {"message": "Resource not accessible by integration"}, {})}, False)
        self.assertEqual(frames(plain)["rulesets"]["reason"], "PERMISSION_DENIED")                            # an ordinary refusal is unchanged

    def test_a_failed_rules_read_has_no_empty_rules_representation(self):
        d = A.collect(Fake({**RULESET_ONLY, RULES: (503, {}, {})}, False), REPO)
        with self.assertRaises(A.EF.Unread):
            d["obs"]["rules"].value                                                               # no [] to fall back on
        rep = A.build(d)
        f = frames(rep)["rulesets"]
        self.assertEqual((f["state"], f["observation_status"], f["reason"], f["observed_value"]), ("UNKNOWN", "FAILED", "SOURCE_UNAVAILABLE", None))
        self.assertIn("Rulesets: unknown (SOURCE_UNAVAILABLE: GitHub answered HTTP 503)", rep["protects"])
        ok = frames(A.build(A.collect(Fake({**RULESET_ONLY, RULES: (200, [], {})}, False), REPO)))["rulesets"]
        self.assertEqual((ok["state"], ok["observation_status"], ok["observed_value"]), ("KNOWN_FALSE", "COMPLETE", []))   # a real empty list

    def test_unknown_rulesets_never_give_a_no_gap_verdict(self):
        _, rep, _ = run({**RULESET_ONLY, RULES: (503, {}, {})}, False)
        self.assertNotIn("No gap", rep["verdict"])
        self.assertNotIn("No authority gap", rep["verdict"])
        self.assertIn("cannot be determined here", rep["verdict"])
        self.assertEqual([f for f in rep["findings"] if f["severity"] in ("HIGH", "MEDIUM")], [])

    def test_protected_false_with_unread_rules_reports_only_the_narrower_fact(self):
        code, rep, _ = run({**UNPROTECTED_FLAG, RULES: (500, {}, {})}, False, ["--fail-on-high"])
        fr = frames(rep)
        self.assertEqual(fr["branch-protected-flag"]["state"], "KNOWN_FALSE")                    # what GitHub returned, and only that
        self.assertIn("not a list of them", fr["branch-protected-flag"]["does_not_permit"])
        held = fr["branch-unprotected"]
        self.assertEqual((held["state"], held["reason"], held["severity_if_confirmed"]), ("UNKNOWN", "SOURCE_UNAVAILABLE", "HIGH"))
        self.assertEqual(rep["counts"]["HIGH"], 0)                                                # unknown is not a HIGH ...
        self.assertTrue(rep["verdict"].startswith("Whether anything stops a direct push to `main` cannot be determined here (SOURCE_UNAVAILABLE"))
        self.assertEqual(code, 3)                                                                 # ... and not a pass either
        self.assertEqual(run({**UNPROTECTED_FLAG, RULES: (500, {}, {})}, False)[0], 0)           # without --fail-on-high nothing fails

    def test_http_failures_keep_their_reason(self):
        cases = {"permission": ((403, {"message": "Resource not accessible"}, {}), "PERMISSION_DENIED"),
                 "rate limit": ((403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0"}), "RATE_LIMITED"),
                 "secondary limit": ((403, {"message": "You have exceeded a secondary rate limit"}, {"retry-after": "60"}), "RATE_LIMITED"),
                 "too many": ((429, {}, {}), "RATE_LIMITED"), "server": ((502, {}, {}), "SOURCE_UNAVAILABLE"), "not found": ((404, {}, {}), "NOT_OBSERVED"),
                 "wrong shape": ((200, {"not": "a list"}, {}), "SOURCE_UNAVAILABLE")}
        for name, (answer, reason) in cases.items():
            with self.subTest(name):
                f = frames(A.build(A.collect(Fake({**RULESET_ONLY, RULES: answer}, False), REPO)))["rulesets"]
                self.assertEqual((f["state"], f["observation_status"], f["reason"]), ("UNKNOWN", "FAILED", reason))
        f = frames(A.build(A.collect(Flaky(RULESET_ONLY, {RULES}, False), REPO)))["rulesets"]
        self.assertEqual((f["reason"], f["limitation"]), ("SOURCE_UNAVAILABLE", "no response"))  # a dropped connection, not an empty list

    def test_a_paginated_rules_read_cannot_establish_absence(self):
        seen = [{"type": "deletion"}, {"type": "non_fast_forward"}]
        _, whole, _ = run({**RULESET_ONLY, RULES: (200, seen, {})}, False)
        self.assertIn("no-pull-request-required", [f["id"] for f in whole["findings"]])           # every rule read: the gap is real
        more = {"link": f'<https://api.github.com/repositories/1/rules/branches/main?page=2>; rel="next"'}
        _, part, _ = run({**RULESET_ONLY, RULES: (200, seen, more)}, False)
        self.assertNotIn("no-pull-request-required", [f["id"] for f in part["findings"]])         # page 2 may hold the pull-request rule
        fr = frames(part)
        self.assertEqual((fr["rulesets"]["state"], fr["rulesets"]["observation_status"]), ("KNOWN_TRUE", "PARTIAL"))   # what was seen still counts
        self.assertEqual((fr["no-pull-request-required"]["state"], fr["no-pull-request-required"]["reason"]), ("UNKNOWN", "PARTIAL_SCOPE"))
        self.assertTrue(any("more not read" in p for p in part["protects"]))

    def test_classic_findings_a_ruleset_could_override_hold_back_until_the_rules_are_read(self):
        prot = {"allow_force_pushes": {"enabled": True}, "enforce_admins": {"enabled": True}, "required_status_checks": {"strict": True, "contexts": ["ci"]}}
        table = {"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "push": True}, "repo"),
                 f"/repos/{REPO}/branches/main": (200, {"protected": True, "protection": {"enabled": True}}, {}),
                 f"/repos/{REPO}/branches/main/protection": (200, prot, {})}
        held = {"force-push-allowed", "no-review-required-classic"}
        _, read, _ = run({**table, RULES: (200, [], {})})
        self.assertEqual(held & {f["id"] for f in read["findings"]}, held)                        # with the rules read: both are real
        _, unread, _ = run({**table, RULES: (503, {}, {})})
        self.assertEqual(held & {f["id"] for f in unread["findings"]}, set())                     # unread: a ruleset could block force-pushes or require review
        self.assertEqual({k for k, f in frames(unread).items() if f["state"] == "UNKNOWN"} & held, held)
        self.assertTrue(any("GitHub answered HTTP 503" in u for u in unread["cannot_determine"]))

    def test_a_codeowners_read_that_failed_is_not_a_missing_file(self):
        denied = {f"/repos/{REPO}/contents/{p}?ref=main": (403, {}, {}) for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")}
        _, rep, _ = run({**UNPROTECTED, **denied}, False)
        self.assertNotIn("no-codeowners", [f["id"] for f in rep["findings"]])
        self.assertEqual((frames(rep)["codeowners"]["state"], frames(rep)["codeowners"]["reason"]), ("UNKNOWN", "PERMISSION_DENIED"))
        _, rep, _ = run(UNPROTECTED, False)                                                       # three 404s: the file is known absent
        self.assertIn("no-codeowners", [f["id"] for f in rep["findings"]])
        self.assertEqual(frames(rep)["codeowners"]["state"], "KNOWN_FALSE")

    def test_a_role_is_not_a_capability(self):
        base = {f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), RULES: (200, [], {}), "/user": (200, {"login": "agent-bot"}, {})}
        cases = {"admin, classic repo scope": (repo({"admin": True, "push": True}, "repo"), True, "KNOWN_TRUE", None),
                 "admin, fine-grained token": (repo({"admin": True, "push": True}), True, "UNKNOWN", "UNSUPPORTED_INFERENCE"),
                 "write only": (repo({"admin": False, "push": True}, "repo"), True, "KNOWN_FALSE", None),
                 "no credential": (repo(), False, "UNKNOWN", "NOT_OBSERVED")}
        for name, (r, auth, state, reason) in cases.items():
            with self.subTest(name):
                f = frames(run({**base, f"/repos/{REPO}": r}, auth)[1])["credential-can-change-protection"]
                self.assertEqual((f["state"], f["reason"]), (state, reason))

    def test_every_output_carries_the_same_epistemic_state(self):
        table = {**UNPROTECTED_FLAG, RULES: (503, {}, {})}
        with tempfile.TemporaryDirectory() as d, mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            A.main(["--repo", REPO, "--out", d, "--json", f"{d}/r.json"], t=Fake(table, False))
            rep, md, page = json.loads(Path(d, "r.json").read_text()), Path(d, "report.md").read_text(), Path(d, "report.html").read_text()
        held = frames(rep)["branch-unprotected"]
        self.assertEqual((held["state"], held["reason"]), ("UNKNOWN", "SOURCE_UNAVAILABLE"))
        for text in (md, page):
            self.assertIn("What is known and what is not", text)
            self.assertIn("SOURCE_UNAVAILABLE", text)
            self.assertIn("would be HIGH if confirmed", text)
        self.assertIn("Nothing stops a direct push to `main`. (would be HIGH if confirmed)", md)
        self.assertIn("Nothing stops a direct push to <code>main</code>. (would be HIGH if confirmed)", page)
        self.assertIn(f"{rep['unresolved']} unresolved", out.getvalue())
        self.assertIn(rep["verdict"], out.getvalue())
        self.assertIn(rep["verdict"], md)

    def test_conflicting_classic_observations_never_become_a_confirmed_gap(self):
        for branch in ({"protected": False}, {"protected": True, "protection": {"enabled": False}}):
            with self.subTest(branch=branch):
                table = {**UNPROTECTED_FLAG, RULES: (200, [], {}),
                         f"/repos/{REPO}/branches/main": (200, branch, {}),
                         f"/repos/{REPO}/branches/main/protection":
                         (200, {"required_pull_request_reviews": {"required_approving_review_count": 1,
                                                                  "dismiss_stale_reviews": True}}, {})}
                code, rep, files = run(table, False, ["--fail-on-high"])
                fr = frames(rep)
                for key in ("classic-protection", "pull-request-required", "review-bypass"):
                    self.assertEqual((fr[key]["state"], fr[key]["reason"]),
                                     ("UNKNOWN", "CONFLICTING_OBSERVATIONS"))
                self.assertNotIn("branch-unprotected", [f["id"] for f in rep["findings"]])
                self.assertIn("cannot be determined", rep["verdict"])
                self.assertIn("Classic branch protection: unknown (CONFLICTING_OBSERVATIONS", rep["protects"][0])
                for output in (files["report.md"], files["report.html"]):
                    self.assertIn("CONFLICTING_OBSERVATIONS", output)
                if branch["protected"] is False:
                    self.assertEqual(code, 3)

    def test_frames_are_stable_for_machines(self):
        a = run({**RULESET_ONLY, RULES: (503, {}, {})}, False)[1]["frames"]
        b = run({**RULESET_ONLY, RULES: (503, {}, {})}, False)[1]["frames"]
        strip = lambda fr: [{k: v for k, v in f.items() if k != "observed_at"} for f in fr]
        self.assertEqual(strip(a), strip(b))
        self.assertEqual(list(a[0]), ["id", "claim", "state", "observation_status", "reason", "source", "observed_value", "scope_inspected",
                                      "observed_at", "evidence", "limitation", "permits", "does_not_permit", "resolve", "severity_if_confirmed"])

    def test_confirmed_findings_and_safe_configurations_are_unchanged(self):
        _, rep, _ = run(UNPROTECTED, False)                                                       # a confirmed HIGH stays HIGH
        self.assertEqual(rep["findings"][0]["id"], "branch-unprotected")
        self.assertEqual(rep["findings"][0]["severity"], "HIGH")
        self.assertEqual((frames(rep)["rulesets"]["state"], frames(rep)["branch-protected-flag"]["state"]), ("KNOWN_FALSE", "KNOWN_FALSE"))
        rules = [{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                         "require_last_push_approval": True, "dismiss_stale_reviews_on_push": True}}, {"type": "non_fast_forward"}]
        _, safe, _ = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "push": True}, "repo"),
                          f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), RULES: (200, rules, {}),
                          f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("* @lead\n/.github/ @lead @sec\n")})
        self.assertEqual(safe["verdict"], "`main` is protected, but its settings are visible only to repository admins. No gap found in what is visible.")
        self.assertEqual(frames(safe)["pull-request-required"]["state"], "KNOWN_TRUE")
        self.assertEqual(frames(safe)["review-bypass"]["state"], "UNKNOWN")                      # bypass lists are not readable here, and it says so


class Credentials(unittest.TestCase):
    def test_only_gets_and_the_token_never_reaches_any_output(self):
        secret = "test-token-sentinel-not-a-real-secret-0123456789"
        seen = []

        class Resp:
            def __init__(self, req):
                seen.append(req)
                body = {"/repos/acme/app": {"default_branch": "main", "permissions": {"admin": False, "push": True}},
                        "/user": {"login": "agent-bot"}, "/repos/acme/app/branches/main": {"protected": False}}.get(req.full_url[len(A.API):])
                if body is None:
                    raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b"{}"))
                self.status, self.headers, self._b = 200, {}, json.dumps(body).encode()

            def read(self):
                return self._b

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        out = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": secret}), mock.patch.object(urllib.request, "urlopen", side_effect=lambda req, timeout: Resp(req)):
            A.main(["--repo", REPO, "--out", out, "--json", f"{out}/r.json"])
        self.assertTrue(seen)
        self.assertEqual({r.get_method() for r in seen}, {"GET"})
        self.assertTrue(all(r.get_header("Authorization") == f"Bearer {secret}" for r in seen))
        for p in Path(out).iterdir():
            self.assertNotIn(secret, p.read_text(), p.name)

    def test_anonymized_reports_carry_no_names(self):
        table = {"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": True}, "repo"),
                 f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}), f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("* @jane\n")}
        _, rep, files = run(table, True, ["--anonymize"])
        text = json.dumps(rep) + "".join(files.values())
        for name in ("acme", "agent-bot", "jane"):
            self.assertNotIn(name, text)

    def test_anonymize_also_masks_the_branch_name(self):
        b, q = "alice/project-phoenix", "alice%2Fproject-phoenix"           # git-flow branches carry teammate handles and codenames
        table = {"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "push": True}, "repo"),
                 f"/repos/{REPO}/branches/{q}": (200, {"protected": False}, {}), f"/repos/{REPO}/rules/branches/{q}": (200, [], {})}
        _, rep, files = run(table, True, ["--branch", b, "--anonymize"])
        text = json.dumps(rep) + "".join(files.values())
        for leak in ("alice", "project-phoenix"):                           # neither the raw nor the url-quoted branch may survive
            self.assertNotIn(leak, text)
        self.assertIn("<branch>", json.dumps(rep))

    def test_the_page_escapes_what_it_shows(self):
        page = A.page({"repository": "<script>x</script>", "branch": "main", "verdict": "v", "credential": "c", "generated_at": "t", "protects": ["<b>"],
                       "findings": [], "cannot_determine": [], "limits": "l", "evidence": []})
        self.assertNotIn("<script>x", page)


class PassportStarter(unittest.TestCase):
    """The bridge from the check's finding to the Change Passport fix: a tailored policy that parses cleanly."""

    def test_starter_is_tailored_to_the_branch(self):
        # standard-library only, like the rest of the public check: assert on the emitted text, no YAML parser needed
        text = A.passport_starter({"repo": "acme/app", "branch": "release/it's"})
        self.assertIn("# Haven Change Passport starter for acme/app (branch release/it's)", text)
        self.assertIn("target_branches: ['release/it''s']", text)   # apostrophe doubled: valid YAML
        self.assertIn("scope: all_changes", text)                   # every change needs an approval: closes the no-review gap
        self.assertIn("  - 'secrets/**'", text)
        self.assertEqual(text.count("authority: A3"), 4)            # four agents, none above A3 (no agent merges on its own)
        for name in ("Claude Code", "Devin", "Cursor", "Codex"):
            self.assertIn(f"name: {name}", text)

    def test_main_emits_the_starter_next_to_the_report(self):
        table = {"/repos/acme/app": (200, {"default_branch": "main", "private": False, "permissions": {}}, {}),
                 "/repos/acme/app/branches/main": (200, {"protected": False, "protection": {"enabled": False}}, {}),
                 "/repos/acme/app/rules/branches/main": (200, [], {})}
        with tempfile.TemporaryDirectory() as tmp:
            out, pp = Path(tmp) / "rep", Path(tmp) / "passport.yaml"
            A.main(["--repo", REPO, "--out", str(out), "--emit-passport", str(pp)], t=Fake(table))
            self.assertTrue(pp.exists() and "target_branches" in pp.read_text())


class RepositoryLevelRulesetIsStillUnprotected(unittest.TestCase):
    """Regression: a branch with protected=false but a ruleset of only repository_* rules (visibility/delete/transfer) is NOT protected —
    those rules govern the repository, not pushes to the branch. The check must still flag HIGH, not report 'no gap'."""

    def test_repo_level_only_ruleset_flags_high(self):
        b = "main"
        table = {
            "/user": (200, {"login": "tester"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": False, "push": False, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, {"protected": False, "protection": {"enabled": False}}, {}),
            f"/repos/{REPO}/branches/{b}/protection": (404, {"message": "Branch not protected"}, {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, [{"type": "repository_visibility"}, {"type": "repository_delete"}, {"type": "repository_transfer"}], {}),
        }
        F, _ = A.findings(A.collect(Fake(table), REPO))
        hi = [f for f in F if f["severity"] == "HIGH" and f["id"] == "branch-unprotected"]
        self.assertTrue(hi, "a repository-level-only ruleset must still flag the branch as unprotected")
        self.assertIn("repository-level ruleset", hi[0]["detail"])        # and must not claim 'no ruleset'
        self.assertNotIn("repository_visibility", {x for f in F for x in [f["id"]]})  # repo-level types are not treated as branch protection


class AutomatedGateIsNotHumanReview(unittest.TestCase):
    """Regression: a branch whose ruleset requires only an automated gate (status checks, merge queue, deployments) or a push restriction,
    with no pull_request rule, is NOT review-gated. An agent whose change passes the automated rules merges with no human approval, so the
    check must flag MEDIUM 'no-review-required' — not report 'no gap'. A pull_request rule, or a truly empty ruleset, keeps its old behaviour."""

    def _run(self, rules, protected=True):
        b = "main"
        table = {
            "/user": (200, {"login": "agent-bot"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": False, "push": True, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, {"protected": protected, "protection": {"enabled": False}}, {}),
            f"/repos/{REPO}/branches/{b}/protection": (404, {"message": "Branch not protected"}, {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, rules, {}),
        }
        return A.findings(A.collect(Fake(table), REPO))[0]

    def test_status_checks_only_flags_no_review_required(self):
        F = self._run([{"type": "required_status_checks"}, {"type": "non_fast_forward"}])
        m = [f for f in F if f["id"] == "no-review-required"]
        self.assertTrue(m, "a status-check-only branch requires no human review and must be flagged")
        self.assertEqual(m[0]["severity"], "MEDIUM")
        self.assertIn("no human review", m[0]["detail"])
        self.assertNotIn("no-pull-request-required", {f["id"] for f in F})  # the HIGH is only for a branch with no gate at all

    def test_merge_queue_and_update_also_flag(self):
        for rules in ([{"type": "merge_queue"}], [{"type": "update"}], [{"type": "required_deployments"}]):
            self.assertIn("no-review-required", {f["id"] for f in self._run(rules)}, rules)

    def test_a_pull_request_rule_is_not_flagged_here(self):
        F = self._run([{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                               "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True}}])
        self.assertNotIn("no-review-required", {f["id"] for f in F})  # a pull_request rule can require review; this finding must not fire

    def test_empty_ruleset_still_flags_high_not_medium(self):
        F = self._run([{"type": "non_fast_forward"}, {"type": "deletion"}])
        ids = {f["id"] for f in F}
        self.assertIn("no-pull-request-required", ids)   # nothing gates a push -> still the HIGH
        self.assertNotIn("no-review-required", ids)      # and not the MEDIUM


class ClassicProtectionWithoutReview(unittest.TestCase):
    """Regression (D1): classic branch protection that requires status checks but no pull-request review must be
    flagged as requiring no human review - the classic-path parallel to the ruleset 'no-review-required'."""

    def _ids(self, table):
        F, _ = A.findings(A.collect(Fake(table), REPO))
        return {f["id"]: f for f in F}

    def test_classic_checks_without_review_flags_no_review(self):
        b = "main"
        ids = self._ids({
            "/user": (200, {"login": "admin"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": True, "push": True, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, {"protected": True, "protection": {"enabled": True}}, {}),
            f"/repos/{REPO}/branches/{b}/protection": (200, {"required_status_checks": {"strict": True, "contexts": ["ci"]},
                                                             "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}}, {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, [], {}),
        })
        self.assertIn("no-review-required-classic", ids)
        self.assertEqual(ids["no-review-required-classic"]["severity"], "MEDIUM")
        self.assertIn("does not require a pull-request review", ids["no-review-required-classic"]["detail"])

    def test_classic_with_required_review_is_not_flagged(self):
        b = "main"
        ids = self._ids({
            "/user": (200, {"login": "admin"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": True, "push": True, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, {"protected": True, "protection": {"enabled": True}}, {}),
            f"/repos/{REPO}/branches/{b}/protection": (200, {"required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True},
                                                             "required_status_checks": {"strict": True}, "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False}}, {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, [], {}),
        })
        self.assertNotIn("no-review-required-classic", ids)


class ForcePushAllowedOnRulesetPath(unittest.TestCase):
    """Regression (D2, Treatment arm). A ruleset-protected branch lacking `non_fast_forward` allows force-pushes and
    must be flagged. Includes the verifier's false-positive case: classic protection enabled-but-unreadable must NOT fire."""

    def _ids(self, rules, branch_body, protection=(404, {"message": "nf"})):
        b = "main"
        table = {
            "/user": (200, {"login": "agent"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": False, "push": True, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, branch_body, {}),
            f"/repos/{REPO}/branches/{b}/protection": (protection[0], protection[1], {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, rules, {}),
        }
        F, _ = A.findings(A.collect(Fake(table), REPO))
        return {f["id"] for f in F}

    REVIEWED = [{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                        "dismiss_stale_reviews_on_push": True, "require_last_push_approval": True}}]

    def test_ruleset_without_non_fast_forward_flags(self):
        ids = self._ids(self.REVIEWED, {"protected": True, "protection": {"enabled": False}})
        self.assertIn("force-push-allowed-ruleset", ids)

    def test_ruleset_with_non_fast_forward_not_flagged(self):
        ids = self._ids(self.REVIEWED + [{"type": "non_fast_forward"}], {"protected": True, "protection": {"enabled": False}})
        self.assertNotIn("force-push-allowed-ruleset", ids)

    def test_classic_enabled_but_unreadable_does_not_false_positive(self):
        # classic protection enabled (classic_enabled True) but unreadable (protection 404) -> must NOT fire (verifier's catch)
        ids = self._ids(self.REVIEWED, {"protected": True, "protection": {"enabled": True}})
        self.assertNotIn("force-push-allowed-ruleset", ids)

    def test_ruleset_update_rule_suppresses_force_push(self):
        # an `update` (restrict who may push) rule gates force-pushes too -> no ruleset force-push finding (issue #2)
        ids = self._ids(self.REVIEWED + [{"type": "update"}], {"protected": True, "protection": {"enabled": False}})
        self.assertNotIn("force-push-allowed-ruleset", ids)

    def test_classic_force_push_suppressed_by_ruleset_non_fast_forward(self):
        # classic allows force-pushes, but a ruleset adds non_fast_forward; GitHub's stricter rule wins -> suppress (issue #5)
        allow_fp = (200, {"allow_force_pushes": {"enabled": True}, "enforce_admins": {"enabled": True}})
        fires = self._ids(self.REVIEWED, {"protected": True, "protection": {"enabled": True}}, protection=allow_fp)
        self.assertIn("force-push-allowed", fires)                    # control: classic force-push fires when nothing overrides it
        suppressed = self._ids(self.REVIEWED + [{"type": "non_fast_forward"}], {"protected": True, "protection": {"enabled": True}}, protection=allow_fp)
        self.assertNotIn("force-push-allowed", suppressed)


class ClassicReviewBypass(unittest.TestCase):
    """Regression (pre-publication audit): a classic branch that requires review but lists bypass actors is NOT protected against them.
    The data is already in the fetched protection payload, so the check must flag HIGH, not report a clean verdict."""

    def _ids(self, rpr):
        b = "main"
        table = {
            "/user": (200, {"login": "agent-bot"}, {}),
            f"/repos/{REPO}": (200, {"default_branch": b, "private": False, "permissions": {"admin": False, "push": True, "pull": True}}, {}),
            f"/repos/{REPO}/branches/{b}": (200, {"protected": True, "protection": {"enabled": True}}, {}),
            f"/repos/{REPO}/branches/{b}/protection": (200, {"required_pull_request_reviews": rpr, "enforce_admins": {"enabled": True},
                                                             "allow_force_pushes": {"enabled": False}}, {}),
            f"/repos/{REPO}/rules/branches/{b}": (200, [], {}),
        }
        F, _ = A.findings(A.collect(Fake(table), REPO))
        return {f["id"]: f for f in F}

    REVIEWED = {"required_approving_review_count": 1, "dismiss_stale_reviews": True, "require_last_push_approval": True}

    def test_bypass_actors_flag_high(self):
        ids = self._ids({**self.REVIEWED, "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": ["automation-app"]}})
        self.assertIn("review-bypass-allowed", ids)
        self.assertEqual(ids["review-bypass-allowed"]["severity"], "HIGH")
        self.assertIn("bypass", ids["review-bypass-allowed"]["detail"].lower())

    def test_no_bypass_actors_not_flagged(self):
        self.assertNotIn("review-bypass-allowed", self._ids(self.REVIEWED))                                             # no bypass block at all
        self.assertNotIn("review-bypass-allowed", self._ids({**self.REVIEWED, "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []}}))  # empty lists


class CodeownersGlob(unittest.TestCase):
    """Regression (audit): _covered must honor mid-path glob patterns, else a glob-scoped CODEOWNERS yields a false governance-files-unowned."""

    def test_mid_path_glob_is_covered(self):
        self.assertTrue(A._covered("/.github/workflows/*.yml @team\n", ".github/workflows/ci.yml"))
        self.assertTrue(A._covered(".github/**/*.yml @team\n", ".github/workflows/ci.yml"))

    def test_existing_shapes_unbroken(self):
        self.assertTrue(A._covered("* @team\n", "anything/here.txt"))
        self.assertTrue(A._covered("/.github/ @team\n", ".github/workflows/ci.yml"))
        self.assertTrue(A._covered("*.yml @team\n", ".github/workflows/ci.yml"))
        self.assertFalse(A._covered("/docs/*.md @team\n", ".github/workflows/ci.yml"))


class DiagnosticOffer(unittest.TestCase):
    """Task 4: an actionable finding routes to the opt-in $1,500 diagnostic; a clean repo carries no offer."""

    def test_offer_present_when_actionable(self):
        _, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {}),
                             f"/repos/{REPO}/branches/main/protection": (401, {}, {}),
                             f"/repos/{REPO}/rules/branches/main": (200, [], {})}, authenticated=False)
        self.assertGreater(rep["counts"]["HIGH"], 0)
        for needle in ("Agent Authority Diagnostic", "$1,500", "five business days", "opt-in"):
            self.assertIn(needle, files["report.md"])
        self.assertIn("Agent Authority Diagnostic", files["report.html"])
        self.assertNotIn(A.CONTACT, files["report.md"])                 # the offer stays email-free so the report is still forwardable

    def test_no_offer_when_clean(self):
        rules = [{"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                         "require_last_push_approval": True, "dismiss_stale_reviews_on_push": True}}, {"type": "non_fast_forward"}]
        _, rep, files = run({"/user": (200, {"login": "agent-bot"}, {}), f"/repos/{REPO}": repo({"admin": False, "maintain": False, "push": True, "pull": True}, "repo"),
                             f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/branches/main/protection": (404, {}, {}),
                             f"/repos/{REPO}/rules/branches/main": (200, rules, {}),
                             f"/repos/{REPO}/contents/.github/CODEOWNERS?ref=main": codeowners("* @lead\n/.github/ @lead @sec\n")})
        self.assertEqual(rep["counts"]["HIGH"] + rep["counts"]["MEDIUM"], 0)
        self.assertNotIn("Agent Authority Diagnostic", files["report.md"])


if __name__ == "__main__":
    unittest.main()
