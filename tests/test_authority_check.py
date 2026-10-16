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
        none = [{"type": "pull_request", "parameters": {"required_approving_review_count": 0, "require_code_owner_review": False}}]
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, none, {})}, False)
        self.assertIn("no-approval-required", [f["id"] for f in rep["findings"]])
        stale = [{"type": "pull_request", "parameters": {"required_approving_review_count": 2}}]
        _, rep, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": True}, {}), f"/repos/{REPO}/rules/branches/main": (200, stale, {})}, False)
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
        _, rep, files = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {})}, authenticated=False)
        for f in rep["findings"]:
            self.assertTrue(f["verify"].startswith('curl -s'), f["verify"])
            self.assertIn('"https://', f["verify"])                                              # quoted: safe in zsh
            self.assertNotIn("gh api", f["verify"])
        for name in ("report.md", "report.html"):
            self.assertNotIn(A.CONTACT, files[name])                                              # no sales pitch in what gets forwarded
            self.assertNotIn("sha256", files[name])                                               # no evidence a reader cannot check

    def test_fail_on_high_for_ci(self):
        code, _, _ = run({f"/repos/{REPO}": repo(), f"/repos/{REPO}/branches/main": (200, {"protected": False}, {})}, False, ["--fail-on-high"])
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

    def test_the_page_escapes_what_it_shows(self):
        page = A.page({"repository": "<script>x</script>", "branch": "main", "verdict": "v", "credential": "c", "generated_at": "t", "protects": ["<b>"],
                       "findings": [], "cannot_determine": [], "limits": "l", "evidence": []})
        self.assertNotIn("<script>x", page)


if __name__ == "__main__":
    unittest.main()
