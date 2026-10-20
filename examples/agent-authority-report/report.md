# Agent Authority Check: <repository> @ `<branch>`

**Nothing stops a direct push to `<branch>`.**

Credential: <owner> (via your gh login) · 2026-10-20T03:17:35+00:00

**What protects `<branch>`** (as visible to this credential)

- Classic branch protection: off (public branch data: protection.enabled = false)
- Rulesets: none apply

### HIGH: Nothing stops a direct push to `<branch>`.

`<branch>` has no branch protection and no ruleset. Any credential with write access, including a token you give a coding agent, can push straight to it: no pull request, review or check is required. The repository has a .github/CODEOWNERS file, but nothing enforces it on `<branch>`.

- Evidence: R3: protected = false; R5: no rule governs pushes to this branch
- Check it yourself: `curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/<repository>/branches/<branch>" | grep -i -E '"protected"|"enabled"'; curl -s -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/<repository>/rules/branches/<branch>"` (expect "protected": false and "enabled": false, then no rule whose type governs pushes to this branch)
- Fix: Protect `<branch>` (Settings › Rules or Branches): require a pull request with at least one approval, from a code owner where a CODEOWNERS file names one; a new push dismisses earlier approvals, and the last push must be approved by someone other than whoever pushed it; block force-pushes and deletion.

Apply it as a repository admin, logged in with `gh` (this check itself changes nothing):

```bash
echo '{"name":"Protect <branch>","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["refs/heads/<branch>"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":true,"required_review_thread_resolution":false}}]}' | gh api --method POST "repos/<repository>/rulesets" --input -
```

Working alone? Nobody else can approve your pull requests, so run this instead. It lets repository admins, meaning you, merge a pull request without another approval, and nothing else: no one may push directly, and anyone without admin rights, an agent included, still needs someone else's approval, which in a repository you run alone means yours. An agent holding an admin's credential could merge the same way, which is why the credential finding matters.

```bash
echo '{"name":"Protect <branch>","target":"branch","enforcement":"active","conditions":{"ref_name":{"include":["refs/heads/<branch>"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":true,"required_review_thread_resolution":false}}],"bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"pull_request"}]}' | gh api --method POST "repos/<repository>/rulesets" --input -
```

On a private repository, GitHub's free plans may not offer rulesets; its answer will say so.

### HIGH: This credential can change or remove the protection on `<branch>`.

`<owner>` is an admin of <repository>, and the token carries the `repo` scope, which lets it use those admin rights: it can edit or delete branch protection and rulesets. If an agent uses this credential, no branch rule holds against it.

- Evidence: R2: permissions.admin = true; R2: response header X-OAuth-Scopes = gist, read:org, repo
- Check it yourself: `curl -si -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/<repository>" | grep -i -E 'x-oauth-scopes|"admin"'` (expect x-oauth-scopes listing repo, and "admin": true)
- Fix: Give the agent its own GitHub identity, with write access and never admin: a machine account added as a collaborator with write access, or a GitHub App with Contents and Pull requests set to read and write and Administration set to no access. Give the agent only that identity's token, keep admin with people, and run the agent where it cannot reach their credentials.

### After a fix

- Run the check again: `agent-authority-check --repo <repository>`. The finding you fixed should be gone.
- With the agent's new token: `GITHUB_TOKEN="$AGENT_TOKEN" agent-authority-check --repo <repository>`. A machine account with write access should show "This credential cannot change the repository's protections."

### Cannot be determined from here

- Whether GitHub refuses a change in practice: this check reads settings and never tries one. A ruleset's bypass list — which actors may skip its pull-request rule — is not returned by GitHub's rules API, so ruleset bypass actors are not visible here (classic bypass allowances, when readable, are reported above).

### How this was checked

Read-only: only GET requests, nothing changed. Findings are configuration facts read from GitHub; they show what is configured and what a credential is permitted to do, not what GitHub will refuse in practice.

| | Request | HTTP |
|---|---|---|
| R1 | `GET /user` | 200 |
| R2 | `GET /repos/<repository>` | 200 |
| R3 | `GET /repos/<repository>/branches/<branch>` | 200 |
| R4 | `GET /repos/<repository>/branches/<branch>/protection` | 403 |
| R5 | `GET /repos/<repository>/rules/branches/<branch>` | 403 |
| R6 | `GET /repos/<repository>/contents/.github/CODEOWNERS?ref=<branch>` | 200 |

### Beyond branch settings

Fix the findings above first: the guard does not replace branch rules, and it holds only where the agent's own credential cannot switch them off. This check is free. Haven, which publishes it, also builds a guard for coding agents, because branch rules treat every pull request the same, whoever wrote it: one authority rule per agent (what it may merge itself, what needs a person's signed approval of that exact change, and what it may never touch), a check inside the agent's session that stops a protected action before it runs, and a receipt for every decision.

If you would rather have it mapped for your repository — exactly what your coding agent's credential can do to this branch, whether it could switch the rules off, who can bypass them, the fix, and a re-check under the agent's own read-only token confirming the finding is gone and that token cannot switch the rules off — that is Haven's opt-in Agent Authority Diagnostic: fixed $1,500, five business days after access and scope are agreed, invoiced on delivery. Shown in a sandbox, not yet on GitHub. Details: https://github.com/charles-337/agent-authority-check#beyond-branch-settings

_Generated by the Haven Agent Authority Check: read-only, no data sent anywhere but GitHub's API._
