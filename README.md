# Agent Authority Check

**Find out, in about a minute, what stands between an AI coding agent and your repository's main branch, and whether the credential your agent uses could switch those protections off.**

- **Read-only.** It reads settings through GitHub's API and changes nothing.
- **Little or no access needed.** No admin rights are needed. Public repositories need no token at all.
- **Checkable.** Every finding names the request it came from and gives a plain `curl` command to check it yourself. No login is needed for public repositories.
- **Private.** There is no telemetry. Nothing is sent anywhere except GitHub's API, and no token is ever written to the report.

## Try it

You need Python 3.10 or later.

```bash
pip install git+https://github.com/charles-337/agent-authority-check@v1
agent-authority-check --repo OWNER/NAME
open agent-authority-OWNER-NAME-main/report.html   # one folder per repository and branch; report.md is the same report as text
```

**Which credential it uses:**
- If you are logged in with `gh`, it checks with your login.
- If you are not, it checks a public repository as the public sees it.
- To check the credential your **agent** uses, set it for the run. Read access is enough:

```bash
GITHUB_TOKEN="$AGENT_TOKEN" agent-authority-check --repo OWNER/NAME
```

You'll get one headline finding, for example:

> **This credential can change or remove the protection on `main`.**
> The account is an admin of the repository, and the token carries the `repo` scope, which lets it use those admin rights. If an agent uses this credential, no branch rule holds against it.
> *Check it yourself:* `curl -si -H "Authorization: Bearer $GITHUB_TOKEN" "https://api.github.com/repos/OWNER/NAME" | grep -i -E 'x-oauth-scopes|"admin"'`
> *Fix:* give the agent its own identity (a machine account or a GitHub App) with write access only.

The full example is in [`examples/agent-authority-report/report.md`](examples/agent-authority-report/report.md). It comes from a real run with the names hidden.

The check comes from Haven's Change Passport, which enforces exact-change approvals for AI agents. It is licensed under Apache-2.0.

## What it looks for

| Finding | What it means for an agent |
|---|---|
| Nothing stops a direct push | The branch has no protection at all: any credential with write access can push to it |
| Nothing requires a pull request | The branch is "protected", but the only rules block force-pushes or deletion, so commits can still be pushed straight to it |
| This credential can change or remove the protection | The credential's account is an admin, and the token's scope lets it use those rights |
| An admin account, with token powers unknown | The account is an admin. Fine-grained and app tokens don't reveal their own permissions, so it says so |
| Pull requests need no approval | An author, human or agent, can merge alone |
| An approval stays valid after new commits | A change can be altered after someone approved it |
| Force-pushes allowed, or admins not held to the rules | History can be rewritten, or rules bypassed (shown only when the settings are visible) |
| No owner for the workflows or review rules | Code-owner review can't protect the files that run your checks |

Every report also lists **what protects the branch**, as far as this credential can see: classic protection on or off, and each ruleset rule.

## What it cannot tell you, and says so

- **Classic branch-protection settings:** only repository admins can read them. Rulesets are visible to anyone with read access.
- **What a fine-grained or app token may do:** GitHub doesn't reveal it to a read-only check.
- **Whether GitHub actually refuses a change:** this check reads settings and never tries one. Seeing a setting doesn't prove it holds.

**Limits on runs without a login:** GitHub allows 60 unauthenticated requests an hour, shared with any `curl` checks you run, and each check uses about 6. With `gh` logged in or `GITHUB_TOKEN` set, the limit is 5,000.

**What HIGH means:** an agent holding a write token could get a change onto the branch without the review you probably expect. The check cannot see how many people hold write access.

## Share it

- `report.md` is ready to paste into an issue or a message.
- `report.html` is a single file with nothing to load.
- Add `--anonymize` to replace the repository, owner and user names with placeholders.

## In GitHub Actions (optional)

```yaml
- uses: charles-337/agent-authority-check@v1
  with:
    token: ${{ secrets.AGENT_TOKEN }}         # optional: your agent's token; defaults to the workflow's own token
    fail-on-high: "false"
```

The report appears in the run's summary. The check itself uses only Python's standard library, so the Action installs nothing; the pip package also brings PyYAML, which the Change Passport's other commands use.

## Next step

This check reads configuration. If you want proof that your controls actually stop an agent, Haven can run an isolated live test against a copy of your setup. It covers:
- what the agent may do on its own;
- what needs an exact signed approval;
- what is refused;
- whether its own credential can switch the controls off.

You get evidence you can verify yourself.

- Questions, problems or ideas: open an issue at https://github.com/charles-337/agent-authority-check/issues.
- The live test: charles_337@me.com
