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

When the fix is a setting, the report also prints the exact command that applies it (see [Fixing what it finds](#fixing-what-it-finds)).

The full example is in [`examples/agent-authority-report/report.md`](examples/agent-authority-report/report.md). It comes from a real run with the names hidden.

The check is free and licensed under Apache-2.0. It is published by Haven, which builds controls for AI coding agents (see [Beyond branch settings](#beyond-branch-settings)).

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

The report appears in the run's summary. The check uses only Python's standard library, so neither the Action nor the pip package installs anything else.

## Fixing what it finds

- **Nothing stops a direct push, or nothing requires a pull request:** the report prints one `gh api` command that adds the missing ruleset. Read its JSON before you run it; it asks for:
  - a pull request with at least one approval, from a code owner where a CODEOWNERS file names one (with no CODEOWNERS file, that part requires nothing);
  - approvals dismissed when new commits are pushed, and the last push approved by someone other than whoever pushed it, so a change can't be altered after approval;
  - no force-push and no deletion.

  You run it as a repository admin; the check itself never writes. If you work alone, nobody else can approve your pull requests, so the report prints a second command to use instead. It lets repository admins merge a pull request without another approval, and nothing more: no one may push directly, and anyone without admin rights, an agent included, still needs someone else's approval.
- **The credential can switch protection off:** no command can fix this for you. Give the agent its own identity with write access only, either a machine account or a GitHub App, and give the agent only that identity's token. Then run the check again with that token.
- After each fix, run the check again. The finding you fixed should be gone.

## Beyond branch settings

Branch rules decide what may land on a branch. They treat every pull request the same, whoever wrote it, and they see nothing an agent does before it pushes. Haven's guard is for teams that want to give a coding agent more room without losing control of what matters:

- **One authority rule per agent:** what it may merge itself, what needs a person's signed approval of that exact change, and what it may never touch.
- **A check inside the agent's session:** a Claude Code hook stops a protected action before it runs, including edits to the agent's own rules or keys.
- **A receipt for every decision:** hash-chained, so an edited receipt is caught. Rewriting the whole chain is caught only against a copy of its last hash kept somewhere else.

**What has been shown, in a sandbox with a live Claude Code agent.** A local repository stood in for GitHub, with Haven's check running inside it instead of GitHub's review rules:
- the agent's routine change was allowed and reached main with no review;
- its push of a production change was stopped before it ran, because no one had signed an approval of that exact change;
- the same commit, pushed separately with the hook out of the way, was refused by that repository's own check;
- its attempt to edit the guard's settings was refused.

**Not yet shown: enforcement on GitHub itself.**
- On GitHub, letting an agent merge routine changes without a person means replacing the approval rule above with a required check that only Haven can report. That is designed, not yet tested.
- Until then, the fixes above require a person's approval for every agent change.
- The guard is a boundary only where the agent's own credential can't switch the branch rules off, which is why those fixes come first.

The guard isn't published. Haven sets it up for one agent workflow against a copy of your setup, then reports what it allowed, held and refused, with evidence you can check yourself.

- Questions, problems or ideas: open an issue at https://github.com/charles-337/agent-authority-check/issues.
- The guard: charles_337@me.com
