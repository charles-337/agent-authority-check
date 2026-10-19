# Haven — from an agent finding to a verified outcome

**Two distinct engagements. Do not confuse repository configuration with money recovered.**

Haven is built around one rule: the agent that acted cannot certify its own success.

## 1. Free Agent Authority Check — available as software

Run the read-only [Agent Authority Check](../README.md) against a repository using **the credential the agent actually uses**. It reads GitHub settings, names the API evidence and gives reproducible checks. It cannot prove that GitHub actually rejects a hostile change, and it does not attempt one.

```bash
pip install git+https://github.com/charles-337/agent-authority-check@v1
GITHUB_TOKEN="$AGENT_TOKEN" agent-authority-check --repo OWNER/REPO
```

The credential needs read access. Use a **test or separately scoped credential**, never an administrator's production secret. The report stays local; this tool has no telemetry.

If you receive a HIGH or MEDIUM finding, do not post a token, private report, financial record, customer name, or private repository detail in a public issue.

## 2. Agent Authority Diagnostic — $1,500 fixed

**One repository · one agent credential / workflow · five business days after access and scope are agreed · invoice on delivery.**

For an accountable engineering or security owner with an actionable finding, Haven delivers:

1. An evidence table showing what the assessed credential can reach and what the read-only check cannot know.
2. One prioritized remediation plan, including a minimal-change option and the customer's owner-controlled deployment steps.
3. Independent re-check commands and a before/after result for changes actually applied by the customer.
4. A limitation statement: configured policy, local enforcement, and GitHub-enforced blocking are **different levels of proof**. A live GitHub App adversarial test is not included unless separately agreed and actually run.

**Qualification:** provide the finding category, repository visibility (public/private), whether your coding agent has a dedicated credential, and a responsible technical owner. No secret is needed to request a diagnostic.

**Start:** [Open a sanitized request](../issues/new?template=authority-diagnostic.yml), or send a **private** inquiry to charles_337@me.com with the subject `Haven Authority Diagnostic`. We reply with a private scope and delivery agreement. Posting a GitHub issue is **not** ordering or authorizing work.

## 3. Economic Outcome Verification Pilot — $1,000 contingent fee

**No upfront fee; payable only for a verified, realized, attributable, positive owner net benefit under a signed measurement agreement.**

This is a different service, not an output of the GitHub check. A candidate engagement needs:
- a specific historical or prospective financial claim; an accountable customer owner;
- an authenticated, customer-authorized system of record that Haven can independently read or observe, not an agent's screenshot or narration;
- a baseline and counterfactual agreed and frozen **before** corrective action;
- evidence of actual receipt/settlement where cash recovery is claimed, plus separate cost evidence;
- a customer-controlled correction path. Haven does not move money or perform corrections.

The receipt separates **changed ledger balance**, **cash paid/transferred**, **causal confidence**, **all costs**, and **customer net**. It can report `VERIFIED`, `REFUTED`, `INCONCLUSIVE`, `UNOBSERVED` or `DISPUTED`. An unverifiable or nonpositive result costs $0 under the pilot fee term. See [measurement and engagement terms](MEASUREMENT_AND_TERMS.md).

**Start:** email charles_337@me.com with subject `Haven Economic Outcome Pilot` and a **non-sensitive** description of the use case and the system-of-record vendor (e.g. ERP or billing platform). Never email credentials, transaction records or customer personal data in an unsolicited inquiry. Access is designed and authorized after scope agreement.

## What is and is not demonstrated today

The free repository analyzer has been tested in the owner's environment. The external GitHub App G3 adversarial proof is **not verified**; a runbook is not its execution. No published example is evidence of a real customer's financial recovery, and no example receipt creates a payment claim.

**The payment contract does not influence the verdict.** A contract, a read-only source integration, actual external use and any subsequent payment must each be evidenced separately.

**Privacy:** initial inquiry requires only redacted summary information. Sensitive access must be explicitly scoped, time-limited, least privileged, and documented in a separate agreement. We do not ask for credentials through GitHub issues.
