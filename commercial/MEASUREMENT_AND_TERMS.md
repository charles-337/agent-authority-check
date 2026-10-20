# Haven — commercial engagement and verification standard

**Discussion draft for customer-specific written agreement, not a substitute for legal review or a signed contract.** The two offers below have different deliverables and different fee triggers. No GitHub issue, email, or free scan constitutes acceptance.

## A. Agent Authority Diagnostic

**Price:** $1,500 fixed, invoiced on delivery, with the payable date stated in the signed order. **Scope:** one repository and one agent workflow/credential. **Start:** after an authorized owner agrees to scope and supplies adequate read-only access. **Time:** five business days from that start, barring an agreed dependency pause.

**Deliverables:** an identified access/policy finding, redacted reproducible read evidence, actionable remediation instructions, and a post-remediation recheck if the customer makes the change in scope. Where a settings endpoint is inaccessible, record `UNKNOWN` rather than claiming absence of protection. Deliveries specify whether they show (i) policy configuration, (ii) local/sandbox rejection, or (iii) enforcement by GitHub itself. The engagement is **not** a compliance audit, security guarantee, penetration test, or fully managed GitHub App deployment.

**Customer responsibilities:** own accounts and repository rights; approve all mutations; safeguard tokens; avoid providing production credentials to Haven; test any changes before production. Haven does not merge, change protection, or install Apps without express authorization.

**Acceptance:** delivery of the agreed evidence package, even if its conclusion is that an unknown cannot be resolved with granted access. Any remedial implementation, GitHub App rollout or adversarial test is separately scoped.

## B. Economic Outcome Verification Pilot

**Price:** one $1,000 contingent success fee per individually signed pilot; no upfront payment. Not a 10–20% commission. Invoicing is permitted **only** if the frozen standard below establishes a realized, attributable **owner net after Haven's fee greater than zero**.

### Mandatory freeze before correction

The parties sign an evidence plan identifying: the claim; actor; authorized action; immutable before state and timestamp; agreed counterfactual; admissible authenticated financial records; settlement definition; observation window; currency and conversion rule; attribution method and confidence threshold; reversals/chargebacks; incremental execution, verification, review, rework and loss costs; disputes and retention limits.

### Gate implementation

- **AUTHORIZATION:** the customer identified a permitted action and the accountable signer. No self-authorization by an agent.
- **SOURCE:** an independent, authorized observation of the genuine system of record; record provider, query identifiers, timestamps, account scope, and a content hash. A customer/agent-supplied spreadsheet alone is insufficient.
- **REALIZATION:** prove separately whether a ledger amount changed, funds were captured, funds were transferred, and funds were ultimately received. A Stripe charge, pending payout, credit memo or accounting adjustment alone is **not** bank-settled cash.
- **ATTRIBUTION:** compare to the frozen counterfactual and disclose method, exclusions, missing evidence, and confidence. Post-hoc stories cannot manufacture a causal baseline.
- **ECONOMICS:** realized attributable benefit in agreed currency minus **all** attributable costs, including the $1,000 Haven fee. Require result > 0 and no unpriced material costs; do not double count an adjustment and associated cash receipt.
- **FINALITY:** classify VERIFIED, REFUTED, INCONCLUSIVE, UNOBSERVED or DISPUTED. Any absent prerequisite, ambiguous causation, unresolved reversals or dispute means **no success-fee invoice**. A positive finding is not an invoice unless the agreement's trigger is met.

**Correction authority:** the customer alone executes changes and moves funds. Haven receives least-privileged read-only access where supported, or observes an authorized customer-run query whose independence and integrity are documented. Haven is not a licensed audit or attestation service.

**Reversals:** the signed agreement specifies a holdback/observation period and refund or credit if a qualifying recovery reverses. Pending settlement is not VERIFIED. Customer net and Haven's actually collected revenue are reported separately.

**Evidence and data:** no GitHub issue uploads of private ledgers, bank details, secrets or personal data. Preserve source references, hashes, exact time windows and verification limitations; establish deletion and access-revocation procedures before any access.

## Commercial gates, never backfilled

`external_install` requires evidence of a third-party run (not a clone counter). `qualified_opt_in` needs an accountable human explicitly requesting a conversation. `pilot_agreed` requires a signed scope. `report_delivered` requires the actual report. `outcome_verified` requires the independent evidence standard above. `invoice_issued` and `cash_received` are distinct events. `repeat` requires another buyer-approved purchase. None can be inferred from an agent's claim, test pass, report view or internal score.

**Product direction:** only an independently verified, authorized and economically valuable outcome may justify a proposed increase in agent funding or authority, and any increase remains inside explicit owner-approved constraints.
