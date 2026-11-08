# Haven — commercial engagement and verification standard

**Discussion draft for customer-specific written agreement, not a substitute for legal review or a signed contract.** It covers the one paid offer. No GitHub issue, email, or free scan constitutes acceptance.

## Agent Authority Diagnostic

**Price:** $1,500 fixed, invoiced on delivery, with the payable date stated in the signed order. **Scope:** one repository and one agent workflow/credential. **Start:** after an authorized owner agrees to scope and supplies adequate read-only access. **Time:** five business days from that start, barring an agreed dependency pause.

**Deliverables:** an identified access/policy finding, redacted reproducible read evidence, actionable remediation instructions, and a post-remediation recheck if the customer makes the change in scope. Where a settings endpoint is inaccessible, record `UNKNOWN` rather than claiming absence of protection. Deliveries specify whether they show (i) policy configuration, (ii) local/sandbox rejection, or (iii) enforcement by GitHub itself. The engagement is **not** a compliance audit, security guarantee, penetration test, or fully managed GitHub App deployment.

**Customer responsibilities:** own accounts and repository rights; approve all mutations; safeguard tokens; avoid providing production credentials to Haven; test any changes before production. Haven does not merge, change protection, or install Apps without express authorization.

**Acceptance:** delivery of the agreed evidence package, even if its conclusion is that an unknown cannot be resolved with granted access. Any remedial implementation, GitHub App rollout or adversarial test is separately scoped.

## Commercial gates, never backfilled

`external_install` requires evidence of a third-party run (not a clone counter). `qualified_opt_in` needs an accountable human explicitly requesting a conversation. `engagement_agreed` requires a signed scope. `report_delivered` requires the actual report. `invoice_issued` and `cash_received` are distinct events. `repeat` requires another buyer-approved purchase. None can be inferred from an agent's claim, test pass, report view or internal score.

**Product direction:** only an independently verified, authorized and economically valuable outcome may justify a proposed increase in agent funding or authority, and any increase remains inside explicit owner-approved constraints.
