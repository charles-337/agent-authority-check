# Deployment gate — manual owner checklist

This branch prepares customer-facing material; it **does not** deploy v1.2.0, register a GitHub App, prove G3 or publish a repository. The existing local `publish-v1.2.0.sh` remains the intended release path. Do **not** replace the source-of-truth implementation with this documentation-only PR.

1. Review all repository history for secrets, private data, and unintended proprietary material, plus the public example for credible anonymization. Removing a file in a new commit does not remove it from Git history.
2. Review and approve exact public terms and contact address in `commercial/START_HERE.md` and `commercial/MEASUREMENT_AND_TERMS.md`; settle version and license semantics.
3. Run the existing owner's v1.2.0 publish preparation and compare the **exact distribution files** it copies against the public checkout. Use its printed PR/tag instructions; do not silently force-push or bypass checks.
4. Rebase/cherry-pick the narrow commercial docs and issue template after the release preparation if necessary. Check `README.md` manually for both v1.2.0's integrated diagnostic CTA and a link to `commercial/START_HERE.md`; don't overwrite a newer README with an old copy.
5. Run the public test suite and actual install from a clean third-party environment. This verifies software packaging, **not** adoption, payment, GitHub enforcement or economic recovery.
6. Have the owner decide public visibility and approve the deployment. Publicize only after step 1. Neither a public repo nor a GitHub issue creates verified installation telemetry.
7. Capture one *voluntary* external run with its source evidence, secure an explicit buyer opt-in, sign scope, deliver findings, and record invoice/payment separately. Never record those events ahead of evidence.
8. G3 is a **separate security proof**: create/install the minimal-permission GitHub App, pin the required check to its `app_id` or ruleset `integration_id`, disallow modifications to policy and signer files, and run all four adversarial tests on a disposable repo. Absent the receipts: `G3 = INCOMPLETE`.

**Stop conditions:** exposed secrets, unapproved publication, inability to reproduce required checks, private-repo restrictions masquerading as negative findings, absent financial source access, unverifiable baseline, or missing owner approval.
