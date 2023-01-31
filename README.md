# Cloud Cost Tag Checker

Read-only audit of normalized multi-provider resource inventory exports against required cost-center, owner, and environment tags. Offline; no provider credentials, API calls, tagging writes, or auto-exceptions. Node.js 22+, zero dependencies. `src/index.mjs` exports `checkCostTags(inventory, policy, {now, deadline})` and `TOOL_ID`.

```sh
node bin/cloud-cost-tag-checker.mjs --root examples --policy policy.json --inventory passing-inventory.json
node bin/cloud-cost-tag-checker.mjs --root examples --policy policy.json --inventory failing-inventory.json
```

The synthetic examples exit 0 and 1 respectively. Policy is `{"schemaVersion":"1","asOf":"2026-09-26T00:00:00Z","requiredTags":[{"key":"cost-center","allowedValues":["CC-1"]},{"key":"owner","allowedValues":["team-a"]},{"key":"environment","allowedValues":["test"]}],"exceptions":[]}`. All three keys are mandatory; allowed values are exact and case-sensitive. `asOf` is an explicit UTC instant, never the machine clock. Inventory is `{"schemaVersion":"1","complete":true,"resources":[{"provider":"aws","resourceId":"synthetic-r1","tags":{"cost-center":"CC-1","owner":"team-a","environment":"test"}}]}`. Supported provider names are `aws`, `azure`, `gcp`. Tag **names** are case-sensitive for AWS/GCP, case-insensitive for Azure. Case-colliding Azure names are ambiguous, never green. Empty or whitespace-only owner fails.

An inventory resource may declare `excluded:true` only with an exact matching policy exception `{provider,resourceId,reason,expiresAt}`. Reason must be nonblank, expiry must be a valid UTC instant strictly after `asOf`, and each exception targets one provider/resource identity. Missing or expired approval fails; malformed exception policy is invalid configuration. A policy exception does not itself exclude an unmarked resource. Reasons, identifiers, and tag values are never echoed.

| Rule ID | Severity | Meaning |
| --- | --- | --- |
| policy-invalid | warning | invalid policy (CLI rejects configuration) |
| inventory-invalid | warning | missing/unsupported or duplicate inventory shape |
| inventory-incomplete | warning | export declares partial coverage |
| provider-unsupported | warning | provider outside pinned comparison rules |
| tag-ambiguous | warning | case-fold collision under provider rule |
| limit-exceeded | warning | byte, record, depth, or time bound exceeded |
| input-unreadable | warning | inventory cannot be read/decoded/parsed |
| required-tag-missing | error | required tag absent |
| blank-owner | error | owner empty after trimming whitespace |
| tag-value-not-allowed | error | value not on exact allowlist |
| exclusion-unapproved | error | scoped approval absent |
| exclusion-expired | error | approval expired at declared `asOf` |

The v1 report uses code-unit-sorted findings. `@policy` and `@inventory` are logical source roles, not host paths; JSON pointers and zero-based resource ordinals identify evidence in the invocation's files. Exit 0 pass, 1 completed policy failure, 2 incomplete or invalid configuration. Invalid option/policy/path gives empty stdout and bounded stderr; unreadable or ambiguous inventory gives an incomplete report on stdout. Root must be a directory and all input files relative and realpath-confined under it.

Limits: policy ≤64 KiB, inventory ≤1 MiB, ≤1000 resources, ≤100 policy exceptions, ≤100 tags per resource, JSON depth ≤16, injected evaluation deadline 5 seconds. Strict UTF-8 and duplicate JSON key checks include escaped aliases. Exceeded limits are incomplete. This checker trusts the export's `complete` assertion; it cannot discover missing cloud resources, verify provider tag propagation/billing attribution, or validate an exception's business justification. Run `npm run check` for syntax and tests.
