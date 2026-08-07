# all-policies

Every sample policy from this repository collected into a single flat directory,
rewritten for **Rego v1** (OPA 1.0+), plus one `scalr-policy.hcl` that declares all
of them with a spread of enforcement levels.

Point a Scalr policy group at this directory to get the whole catalogue in one
place instead of attaching each per-policy directory separately.

## Layout

```
all-policies/
├── scalr-policy.hcl     # declares all 31 policies, enabled flag + enforcement level
└── <policy_name>.rego   # one file per policy, package terraform
```

The policy name in `scalr-policy.hcl` must match the rego file name without the
`.rego` extension. A rego file that is not declared there is ignored by Scalr.

## What is different from the per-policy directories

* **Rego v1 syntax** — `deny contains reason if { ... }`, `f(x) := y if { ... }`,
  and the `in` operator instead of the hand-rolled `array_contains` helper.
  Verified with `opa check --strict`.
* **No `*_test.rego` / `*_mock.json`** — all policies share `package terraform`,
  so test rules and mock data documents from different policies would collide on
  identical names (`test_valid`, `data.mock.valid`, …). The tests stay in the
  per-policy directories, which is also where CI runs them.
* **Helpers renamed to be unique.** `eval_expression` had different bodies (and
  one different arity) in six policies. In a shared package that produces
  conflicting outputs at evaluation time, so each is now prefixed, e.g.
  `kms_eval_expression`, `cloud_location_eval_expression`. The same applies to
  `allowed_subnets`, which is now `instance_allowed_subnets`,
  `lb_allowed_subnets` and `rds_allowed_subnets`.
* **`enforce_s3_private` also catches `public-read`, `public-read-write` and
  `authenticated-read`**, and the standalone `aws_s3_bucket_acl` resource. The
  original only matched the literal ACL value `"public"`, which Terraform never
  produces.
* **`enforce_sec_group` is scoped to `aws_instance`.** The original matched every
  resource that had a `vpc_security_group_ids` attribute.
* **Placeholder-driven policies are disabled by default.** Anything referencing a
  fake subnet ID, AMI ID, account ID, KMS alias or username ships with
  `enabled = false`. Replace the values, then flip the flag.

## Important caveat

All files use `package terraform`, which Scalr requires. Scalr evaluates each
declared rego file on its own, so the per-file `deny` sets and the per-file
enforcement levels stay separate. If you load this directory into plain OPA as a
single bundle instead, every `deny` merges into one `data.terraform.deny` set and
the enforcement levels lose their meaning. Validate with
`opa check --strict all-policies/`; do not `opa eval data.terraform.deny` against
the whole directory and expect per-policy results.

## Validating locally

```bash
opa check --strict all-policies/
opa eval --format pretty --data all-policies/enforce_s3_private.rego -i plan.json data.terraform.deny
```

Note that `-i plan.json` must be the Scalr input shape (`{"tfplan": ..., "tfrun": ...}`),
not a bare `terraform show -json` output.
