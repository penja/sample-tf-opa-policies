version = "v1"

# Every policy in this directory is listed below. A rego file that is not listed
# here is ignored by Scalr.
#
# Enforcement levels:
#   hard-mandatory - the run errors and cannot be overridden.
#   soft-mandatory - the run errors but users with the `policy-checks:override`
#                    permission can override it.
#   advisory       - a warning is shown and the run continues.
#
# Policies that ship with placeholder values (account IDs, subnet IDs, AMI IDs,
# usernames, KMS key names) are disabled by default. Replace the values in the
# corresponding rego file before enabling them.

#-------------------------------------------------------------------------------
# hard-mandatory: security controls that must not be overridable
#-------------------------------------------------------------------------------

policy "enforce_s3_private" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce_s3_buckets_encryption" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce_gcs_private" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce_cidr" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "enforce_ebs_del_on_term" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "denied_provisioners" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "blacklist_provider" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

policy "workspace_destroy" {
  enabled           = true
  enforcement_level = "hard-mandatory"
}

# Requires a real security group ID in enforce_sec_group.rego
policy "enforce_sec_group" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real subnet IDs in enforce_instance_subnet.rego
policy "enforce_instance_subnet" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real subnet IDs in enforce_lb_subnets.rego
policy "enforce_lb_subnets" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real subnet IDs in enforce_rds_subnets.rego
policy "enforce_rds_subnets" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real IAM instance profile names in enforce_iam_instance_profiles.rego
policy "enforce_iam_instance_profiles" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real role ARNs and workspace prefixes in enforce_aws_iam_and_workspace.rego
policy "enforce_aws_iam_and_workspace" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real KMS key aliases in enforce_kms_key_names.rego
policy "enforce_kms_key_names" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real AMI IDs in whitelist_ami.rego
policy "whitelist_ami" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real AWS account IDs in enforce_ami_owners.rego
policy "enforce_ami_owners" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

# Requires real usernames and a commit author domain in check_user.rego
policy "check_user" {
  enabled           = false
  enforcement_level = "hard-mandatory"
}

#-------------------------------------------------------------------------------
# soft-mandatory: guardrails that a privileged user may override
#-------------------------------------------------------------------------------

policy "limit_monthly_cost" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "workspace_environment_type" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "instance_types" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "cloud_location" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "resource_tags" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "required_modules" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "pin_module_version" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "pull_requests" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

# Denies every resource type that is not on the allow list, including all
# non-AWS resources. Review allowed_resources in enforce_aws_resource.rego first.
policy "enforce_aws_resource" {
  enabled           = false
  enforcement_level = "soft-mandatory"
}

#-------------------------------------------------------------------------------
# advisory: warnings only
#-------------------------------------------------------------------------------

policy "enforce_var_desc" {
  enabled           = true
  enforcement_level = "advisory"
}

policy "workspace_name" {
  enabled           = true
  enforcement_level = "advisory"
}

policy "workspace_tags" {
  enabled           = true
  enforcement_level = "advisory"
}

# Demo only: performs an outbound HTTP call to random.org on every evaluation.
policy "random_decision" {
  enabled           = false
  enforcement_level = "advisory"
}

policy "workspace_name_suffix" {
  enabled           = true
  enforcement_level = "advisory"
}
