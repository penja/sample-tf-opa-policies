# Restricts IAM roles for provider and workspace.

package terraform

import input.tfplan as tfplan
import input.tfrun as tfrun

allowed_roles_map := {
	"arn:aws:iam::4423:role/dev": ["test-", "qa-", "staging-", "dev-"],
	"arn:aws:iam::4422:role/release_admin": ["prod-", "demo-", "test-", "qa-", "staging-", "dev-"],
}

# Configuration may be a constant value or a reference to a variable.
iam_ws_eval_expression(plan, expr) := constant_value if {
	constant_value := expr.constant_value
} else := reference if {
	ref := expr.references[0]
	startswith(ref, "var.")
	var_name := replace(ref, "var.", "")
	reference := plan.variables[var_name].value
}

# Extracts provider configs for AWS from the input
aws_provider_aliases[alias] := provider if {
	provider := tfplan.configuration.provider_config[alias]
	provider.name == "aws"
}

# Creates a map of providers to role arn from AWS list created above
providers_roles_arn[alias] := role_arn if {
	provider := aws_provider_aliases[alias]
	role_arn := iam_ws_eval_expression(tfplan, provider.expressions.assume_role[0].role_arn)
}

# Check the role in the provider against the allowed list for each provider in the input
deny contains reason if {
	role_arn := providers_roles_arn[alias]
	not allowed_roles_map[role_arn]

	reason := sprintf(
		"%s: AWS provider with role %q is not allowed",
		[alias, role_arn],
	)
}

# Uses the map to match workspaces to roles. Only workspaces containing elements of the map for a given
# role will be allowed.
deny contains reason if {
	role_arn := providers_roles_arn[alias]
	workspaces := allowed_roles_map[role_arn]
	workspace_name := tfrun.workspace.name
	count([ws_pattern |
		some ws_pattern in workspaces
		contains(workspace_name, ws_pattern)
	]) == 0

	reason := sprintf(
		"%s: Workspace %q is not allowed to use role %q",
		[alias, workspace_name, role_arn],
	)
}
