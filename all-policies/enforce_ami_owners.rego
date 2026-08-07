# Enforces all aws_ami data sources to have an owners list of allowed values only
# (the actual presence of a non-empty `owners` attribute
# is validated by the Terraform AWS provider itself since v2.0.0).

package terraform

import input.tfplan as tfplan

# The list of owners aws_ami data sources are limited to.
# Valid values are: an AWS account ID, `self` (the current account),
# or an AWS owner alias (e.g. `amazon`, `aws-marketplace`, `microsoft`)
allowed_owners := [
	"self",
	"012345678901",
]

ami_owners_eval_expression(plan, expr) := constant_value if {
	constant_value := expr.constant_value
} else := reference if {
	ref := expr.references[0]
	startswith(ref, "var.")
	var_name := replace(ref, "var.", "")
	reference := plan.variables[var_name].value
}

deny contains reason if {
	walk(tfplan.configuration.root_module, [_, value])
	value.mode == "data"
	value.type == "aws_ami"
	owners := ami_owners_eval_expression(tfplan, value.expressions.owners)
	some owner in owners
	not owner in allowed_owners

	reason := sprintf(
		"%s: owner %q is not allowed. Expected owners are: %v",
		[value.address, owner, allowed_owners],
	)
}
