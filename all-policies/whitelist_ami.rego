# This policy introduces an AMI id allow list for AWS instances.
# There are two rules: the first one disallows the usage of
# all AMIs that are not from the allowed list,
# while the second rule allows only directly (or via variable) specified AMIs
# thus allowing them to be pulled from an aws_ami data source.
# You will probably want to keep only one rule that is relevant for you,
# removing/commenting out the other.

package terraform

import input.tfplan as tfplan

# An allow list of AMI ids
allowed_amis := [
	"ami-07d0cf3af28718ef8",
	"ami-0a9b2a20d7dc001e0",
]

whitelist_ami_eval_expression(plan, expr) := constant_value if {
	constant_value := expr.constant_value
} else := reference if {
	ref := expr.references[0]
	startswith(ref, "var.")
	var_name := replace(ref, "var.", "")
	reference := plan.variables[var_name].value
}

whitelist_ami_get_address(value) := address if {
	address := value.address
} else := source if {
	source := value.source
}

# Force all found AMIs to belong to the allowed list
deny contains reason if {
	resource := tfplan.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	action in ["create", "update"]
	ami := resource.change.after.ami
	not ami in allowed_amis

	reason := sprintf(
		"%s: AMI %q is not allowed. Expected values are: %v",
		[resource.address, ami, allowed_amis],
	)
}

# Force directly specified AMIs to belong to the allowed list,
# but allow AMIs from a data source
deny contains reason if {
	walk(tfplan.configuration.root_module, [_, value])
	ami := whitelist_ami_eval_expression(tfplan, value.expressions.ami)
	not ami in allowed_amis

	reason := sprintf(
		"%s: AMI %q is not allowed.\nAMI id should be pulled from an aws_ami data source\nor otherwise be one of the allowed ones when specified directly:\n%v",
		[whitelist_ami_get_address(value), ami, allowed_amis],
	)
}
