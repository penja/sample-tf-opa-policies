# Implements an allowed list of resource types.
#
# NOTE: This policy would also prevent the use of all providers except AWS.
#       To allow other clouds with no restrictions on resource types add the following line to the rule
#       before "not resource.type in allowed_resources"
#
#       startswith(resource.type, "aws_")

package terraform

import input.tfplan as tfplan

# Allowed Terraform resources
allowed_resources := [
	"aws_security_group",
	"aws_instance",
	"aws_s3_bucket",
]

deny contains reason if {
	resource := tfplan.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	action in ["create", "update"] # allow destroy action

	not resource.type in allowed_resources

	reason := sprintf(
		"%s: resource type %q is not allowed",
		[resource.address, resource.type],
	)
}
