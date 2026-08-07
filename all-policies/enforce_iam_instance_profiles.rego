# Validate that the iam_instance_profile is in the allowed list.

package terraform

import input.tfplan as tfplan

allowed_iam_profiles := [
	"my_iam_profile",
	"my_iam_profile_2",
	"my_iam_profile_3",
]

# The attribute is either a list of objects with a name, or a plain string.
iam_profile_name(expr) := name if {
	name := expr[_].name
} else := iamp if {
	iamp := expr
}

deny contains reason if {
	resource := tfplan.resource_changes[_]
	iam := iam_profile_name(resource.change.after.iam_instance_profile)
	not iam in allowed_iam_profiles

	reason := sprintf(
		"%-40s :: iam_instance_profile '%s' is not allowed.",
		[resource.address, iam],
	)
}
