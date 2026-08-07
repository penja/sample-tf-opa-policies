# Enforces a set of required tag keys. Values are not checked.

package terraform

import input.tfplan as tfplan

required_tags := ["owner", "department"]

# registry.terraform.io/hashicorp/google -> google
get_basename(path) := basename if {
	arr := split(path, "/")
	basename := arr[count(arr) - 1]
}

# Extract the tags catering for Google where they are called "labels"
get_tags(resource) := labels if {
	provider_name := get_basename(resource.provider_name)
	provider_name == "google"
	labels := resource.change.after.labels
} else := tags if {
	tags := resource.change.after.tags
} else := {}

deny contains reason if {
	resource := tfplan.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	action in ["create", "update"]
	tags := get_tags(resource)
	some required_tag in required_tags
	not tags[required_tag]

	reason := sprintf(
		"%s: missing required tag %q",
		[resource.address, required_tag],
	)
}
