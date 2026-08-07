# Prevent specified providers from being used.

package terraform

import input.tfplan as tfplan

# Denied Terraform providers
not_allowed_provider := ["azurerm"]

# registry.terraform.io/hashicorp/aws -> aws
get_basename(path) := basename if {
	arr := split(path, "/")
	basename := arr[count(arr) - 1]
}

deny contains reason if {
	resource := tfplan.resource_changes[_]
	action := resource.change.actions[count(resource.change.actions) - 1]
	action in ["create", "update"] # allow destroy action

	provider_name := get_basename(resource.provider_name)
	provider_name in not_allowed_provider

	reason := sprintf(
		"%s: provider type %q is not allowed",
		[resource.address, provider_name],
	)
}
