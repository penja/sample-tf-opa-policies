# Multi provider rule to enforce instance type/size.

package terraform

import input.tfplan as tfplan

# Allowed sizes by provider
allowed_types := {
	"aws": ["t2.nano", "t2.micro"],
	"azurerm": ["Standard_A0", "Standard_A1"],
	"google": ["n1-standard-1", "n1-standard-2"],
}

# Attribute name for instance type/size by provider
instance_type_key := {
	"aws": "instance_type",
	"azurerm": "vm_size",
	"google": "machine_type",
}

# registry.terraform.io/hashicorp/aws -> aws
get_basename(path) := basename if {
	arr := split(path, "/")
	basename := arr[count(arr) - 1]
}

# Extracts the instance type/size
get_instance_type(resource) := instance_type if {
	provider_name := get_basename(resource.provider_name)
	instance_type := resource.change.after[instance_type_key[provider_name]]
}

deny contains reason if {
	resource := tfplan.resource_changes[_]
	instance_type := get_instance_type(resource)
	provider_name := get_basename(resource.provider_name)
	not instance_type in allowed_types[provider_name]

	reason := sprintf(
		"%s: instance type %q is not allowed",
		[resource.address, instance_type],
	)
}
