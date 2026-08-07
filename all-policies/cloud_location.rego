# Enforce a list of allowed locations / availability zones for each provider.

package terraform

import input.tfplan as tfplan

allowed_locations := {
	"aws": ["us-east-1", "us-east-2"],
	"azurerm": ["eastus", "eastus2"],
	"google": ["us-central1-a", "us-central1-b", "us-west1-a"],
}

# registry.terraform.io/hashicorp/aws -> aws
get_basename(path) := basename if {
	arr := split(path, "/")
	basename := arr[count(arr) - 1]
}

cloud_location_eval_expression(plan, expr) := constant_value if {
	constant_value := expr.constant_value
} else := reference if {
	ref := expr.references[0]
	startswith(ref, "var.")
	var_name := replace(ref, "var.", "")
	reference := plan.variables[var_name].value
}

cloud_location_get_location(resource, plan) := aws_region if {
	provider_name := get_basename(resource.provider_name)
	provider_name == "aws"
	provider := plan.configuration.provider_config[_]
	provider.name == "aws"
	region_expr := provider.expressions.region
	aws_region := cloud_location_eval_expression(plan, region_expr)
} else := azure_location if {
	provider_name := get_basename(resource.provider_name)
	provider_name == "azurerm"
	azure_location := resource.change.after.location
} else := google_zone if {
	provider_name := get_basename(resource.provider_name)
	provider_name == "google"
	google_zone := resource.change.after.zone
}

deny contains reason if {
	resource := tfplan.resource_changes[_]
	location := cloud_location_get_location(resource, tfplan)
	provider_name := get_basename(resource.provider_name)
	not location in allowed_locations[provider_name]

	reason := sprintf(
		"%s: location %q is not allowed",
		[resource.address, location],
	)
}
