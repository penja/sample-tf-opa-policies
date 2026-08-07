# Check that variables have descriptions.

package terraform

import input.tfplan as tfplan

get_desc(avar) := desc if {
	desc := avar.description
} else := ""

deny contains reason if {
	tfvar := tfplan.configuration.root_module.variables[key]
	get_desc(tfvar) == ""

	reason := sprintf("%-40s :: Variable must have a description", [key])
}
