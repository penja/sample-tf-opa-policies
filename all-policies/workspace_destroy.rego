# Denies the destruction of a Scalr workspace that still has an active state.

package terraform

import input.tfplan as tfplan

deny contains "Can not destroy workspace with active state" if {
	resource := tfplan.resource_changes[_]
	resource.change.actions[count(resource.change.actions) - 1] == "delete"
	resource.type == "scalr_workspace"
	resource.change.before.has_resources
}
