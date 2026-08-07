# Prevent specified provisioners from being used.

package terraform

import input.tfplan as tfplan

# List of disallowed provisioner types
denied_provisioners := ["local-exec"]

module_name(path) := name if {
	name := sprintf("module.%s", [path[count(path) - 2]])
} else := "root-module"

# Walk the configuration looking in the root module and any called module for
# provisioners and check them against the denied list.
deny contains reason if {
	walk(tfplan.configuration.root_module, [path, value])
	resource := value.resources[_]
	provisioner := resource.provisioners[_]
	provisioner.type in denied_provisioners
	module := module_name(path)

	reason := sprintf(
		"%s.%s: provisioner of type %s is not allowed",
		[module, resource.address, provisioner.type],
	)
}
