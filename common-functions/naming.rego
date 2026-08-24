# Shared helpers available to every policy in this repository.
#
# Scalr loads this directory through the policy group's common functions folder and passes
# each file to OPA as its own --data argument.

package naming

required_suffix := "-dev"

has_required_suffix(name) if {
	endswith(name, required_suffix)
}
