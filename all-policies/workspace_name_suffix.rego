# Advisory: the workspace name should carry the shared suffix.
#
# The check is delegated to data.naming on purpose: it exercises the common functions plumbing.
# If the common functions file is not delivered to OPA, this policy fails to compile instead of
# silently passing, which makes a missing file visible in the run output.

package terraform

import input.tfrun as tfrun

deny contains reason if {
	not data.naming.has_required_suffix(tfrun.workspace.name)

	reason := sprintf(
		"%-40s :: Workspace name should end with %q",
		[tfrun.workspace.name, data.naming.required_suffix],
	)
}
