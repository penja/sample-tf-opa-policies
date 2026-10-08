# Shared policy, referenced from the environment folders as "../vcs_deploy".

package terraform

import input.tfrun as tfrun

deny[reason] {
	not tfrun.workspace.vcs_repo

	reason := "Workspace is not a VCS deployment"
}
