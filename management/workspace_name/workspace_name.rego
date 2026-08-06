# Checks the worksoace name for a specific suffix.

package terraform

import rego.v1

import input.tfrun as tfrun


deny["Forbidden workspace name"] {
    not endswith(tfrun.workspace.name, "-dev")
}
