# Restricts which users can trigger Terraform runs. Works for CLI and VCS.

package terraform

import input.tfplan as tfplan
import input.tfrun as tfrun

allowed_cli_users := ["d.johnson", "j.smith"]

# registry.terraform.io/hashicorp/aws -> aws
get_basename(path) := basename if {
	arr := split(path, "/")
	basename := arr[count(arr) - 1]
}

deny contains "User is not allowed to perform runs from Terraform CLI" if {
	tfrun.source == "cli"
	not tfrun.created_by.username in allowed_cli_users
}

deny contains "Only commits from authorized authors are allowed to trigger AWS infrastructure update" if {
	tfrun.source == "vcs"
	resource := tfplan.resource_changes[_]
	provider_name := get_basename(resource.provider_name)
	provider_name == "aws"
	not endswith(tfrun.vcs.commit.author.email, "-aws-ops@foo.bar")
}
