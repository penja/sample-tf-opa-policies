# Shared policy, referenced from the environment folders as "../min_terraform_version".

package terraform

import input.tfplan as tfplan

deny[reason] {
	tfplan.terraform_version < "1.5.0"

	reason := sprintf("Terraform %s is below the minimum 1.5.0", [tfplan.terraform_version])
}
