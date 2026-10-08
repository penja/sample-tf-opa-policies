# Shared policy, referenced from the environment folders as "../enforce_tls_policy".

package terraform

import input.tfplan as tfplan

deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_lb_listener"
	r.change.after.protocol == "HTTP"

	reason := sprintf("%-40s :: ALB listeners must use HTTPS", [r.address])
}
