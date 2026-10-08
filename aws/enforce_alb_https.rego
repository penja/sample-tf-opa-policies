# Shared policy kept in the manifest as disabled: the blob must still carry it,
# `from_dir` reads every manifest entry.

package terraform

import input.tfplan as tfplan

deny[reason] {
	r = tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_lb_listener"
	r.change.after.port == 80

	reason := sprintf("%-40s :: ALB listeners must not listen on port 80", [r.address])
}
