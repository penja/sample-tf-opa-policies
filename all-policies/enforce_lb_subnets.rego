# Enforces the use of specific subnets on AWS Load Balancers.

package terraform

import input.tfplan as tfplan

# Add only private subnets to this list.
# NOTE: OPA cannot validate that a subnet is private unless the terraform config is actually creating the subnet.
lb_allowed_subnets := [
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
]

lbs := ["aws_elb", "aws_lb"]

# Check subnets are in allowed list
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type in lbs
	sid := r.change.after.subnets[_]
	not sid in lb_allowed_subnets

	reason := sprintf(
		"%-40s :: subnet_id '%s' is public and not allowed!",
		[r.address, sid],
	)
}
