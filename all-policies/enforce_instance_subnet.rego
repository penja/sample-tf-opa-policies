# Enforces the use of specific subnets on EC2 instances.
# This policy first checks that a subnet_id has been specified, i.e. not default for an AZ.

package terraform

import input.tfplan as tfplan

# Add only private subnets to this list.
# NOTE: OPA cannot validate that a subnet is private unless the terraform config is actually creating the subnet.
instance_allowed_subnets := [
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
]

# Check that subnet has been specified
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_instance"
	r.change.after_unknown.subnet_id == true

	reason := sprintf(
		"%-40s :: subnet_id must be specified in terraform configuration.",
		[r.address],
	)
}

# Check subnet is in allowed list for EC2 instances
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_instance"
	not r.change.after.subnet_id in instance_allowed_subnets

	reason := sprintf(
		"%-40s :: subnet_id '%s' is public and not allowed",
		[r.address, r.change.after.subnet_id],
	)
}
