# Enforces the use of specific subnets on RDS subnet groups.

package terraform

import input.tfplan as tfplan

# Add only private subnets to this list.
# NOTE: OPA cannot validate that a subnet is private unless the terraform config is actually creating the subnet.
rds_allowed_subnets := [
	"subnet-019c416174b079502",
	"subnet-04dbded374ed11690",
]

# Check subnets are in allowed list
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_db_subnet_group"
	sid := r.change.after.subnet_ids[_]
	not sid in rds_allowed_subnets

	reason := sprintf(
		"%-40s :: subnet_id '%s' is public and not allowed!",
		[r.address, sid],
	)
}
