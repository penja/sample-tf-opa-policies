# Enforces the use of a specific security group on EC2 instances.

package terraform

import input.tfplan as tfplan

required_sg := "sg-0434611e67ac24e27"

# Checks that a list of sec groups has been included in the config
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_instance"
	r.change.after_unknown.vpc_security_group_ids == true

	reason := sprintf(
		"%-40s :: security group '%s' must be specified",
		[r.address, required_sg],
	)
}

# If a list of sec groups has been given, check that the required one is in the list.
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_instance"
	vsg := r.change.after.vpc_security_group_ids
	not required_sg in vsg

	reason := sprintf(
		"%-40s :: security group '%s' must be included in list",
		[r.address, required_sg],
	)
}
