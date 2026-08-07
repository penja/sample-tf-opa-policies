# Enforces the denial of CIDR 0.0.0.0/0 in security groups.

package terraform

import input.tfplan as tfplan

# Add CIDRS that should be disallowed
invalid_cidrs := ["0.0.0.0/0"]

# Checks security groups embedded ingress rules
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.type == "aws_security_group"
	ingress := r.change.after.ingress[_]
	some invalid in invalid_cidrs
	invalid in ingress.cidr_blocks

	reason := sprintf(
		"%-40s :: security group invalid ingress CIDR %s",
		[r.address, invalid],
	)
}

# Checks security groups embedded egress rules
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.type == "aws_security_group"
	egress := r.change.after.egress[_]
	some invalid in invalid_cidrs
	invalid in egress.cidr_blocks

	reason := sprintf(
		"%-40s :: security group invalid egress CIDR %s",
		[r.address, invalid],
	)
}

# Checks standalone security group rules
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.type == "aws_security_group_rule"
	some invalid in invalid_cidrs
	invalid in r.change.after.cidr_blocks

	reason := sprintf(
		"%-40s :: security group rule invalid CIDR %s",
		[r.address, invalid],
	)
}
