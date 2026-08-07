# Enforces private ACLs and server side encryption on S3 buckets.

package terraform

import input.tfplan as tfplan

allowed_acls := ["private"]

allowed_sse_algorithms := ["aws:kms", "AES256"]

s3_buckets contains r if {
	r := tfplan.resource_changes[_]
	r.type == "aws_s3_bucket"
}

# Rule to restrict S3 bucket ACLs
deny contains reason if {
	r := s3_buckets[_]
	not r.change.after.acl in allowed_acls

	reason := sprintf(
		"%s: ACL %q is not allowed",
		[r.address, r.change.after.acl],
	)
}

# Rule to require server-side encryption
deny contains reason if {
	r := s3_buckets[_]
	count(r.change.after.server_side_encryption_configuration) == 0

	reason := sprintf(
		"%s: requires server-side encryption with expected sse_algorithm to be one of %v",
		[r.address, allowed_sse_algorithms],
	)
}

# Rule to enforce specific SSE algorithms
deny contains reason if {
	r := s3_buckets[_]
	sse_configuration := r.change.after.server_side_encryption_configuration[_]
	apply_sse_by_default := sse_configuration.rule[_].apply_server_side_encryption_by_default[_]
	not apply_sse_by_default.sse_algorithm in allowed_sse_algorithms

	reason := sprintf(
		"%s: expected sse_algorithm to be one of %v",
		[r.address, allowed_sse_algorithms],
	)
}
