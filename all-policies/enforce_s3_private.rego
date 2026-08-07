# Check S3 bucket is not public.

package terraform

import input.tfplan as tfplan

public_acls := ["public", "public-read", "public-read-write", "authenticated-read"]

deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_s3_bucket"
	r.change.after.acl in public_acls

	reason := sprintf("%-40s :: S3 buckets must not be PUBLIC", [r.address])
}

# Modern configurations set the ACL on a dedicated aws_s3_bucket_acl resource.
deny contains reason if {
	r := tfplan.resource_changes[_]
	r.mode == "managed"
	r.type == "aws_s3_bucket_acl"
	r.change.after.acl in public_acls

	reason := sprintf("%-40s :: S3 buckets must not be PUBLIC", [r.address])
}
