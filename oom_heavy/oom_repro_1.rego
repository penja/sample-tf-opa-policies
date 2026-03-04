package terraform

import future.keywords.contains
import future.keywords.if

deny contains msg if {
    count(object.get(input.tfplan, "resource_changes", [])) < 0
    msg := "oom-repro-1"
}
