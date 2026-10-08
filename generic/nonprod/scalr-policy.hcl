version = "v1"

policy "../min_terraform_version" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "../vcs_deploy" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}
