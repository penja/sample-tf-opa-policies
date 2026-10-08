version = "v1"

policy "../enforce_tls_policy" {
  enabled           = true
  enforcement_level = "soft-mandatory"
}

policy "../enforce_alb_https" {
  enabled           = false
  enforcement_level = "soft-mandatory"
}
