output "dnssec" {
  description = "DNSSEC details, including the DS record to add at your registrar (manual step)."
  value       = var.enable_dnssec ? one(cloudflare_zone_dnssec.this[*]) : null
}

output "security_headers_ruleset_id" {
  description = "Ruleset id for the security-headers Transform Rule (null if disabled)."
  value       = try(cloudflare_ruleset.security_headers[0].id, null)
}

output "rate_limit_ruleset_id" {
  description = "Ruleset id for the rate-limit rule (null if disabled)."
  value       = try(cloudflare_ruleset.rate_limit[0].id, null)
}

output "custom_firewall_ruleset_id" {
  description = "Ruleset id for the custom WAF rules (null if none)."
  value       = try(cloudflare_ruleset.custom_firewall[0].id, null)
}
