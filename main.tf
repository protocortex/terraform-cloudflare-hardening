# Free-tier Cloudflare zone hardening: TLS/security settings, security response
# headers, one rate-limit rule, optional custom WAF rules, and DNSSEC.
# Everything here is available on the Cloudflare Free plan. The full managed WAF
# (OWASP) is Pro+ and intentionally NOT deployed here, the Free Managed Ruleset
# is applied automatically by Cloudflare on free zones.

locals {
  # Baseline TLS/security settings, all free tier. Override via var.zone_settings.
  default_zone_settings = {
    ssl                      = "strict" # Full (Strict)
    min_tls_version          = "1.2"
    tls_1_3                  = "on"
    always_use_https         = "on"
    automatic_https_rewrites = "on"
    opportunistic_encryption = "on"
    browser_check            = "on"
  }
  effective_zone_settings = var.manage_zone_settings ? merge(local.default_zone_settings, var.zone_settings) : {}

  # Security response headers (name => value), assembled from fixed defaults +
  # conditional HSTS/CSP + caller extras.
  base_headers = merge(
    {
      "X-Content-Type-Options" = "nosniff"
      "X-Frame-Options"        = "SAMEORIGIN"
      "Referrer-Policy"        = "strict-origin-when-cross-origin"
      "Permissions-Policy"     = "geolocation=(), microphone=(), camera=()"
    },
    var.hsts_max_age > 0 ? { "Strict-Transport-Security" = "max-age=${var.hsts_max_age}; includeSubDomains; preload" } : {},
    var.content_security_policy != null ? { "Content-Security-Policy" = var.content_security_policy } : {},
    var.extra_response_headers,
  )
  response_headers = { for name, value in local.base_headers : name => { operation = "set", value = value } }
}

# ── Zone TLS / security settings ──────────────────────────────────────────
resource "cloudflare_zone_setting" "this" {
  for_each = local.effective_zone_settings

  zone_id    = var.zone_id
  setting_id = each.key
  value      = each.value
}

# ── Security response headers (Transform Rule) ────────────────────────────
resource "cloudflare_ruleset" "security_headers" {
  count = var.manage_security_headers ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-security-headers"
  kind    = "zone"
  phase   = "http_response_headers_transform"

  rules = [{
    ref         = "security_headers"
    description = "Set baseline security response headers"
    expression  = "true"
    action      = "rewrite"
    action_parameters = {
      headers = local.response_headers
    }
  }]
}

# ── Rate limiting (free tier: one rule) ───────────────────────────────────
resource "cloudflare_ruleset" "rate_limit" {
  count = var.rate_limit != null ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-rate-limit"
  kind    = "zone"
  phase   = "http_ratelimit"

  rules = [{
    ref         = "rate_limit"
    description = "Rate limit abuse-prone path"
    expression  = var.rate_limit.expression
    action      = var.rate_limit.action
    ratelimit = {
      characteristics     = ["ip.src", "cf.colo.id"]
      period              = var.rate_limit.period
      requests_per_period = var.rate_limit.requests
      mitigation_timeout  = var.rate_limit.timeout
    }
  }]
}

# ── Custom WAF rules (free tier: up to 5) ─────────────────────────────────
resource "cloudflare_ruleset" "custom_firewall" {
  count = length(var.custom_firewall_rules) > 0 ? 1 : 0

  zone_id = var.zone_id
  name    = "${var.name_prefix}-custom-firewall"
  kind    = "zone"
  phase   = "http_request_firewall_custom"

  rules = [for r in var.custom_firewall_rules : {
    ref         = r.ref
    description = r.description
    expression  = r.expression
    action      = r.action
  }]
}

# ── DNSSEC ────────────────────────────────────────────────────────────────
resource "cloudflare_zone_dnssec" "this" {
  count   = var.enable_dnssec ? 1 : 0
  zone_id = var.zone_id
}
