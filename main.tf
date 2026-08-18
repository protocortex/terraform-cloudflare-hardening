# Free-tier Cloudflare zone hardening: TLS/security settings, security response
# headers, one rate-limit rule, optional custom WAF rules, DNSSEC, and the
# DNS-based controls (CAA pinning plus DMARC, SPF and null MX anti-spoofing).
# Everything here is available on the Cloudflare Free plan. The full managed WAF
# (OWASP) is Pro+ and intentionally NOT deployed here, the Free Managed Ruleset
# is applied automatically by Cloudflare on free zones.

locals {
  # ── Effective variable resolution ──
  # These three inputs default to null so a caller can say "unset" and inherit
  # whatever this module considers strong, rather than pinning a copy that goes
  # stale. A passthrough variable carrying its own default silently beats the
  # value here, and it does so in the weakening direction, which is how a
  # consumer once cut its own HSTS window in half on a module upgrade.
  # Resources below read local.eff_* and never var.* for these.
  eff_manage_zone_settings    = var.manage_zone_settings != null ? var.manage_zone_settings : true
  eff_manage_security_headers = var.manage_security_headers != null ? var.manage_security_headers : true
  eff_hsts_max_age            = var.hsts_max_age != null ? var.hsts_max_age : 63072000

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
  effective_zone_settings = local.eff_manage_zone_settings ? merge(local.default_zone_settings, var.zone_settings) : {}

  # Security response headers (name => value), assembled from fixed defaults +
  # conditional HSTS/CSP + caller extras.
  base_headers = merge(
    {
      "X-Content-Type-Options" = "nosniff"
      # DENY, not SAMEORIGIN. A hardening module should refuse framing outright;
      # a caller that genuinely frames its own pages can relax it through
      # extra_response_headers.
      "X-Frame-Options"    = "DENY"
      "Referrer-Policy"    = "strict-origin-when-cross-origin"
      "Permissions-Policy" = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    },
    local.eff_hsts_max_age > 0 ? { "Strict-Transport-Security" = "max-age=${local.eff_hsts_max_age}; includeSubDomains; preload" } : {},
    var.content_security_policy != null ? { "Content-Security-Policy" = var.content_security_policy } : {},
    var.extra_response_headers,
  )
  # Omitted headers are dropped before the rule is built, leaving them to the
  # origin. See var.omit_response_headers for why that is sometimes required.
  managed_headers  = { for name, value in local.base_headers : name => value if !contains(var.omit_response_headers, name) }
  response_headers = { for name, value in local.managed_headers : name => { operation = "set", value = value } }
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
  count = local.eff_manage_security_headers ? 1 : 0

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

# ── DNS-based hardening: CAA + email anti-spoofing ────────────────────────
# Free tier. These need var.zone_name as well as var.zone_id, because they are
# written at or under the apex.

check "dns_hardening_needs_zone_name" {
  assert {
    condition = (
      var.zone_name != null
      || (
        length(var.caa_issuers) == 0
        && var.dmarc_policy == null
        && var.apex_spf == null
        && !var.manage_null_mx
      )
    )
    error_message = "zone_name is required when caa_issuers, dmarc_policy, apex_spf or manage_null_mx is set: those records are written at or under the apex, and the zone id alone does not give the name."
  }
}

# CAA. issue covers the apex certificate, issuewild the wildcard that Universal
# SSL also provisions, so both are written for every allowed CA.
resource "cloudflare_dns_record" "caa_issue" {
  for_each = toset(var.caa_issuers)

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 1
  comment = "${var.name_prefix}: restrict certificate issuance"
  data = {
    flags = 0
    tag   = "issue"
    value = each.value
  }
}

resource "cloudflare_dns_record" "caa_issuewild" {
  for_each = toset(var.caa_issuers)

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "CAA"
  ttl     = 1
  comment = "${var.name_prefix}: restrict wildcard certificate issuance"
  data = {
    flags = 0
    tag   = "issuewild"
    value = each.value
  }
}

# DMARC. Without it, receivers cannot act on SPF/DKIM alignment, so the domain
# can be spoofed even when both are configured.
resource "cloudflare_dns_record" "dmarc" {
  count = var.dmarc_policy != null ? 1 : 0

  zone_id = var.zone_id
  name    = "_dmarc.${var.zone_name}"
  type    = "TXT"
  ttl     = 1
  comment = "${var.name_prefix}: DMARC policy"
  content = join("; ", concat(
    ["v=DMARC1", "p=${var.dmarc_policy}"],
    var.dmarc_rua != null ? ["rua=${var.dmarc_rua}"] : [],
  ))
}

# Apex SPF, for a domain declared as a non-sender.
resource "cloudflare_dns_record" "apex_spf" {
  count = var.apex_spf != null ? 1 : 0

  zone_id = var.zone_id
  name    = var.zone_name
  type    = "TXT"
  ttl     = 1
  comment = "${var.name_prefix}: apex SPF"
  content = var.apex_spf
}

# Null MX (RFC 7505): states that the domain accepts no mail.
resource "cloudflare_dns_record" "null_mx" {
  count = var.manage_null_mx ? 1 : 0

  zone_id  = var.zone_id
  name     = var.zone_name
  type     = "MX"
  ttl      = 1
  content  = "."
  priority = 0
  comment  = "${var.name_prefix}: null MX, domain sends and receives no mail"
}
