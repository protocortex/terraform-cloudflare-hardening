variable "zone_id" {
  type        = string
  description = "Cloudflare zone id to harden."
}

variable "name_prefix" {
  type        = string
  default     = "hardening"
  description = "Prefix for the ruleset names created in the zone (must be unique per zone if you deploy multiple)."
}

# ── Zone TLS / security settings (all free tier) ──────────────────────────
variable "manage_zone_settings" {
  type        = bool
  description = <<-EOT
    Apply the baseline TLS and security zone settings.

    Leave null (the default) to inherit this module's choice, which is on. Set
    it explicitly only to force it off.

    Null exists so a caller can express "unset" instead of pinning a copy of the
    default. A passthrough variable that carries its own default silently beats
    the value here whenever this module is strengthened, and it does so in the
    weakening direction.
  EOT
  default     = null
}

variable "zone_settings" {
  type        = map(string)
  description = "setting_id => value. Overrides/extends the free-tier defaults below."
  default     = {}
}

# ── Security response headers (Transform Rule; free tier) ──────────────────
variable "manage_security_headers" {
  type        = bool
  description = <<-EOT
    Add the response-header transform rule.

    Leave null (the default) to inherit this module's choice, which is on. Set
    it explicitly only to force it off, for example where the origin already
    serves an equal or stronger set and varies headers per path.

    See manage_zone_settings for why null rather than a literal default.
  EOT
  default     = null
}

variable "hsts_max_age" {
  type        = number
  description = <<-EOT
    Strict-Transport-Security max-age in seconds. 0 disables the header.

    Leave null (the default) to inherit this module's value, currently two
    years, which is what the HSTS preload list expects. The common one year is
    enough to be accepted but leaves a shorter window of protection.

    Pinning a number here is what silently halves the window when this module
    raises its default, so prefer null unless you specifically need a different
    value. Note that includeSubDomains is always sent, so every subdomain must
    serve HTTPS before enabling the headers.
  EOT
  default     = null
}

variable "content_security_policy" {
  type        = string
  default     = null
  description = "Optional Content-Security-Policy value. Null omits the CSP header."
}

variable "omit_response_headers" {
  type        = list(string)
  default     = []
  description = <<-EOT
    Header names to leave out of the managed set entirely, so the origin keeps
    control of them.

    Needed when the origin varies a header per path, which a single transform
    rule cannot express. The motivating case: a site that sends
    Referrer-Policy: no-referrer only on pages whose URL carries a signed token,
    and the ordinary policy everywhere else. This rule runs after the origin
    response and uses "set", so without omitting it the stricter per-path value
    would be silently overwritten and the token would leak in the Referer.

    Names match the base set exactly, e.g. "Referrer-Policy".
  EOT
}

variable "extra_response_headers" {
  type        = map(string)
  default     = {}
  description = "Additional response headers to set (name => value)."
}

# ── Rate limiting (free tier allows ONE rule) ─────────────────────────────
variable "rate_limit" {
  type = object({
    expression = string # e.g. (http.request.uri.path eq "/api/waitlist")
    requests   = optional(number, 20)
    period     = optional(number, 60)  # seconds: 10|60|120|300|600|3600
    timeout    = optional(number, 600) # mitigation timeout seconds
    action     = optional(string, "block")
  })
  default     = null
  description = "Single rate-limit rule (free tier). Null disables. Put it on the abuse-prone path (waitlist)."
}

# ── Custom WAF rules (free tier allows up to 5) ───────────────────────────
variable "custom_firewall_rules" {
  type = list(object({
    ref         = string
    description = string
    expression  = string
    action      = string # block | managed_challenge | js_challenge | skip | log
  }))
  default     = []
  description = "Custom firewall (http_request_firewall_custom) rules. Free tier caps at 5."

  validation {
    condition     = length(var.custom_firewall_rules) <= 5
    error_message = "Free tier allows at most 5 custom WAF rules."
  }
}

# ── DNSSEC (free) ─────────────────────────────────────────────────────────
variable "enable_dnssec" {
  type        = bool
  default     = true
  description = "Enable DNSSEC. Outputs the DS record to add at your registrar (manual step)."
}

# ── DNS-based hardening (CAA, email anti-spoofing) ────────────────────────
# These write DNS records, so they need the zone's apex name as well as its id.

variable "zone_name" {
  type        = string
  default     = null
  description = "Apex domain of the zone (e.g. example.com). Required when any DNS-based hardening below is enabled, because those records are written at or under the apex."
}

variable "caa_issuers" {
  type        = list(string)
  default     = []
  description = <<-EOT
    CA domains allowed to issue certificates for this zone, written as CAA issue
    and issuewild records.

    If the zone uses Cloudflare Universal SSL, this MUST include every Cloudflare
    partner CA or certificate renewal breaks: letsencrypt.org, pki.goog, ssl.com,
    sectigo.com. Empty list writes no CAA records, which leaves issuance open to
    any CA.
  EOT
}

variable "dmarc_policy" {
  type        = string
  default     = null
  description = "DMARC policy published at _dmarc.<zone_name>: none (monitor only), quarantine, or reject. Start at none on a domain that sends mail, and move up once the aggregate reports show SPF and DKIM aligning. Use reject immediately on a domain that never sends. null writes no record."
  validation {
    condition     = var.dmarc_policy == null || contains(["none", "quarantine", "reject"], coalesce(var.dmarc_policy, "none"))
    error_message = "dmarc_policy must be null or one of: none, quarantine, reject."
  }
}

variable "dmarc_rua" {
  type        = string
  default     = null
  description = "Aggregate report destination for DMARC (e.g. mailto:dmarc@example.com). Must be an inbox someone actually reads, otherwise the reports are wasted. Omitted from the record when null."
}

variable "apex_spf" {
  type        = string
  default     = null
  description = "SPF TXT value published at the apex. Use 'v=spf1 -all' on a domain that never sends mail, so it cannot be spoofed. Leave null on a domain that sends via subdomains, so an existing apex SPF is not clobbered."
}

variable "manage_null_mx" {
  type        = bool
  default     = false
  description = "Publish a null MX ('.' at priority 0, RFC 7505) at the apex, declaring that the domain accepts no mail. Only for non-mail domains."
}
