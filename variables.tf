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

variable "manage_managed_waf" {
  type        = bool
  default     = true
  description = "Deploy Cloudflare's managed WAF ruleset. Available on every plan including Free, but NOT enabled unless an entrypoint ruleset exists in the http_request_firewall_managed phase, so a zone can look hardened while none of it runs. Needs Zone WAF Read to resolve the ruleset id and Zone WAF Edit to deploy it."
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

variable "dmarc_sp" {
  type        = string
  default     = null
  description = "Policy for SUBDOMAINS of this zone: none, quarantine, or reject. null omits the tag, and subdomains then inherit dmarc_policy. Set this explicitly when the apex and its subdomains have different sending profiles, e.g. an apex that sends via an ESP and subdomains that never send at all, which can go straight to reject."
  validation {
    condition     = var.dmarc_sp == null || contains(["none", "quarantine", "reject"], coalesce(var.dmarc_sp, "none"))
    error_message = "dmarc_sp must be null or one of: none, quarantine, reject."
  }
}

variable "dmarc_adkim" {
  type        = string
  default     = null
  description = "DKIM alignment: r (relaxed, the DMARC default) or s (strict). Relaxed lets a subdomain's DKIM signature satisfy the parent. Strict requires the d= domain to equal the From domain exactly, which breaks an ESP that signs with a subdomain. null omits the tag and takes the relaxed default."
  validation {
    condition     = var.dmarc_adkim == null || contains(["r", "s"], coalesce(var.dmarc_adkim, "r"))
    error_message = "dmarc_adkim must be null, r (relaxed) or s (strict)."
  }
}

variable "dmarc_aspf" {
  type        = string
  default     = null
  description = "SPF alignment: r (relaxed, the DMARC default) or s (strict). Same trade-off as dmarc_adkim: strict requires the envelope sender domain to match the From domain exactly. null omits the tag and takes the relaxed default."
  validation {
    condition     = var.dmarc_aspf == null || contains(["r", "s"], coalesce(var.dmarc_aspf, "r"))
    error_message = "dmarc_aspf must be null, r (relaxed) or s (strict)."
  }
}

variable "dmarc_pct" {
  type        = number
  default     = null
  description = "Percentage of failing mail the policy applies to, 0 to 100. Use it to ramp a tightening policy, e.g. reject at pct=10 before pct=100. Deprecated in DMARCbis but still honoured widely. null omits the tag, which means 100."
  validation {
    condition     = var.dmarc_pct == null || (var.dmarc_pct >= 0 && var.dmarc_pct <= 100 && floor(var.dmarc_pct) == var.dmarc_pct)
    error_message = "dmarc_pct must be null or a whole number between 0 and 100."
  }
}

variable "dmarc_ruf" {
  type    = string
  default = null

  validation {
    condition     = var.dmarc_ruf == null || can(regex("^(mailto:|https://)", coalesce(var.dmarc_ruf, "mailto:x@y")))
    error_message = "dmarc_ruf must be a URI, e.g. mailto:dmarc-forensics@example.com. A bare email address is silently ignored by reporting agents."
  }
  description = "Destination for FORENSIC (per-message failure) reports, e.g. mailto:dmarc-forensics@example.com. Think before setting this: these reports can carry message headers and content from real mail, so the inbox inherits that sensitivity, and most large providers never send them anyway. Aggregate reports via dmarc_rua are the ones that carry the useful signal. null omits the tag."
}

variable "dmarc_fo" {
  type        = string
  default     = null
  description = "When to generate forensic reports: 0 (all underlying checks failed), 1 (any check failed), d (DKIM failed), s (SPF failed), or a colon-joined set such as \"d:s\". Only has effect when dmarc_ruf is set. null omits the tag, which means 0."
  validation {
    condition     = var.dmarc_fo == null || can(regex("^[01ds](:[01ds])*$", coalesce(var.dmarc_fo, "0")))
    error_message = "dmarc_fo must be null, or 0/1/d/s optionally colon-joined (e.g. \"1\", \"d:s\")."
  }
}

variable "dmarc_rf" {
  type        = string
  default     = null
  description = "Forensic report format. afrf is the only format in practice. null omits the tag."
  validation {
    condition     = var.dmarc_rf == null || contains(["afrf"], coalesce(var.dmarc_rf, "afrf"))
    error_message = "dmarc_rf must be null or afrf."
  }
}

variable "dmarc_ri" {
  type        = number
  default     = null
  description = "Requested interval between aggregate reports, in seconds. 86400 (daily) is the default and effectively the only value providers honour. null omits the tag."
  validation {
    condition     = var.dmarc_ri == null || (var.dmarc_ri > 0 && floor(var.dmarc_ri) == var.dmarc_ri)
    error_message = "dmarc_ri must be null or a positive whole number of seconds."
  }
}

variable "dmarc_rua" {
  type    = string
  default = null

  # A bare address is the classic DMARC typo. RFC 7489 requires a URI, so
  # "dmarc@example.com" without the mailto: scheme is silently ignored by
  # reporters: the record still parses, the policy still applies, and no report
  # ever arrives. Failing at plan time is far better than discovering months
  # later that the inbox was empty for a reason.
  validation {
    condition     = var.dmarc_rua == null || can(regex("^(mailto:|https://)", coalesce(var.dmarc_rua, "mailto:x@y")))
    error_message = "dmarc_rua must be a URI, e.g. mailto:dmarc@example.com. A bare email address is silently ignored by reporting agents."
  }
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
