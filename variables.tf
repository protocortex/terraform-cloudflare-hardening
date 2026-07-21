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
  default     = true
  description = "Manage the baseline TLS/security zone settings."
}

variable "zone_settings" {
  type        = map(string)
  description = "setting_id => value. Overrides/extends the free-tier defaults below."
  default     = {}
}

# ── Security response headers (Transform Rule; free tier) ──────────────────
variable "manage_security_headers" {
  type        = bool
  default     = true
  description = "Add a response-header Transform Rule (HSTS, X-CTO, X-Frame-Options, Referrer-Policy, Permissions-Policy)."
}

variable "hsts_max_age" {
  type        = number
  default     = 31536000
  description = "Strict-Transport-Security max-age (seconds). 0 disables the HSTS header."
}

variable "content_security_policy" {
  type        = string
  default     = null
  description = "Optional Content-Security-Policy value. Null omits the CSP header."
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
