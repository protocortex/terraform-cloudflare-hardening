<!-- SPDX-License-Identifier: Apache-2.0 -->
# terraform-cloudflare-hardening

Reusable OpenTofu/Terraform module that applies a **free-tier** security baseline to
a Cloudflare zone: TLS/security settings, security response headers, a rate-limit
rule, optional custom WAF rules, DNSSEC, and the DNS records that carry the rest
of a zone's posture (CAA pinning, plus DMARC, SPF and null MX anti-spoofing).
Works with the Cloudflare **v5** provider.

Everything here is available on the Cloudflare **Free plan**. The full OWASP/Managed
WAF is Pro+ and is intentionally **not** deployed, Cloudflare auto-applies the Free
Managed Ruleset on free zones.

## Usage

```hcl
provider "cloudflare" {} # configure via CLOUDFLARE_API_TOKEN

module "hardening" {
  source  = "git::https://github.com/protocortex/terraform-cloudflare-hardening.git?ref=v0.2.0"
  zone_id = "<zone id>"

  # Required for the DNS-based hardening below, which writes records at the apex.
  zone_name = "example.com"

  name_prefix             = "mysite"
  content_security_policy = "default-src 'self'; frame-ancestors 'none'"

  # Free tier allows ONE rate-limit rule, put it on the abuse-prone path.
  rate_limit = {
    expression = "(http.request.uri.path eq \"/api/waitlist\" and http.request.method eq \"POST\")"
    requests   = 10
    period     = 60
  }

  # Pin certificate issuance. On a zone using Universal SSL this MUST list every
  # Cloudflare partner CA, or renewal breaks.
  caa_issuers = ["letsencrypt.org", "pki.goog", "ssl.com", "sectigo.com"]

  # Email anti-spoofing. Start DMARC at "none" on a domain that sends mail and
  # tighten once the reports show SPF and DKIM aligning.
  dmarc_policy = "none"
  dmarc_rua    = "mailto:dmarc@example.com"

  # On a domain that never sends mail, declare it: SPF -all, a null MX, and
  # DMARC "reject".
  # apex_spf       = "v=spf1 -all"
  # manage_null_mx = true

  # Free tier allows up to 5 custom WAF rules.
  custom_firewall_rules = [{
    ref         = "block-scanners"
    description = "Challenge obvious scanners"
    expression  = "(cf.threat_score gt 20)"
    action      = "managed_challenge"
  }]
}

output "dnssec_ds" { value = module.hardening.dnssec }
```

The **provider is configured by the caller**, not the module. DNSSEC returns a DS
record you must add at your registrar (a manual step).

## What it manages (all free tier)

| Resource | Purpose |
|---|---|
| `cloudflare_zone_setting` × N | Full(Strict) SSL, min TLS 1.2, TLS 1.3, Always-HTTPS, Auto-HTTPS-Rewrites, Opportunistic Encryption, Browser Check |
| `cloudflare_ruleset` (`http_response_headers_transform`) | HSTS (2y, `includeSubDomains`, `preload`) + `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, a six-directive `Permissions-Policy`, optional CSP |
| `cloudflare_ruleset` (`http_ratelimit`) | one rate-limit rule (the free-tier cap) |
| `cloudflare_ruleset` (`http_request_firewall_custom`) | up to 5 custom WAF rules |
| `cloudflare_zone_dnssec` | DNSSEC (outputs the DS record) |
| `cloudflare_dns_record` (CAA × 2N) | `issue` + `issuewild` pinning, one pair per allowed CA |
| `cloudflare_dns_record` (TXT) | DMARC policy at `_dmarc.<zone_name>`, and an optional apex SPF |
| `cloudflare_dns_record` (MX) | optional null MX (RFC 7505), for a domain that accepts no mail |

## Key inputs

| Name | Default | Description |
|---|---|---|
| `zone_id` | _required_ | Zone to harden (required) |
| `name_prefix` | `hardening` | Prefix for the ruleset names |
| `manage_zone_settings` | `true` | Apply the TLS/security zone settings |
| `zone_settings` | `{}` | `setting_id => value` overrides/extras |
| `manage_security_headers` | `true` | Add the response-header Transform Rule |
| `hsts_max_age` | `63072000` | HSTS max-age, two years, what the preload list expects (0 disables the header) |
| `content_security_policy` | `null` | Optional CSP header value |
| `extra_response_headers` | `{}` | Extra `name => value` headers |
| `rate_limit` | `null` | One rate-limit rule (see example) |
| `custom_firewall_rules` | `[]` | Up to 5 custom WAF rules |
| `enable_dnssec` | `true` | Enable DNSSEC |
| `zone_name` | `null` | Apex domain. **Required** when any DNS-based input below is set |
| `caa_issuers` | `[]` | CAs allowed to issue certs. Must include every Cloudflare partner CA on a Universal SSL zone |
| `dmarc_policy` | `null` | `none`, `quarantine` or `reject`, published at `_dmarc.<zone_name>` |
| `dmarc_rua` | `null` | Aggregate report destination, e.g. `mailto:dmarc@example.com` |
| `apex_spf` | `null` | Apex SPF value, e.g. `v=spf1 -all` on a non-sending domain |
| `manage_null_mx` | `false` | Publish a null MX, declaring the domain accepts no mail |

## Outputs

`dnssec` (incl. the DS record for your registrar), `security_headers_ruleset_id`,
`rate_limit_ruleset_id`, `custom_firewall_ruleset_id`.

## License

Apache-2.0. See [LICENSE](LICENSE).
