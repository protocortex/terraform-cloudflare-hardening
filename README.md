<!-- SPDX-License-Identifier: Apache-2.0 -->
# terraform-cloudflare-hardening

Reusable OpenTofu/Terraform module that applies a **free-tier** security baseline to
a Cloudflare zone: TLS/security settings, security response headers, a rate-limit
rule, optional custom WAF rules, and DNSSEC. Works with the Cloudflare **v5**
provider.

Everything here is available on the Cloudflare **Free plan**. The full OWASP/Managed
WAF is Pro+ and is intentionally **not** deployed — Cloudflare auto-applies the Free
Managed Ruleset on free zones.

## Usage

```hcl
provider "cloudflare" {} # configure via CLOUDFLARE_API_TOKEN

module "hardening" {
  source  = "git::https://github.com/protocortex/terraform-cloudflare-hardening.git?ref=v0.1.0"
  zone_id = "<zone id>"

  name_prefix             = "mysite"
  content_security_policy = "default-src 'self'; frame-ancestors 'none'"

  # Free tier allows ONE rate-limit rule — put it on the abuse-prone path.
  rate_limit = {
    expression = "(http.request.uri.path eq \"/api/waitlist\" and http.request.method eq \"POST\")"
    requests   = 10
    period     = 60
  }

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
| `cloudflare_ruleset` (`http_response_headers_transform`) | HSTS + `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, optional CSP |
| `cloudflare_ruleset` (`http_ratelimit`) | one rate-limit rule (the free-tier cap) |
| `cloudflare_ruleset` (`http_request_firewall_custom`) | up to 5 custom WAF rules |
| `cloudflare_zone_dnssec` | DNSSEC (outputs the DS record) |

## Key inputs

| Name | Default | Description |
|---|---|---|
| `zone_id` | — | Zone to harden (required) |
| `name_prefix` | `hardening` | Prefix for the ruleset names |
| `manage_zone_settings` | `true` | Apply the TLS/security zone settings |
| `zone_settings` | `{}` | `setting_id => value` overrides/extras |
| `manage_security_headers` | `true` | Add the response-header Transform Rule |
| `hsts_max_age` | `31536000` | HSTS max-age (0 disables the header) |
| `content_security_policy` | `null` | Optional CSP header value |
| `extra_response_headers` | `{}` | Extra `name => value` headers |
| `rate_limit` | `null` | One rate-limit rule (see example) |
| `custom_firewall_rules` | `[]` | Up to 5 custom WAF rules |
| `enable_dnssec` | `true` | Enable DNSSEC |

## Outputs

`dnssec` (incl. the DS record for your registrar), `security_headers_ruleset_id`,
`rate_limit_ruleset_id`, `custom_firewall_ruleset_id`.

## License

Apache-2.0. See [LICENSE](LICENSE).
