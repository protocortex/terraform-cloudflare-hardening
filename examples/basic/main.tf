terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 5.0, < 6.0"
    }
  }
}

# Configure via CLOUDFLARE_API_TOKEN (Zone:Read, Zone WAF:Edit, DNS:Edit, Zone Settings:Edit).
provider "cloudflare" {}

variable "zone_id" {
  type = string
}

variable "zone_name" {
  type        = string
  description = "Apex domain, e.g. example.com. Needed for the DNS-based hardening."
}

module "hardening" {
  source    = "../.."
  zone_id   = var.zone_id
  zone_name = var.zone_name

  name_prefix             = "example"
  content_security_policy = "default-src 'self'; frame-ancestors 'none'"

  rate_limit = {
    expression = "(http.request.uri.path eq \"/api/waitlist\" and http.request.method eq \"POST\")"
    requests   = 10
    period     = 60
  }

  # Pin certificate issuance. On a Universal SSL zone this must list every
  # Cloudflare partner CA, or renewal breaks.
  caa_issuers = ["letsencrypt.org", "pki.goog", "ssl.com", "sectigo.com"]

  # This domain sends mail, so DMARC starts in monitor mode and the existing
  # SPF/DKIM records are left alone.
  dmarc_policy = "none"
  dmarc_rua    = "mailto:dmarc@example.com"
}

output "dnssec_ds" {
  value = module.hardening.dnssec
}
