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

module "hardening" {
  source  = "../.."
  zone_id = var.zone_id

  name_prefix             = "example"
  content_security_policy = "default-src 'self'; frame-ancestors 'none'"

  rate_limit = {
    expression = "(http.request.uri.path eq \"/api/waitlist\" and http.request.method eq \"POST\")"
    requests   = 10
    period     = 60
  }
}

output "dnssec_ds" {
  value = module.hardening.dnssec
}
