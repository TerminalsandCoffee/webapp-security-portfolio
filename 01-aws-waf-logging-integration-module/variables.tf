# -----------------------------------------------------------------------------
# Required Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, production)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "resource_arn" {
  description = "ARN of the regional resource to associate with the WAF WebACL (for example ALB or API Gateway stage)"
  type        = string
}

# -----------------------------------------------------------------------------
# Sensitivity & Behavior
# -----------------------------------------------------------------------------

variable "sensitivity_level" {
  description = <<-EOT
    WAF enforcement sensitivity:
      low    = Count mode for managed, geo, and rate rules — use for initial deployment/baselining
      medium = Block known bad, count suspicious — recommended for most environments
      high   = Block aggressively + strict rate limits — use for production with mature tuning
  EOT
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["low", "medium", "high"], var.sensitivity_level)
    error_message = "Sensitivity level must be one of: low, medium, high."
  }
}

variable "default_action" {
  description = "Default action when no rules match (allow or block)"
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "Default action must be 'allow' or 'block'."
  }
}

# -----------------------------------------------------------------------------
# Rate Limiting
# -----------------------------------------------------------------------------

variable "rate_limit_threshold" {
  description = "Maximum requests per 5-minute window from a single IP before rate limiting kicks in"
  type        = number
  default     = 2000
}

# -----------------------------------------------------------------------------
# IP Lists
# -----------------------------------------------------------------------------

variable "allowed_ip_ranges" {
  description = "IPv4 or IPv6 CIDR ranges to always allow (bypass WAF rules). Use for trusted internal networks."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.allowed_ip_ranges : can(cidrhost(cidr, 0))])
    error_message = "allowed_ip_ranges must contain valid IPv4 or IPv6 CIDR ranges."
  }
}

variable "blocked_ip_ranges" {
  description = "IPv4 or IPv6 CIDR ranges to always block. Use for known malicious sources."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.blocked_ip_ranges : can(cidrhost(cidr, 0))])
    error_message = "blocked_ip_ranges must contain valid IPv4 or IPv6 CIDR ranges."
  }
}

# -----------------------------------------------------------------------------
# Geo-Blocking
# -----------------------------------------------------------------------------

variable "blocked_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes to block (e.g., ['RU', 'CN', 'KP'])"
  type        = list(string)
  default     = []
}

# -----------------------------------------------------------------------------
# Managed Rule Toggles
# -----------------------------------------------------------------------------

variable "enable_anonymous_ip_list" {
  description = <<-EOT
    Enable AWSManagedRulesAnonymousIpList (blocks VPN/Tor/hosting provider IPs).
    WARNING: Can cause false positives in enterprise environments where developers
    use corporate VPNs or cloud-based development environments. Recommended to
    start with count mode (sensitivity_level = 'low') and review logs before
    enforcing in medium/high. Default: false.
  EOT
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.log_retention_days)
    error_message = "Log retention must be a valid CloudWatch retention value."
  }
}

variable "enable_dashboard" {
  description = "Create a CloudWatch dashboard for WAF metrics visualization"
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Tags — Enterprise Tagging Strategy
# -----------------------------------------------------------------------------

variable "tags" {
  description = "Base tags applied to all resources. Module adds Name and ManagedBy automatically."
  type        = map(string)
  default     = {}
}

variable "owner" {
  description = "Team or individual responsible for this WAF deployment"
  type        = string
  default     = ""
}

variable "cost_center" {
  description = "Cost center for billing attribution"
  type        = string
  default     = ""
}

variable "data_classification" {
  description = "Data classification level (public, internal, confidential, restricted)"
  type        = string
  default     = "internal"

  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}
