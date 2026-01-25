# Sentinel Protected Role Terraform Module - Variables
# Configuration for roles that trust ONLY the TVM execution role

variable "role_name" {
  description = "Name of the protected role to create"
  type        = string

  validation {
    condition     = can(regex("^SentinelProtected-", var.role_name))
    error_message = "Role name must start with 'SentinelProtected-' prefix."
  }
}

variable "tvm_execution_role_arn" {
  description = "ARN of the Sentinel TVM Lambda execution role that can assume this role"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::", var.tvm_execution_role_arn))
    error_message = "TVM execution role ARN must be a valid IAM role ARN."
  }
}

variable "assume_role_policy_additions" {
  description = "Additional trust policy statements to include (optional)"
  type = list(object({
    Effect    = string
    Principal = any
    Action    = string
    Condition = optional(any)
  }))
  default = []
}

variable "managed_policy_arns" {
  description = "List of managed policy ARNs to attach to the role"
  type        = list(string)
  default     = []
}

variable "inline_policies" {
  description = "Map of inline policy names to JSON policy documents"
  type        = map(string)
  default     = {}
}

variable "tags" {
  description = "Tags to apply to the role"
  type        = map(string)
  default     = {}
}

variable "max_session_duration" {
  description = "Maximum session duration in seconds (3600-43200)"
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "Max session duration must be between 3600 (1 hour) and 43200 (12 hours)."
  }
}

variable "description" {
  description = "Description for the IAM role"
  type        = string
  default     = "Sentinel-protected role that trusts only the Lambda TVM"
}
