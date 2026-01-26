# Sentinel TVM Terraform Module - Variables
# Required and optional inputs for Lambda TVM deployment

variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
  default     = "sentinel-tvm"
}

variable "lambda_zip_path" {
  description = "Path to the Lambda deployment package (zip file)"
  type        = string
}

variable "policy_parameter" {
  description = "SSM parameter path for the Sentinel policy"
  type        = string
}

variable "policy_root" {
  description = "SSM path root for profile discovery (e.g., /sentinel/policies)"
  type        = string
  default     = ""
}

variable "session_table" {
  description = "DynamoDB table name for session tracking"
  type        = string
  default     = ""
}

variable "approval_table" {
  description = "DynamoDB table name for approval workflows"
  type        = string
  default     = ""
}

variable "breakglass_table" {
  description = "DynamoDB table name for break-glass events"
  type        = string
  default     = ""
}

variable "memory_size" {
  description = "Amount of memory in MB for the Lambda function"
  type        = number
  default     = 256
}

variable "timeout" {
  description = "Timeout in seconds for the Lambda function"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# MDM Configuration
variable "mdm_provider" {
  description = "MDM provider type: 'jamf', 'intune', 'kandji', or '' (disabled)"
  type        = string
  default     = ""
}

variable "mdm_base_url" {
  description = "Base URL for the MDM API (e.g., https://company.jamfcloud.com)"
  type        = string
  default     = ""
}

variable "mdm_api_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the MDM API token. Recommended over mdm_api_token."
  type        = string
  default     = ""
}

variable "mdm_api_token" {
  description = "DEPRECATED: Use mdm_api_secret_arn instead. MDM API bearer token passed via environment variable."
  type        = string
  default     = ""
  sensitive   = true
}

variable "require_device_posture" {
  description = "When true, reject credentials if device posture verification fails"
  type        = bool
  default     = false
}

# Policy Signing Configuration
variable "policy_signing_key_arn" {
  description = "KMS key ARN or alias for policy signature verification. When set, policies must have valid signatures."
  type        = string
  default     = ""
}

variable "enforce_policy_signing" {
  description = "When true, reject policies without valid signatures. Defaults to true when policy_signing_key_arn is set."
  type        = bool
  default     = null # Will default to true when signing key is set
}
