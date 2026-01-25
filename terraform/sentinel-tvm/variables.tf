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
