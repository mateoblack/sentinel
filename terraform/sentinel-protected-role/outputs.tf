# Sentinel Protected Role Terraform Module - Outputs

output "role_arn" {
  description = "ARN of the protected IAM role"
  value       = aws_iam_role.protected.arn
}

output "role_name" {
  description = "Name of the protected IAM role"
  value       = aws_iam_role.protected.name
}

output "role_id" {
  description = "Unique ID of the protected IAM role"
  value       = aws_iam_role.protected.unique_id
}
