# Sentinel TVM Terraform Module - Outputs

output "api_endpoint" {
  description = "API Gateway invoke URL for the Sentinel TVM"
  value       = aws_apigatewayv2_api.tvm.api_endpoint
}

output "function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.tvm.arn
}

output "function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.tvm.function_name
}

output "execution_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.tvm_execution.arn
}

output "api_id" {
  description = "ID of the API Gateway HTTP API"
  value       = aws_apigatewayv2_api.tvm.id
}

output "api_execution_arn" {
  description = "Execution ARN of the API Gateway (for IAM policies)"
  value       = aws_apigatewayv2_api.tvm.execution_arn
}
