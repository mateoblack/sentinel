package errors

import (
	"fmt"
	"strings"
)

// Suggestions contains default fix suggestions for each error code.
var Suggestions = map[string]string{
	ErrCodeSSMAccessDenied: "Ensure your IAM policy includes: ssm:GetParameter on the policy parameter. " +
		"Run: sentinel permissions --feature policy_load",
	ErrCodeSSMParameterNotFound: "The SSM parameter does not exist. " +
		"Create it with: sentinel init bootstrap --profile <profile>",
	ErrCodeSSMKMSAccessDenied: "The SSM parameter is encrypted. " +
		"Ensure your IAM policy includes: kms:Decrypt on the KMS key used for encryption",
	ErrCodeSSMThrottled:         "SSM API rate limit exceeded. Wait a moment and retry.",
	ErrCodeSSMInvalidParameter:  "The SSM parameter name is invalid. Check the path format and characters.",
	ErrCodeDynamoDBAccessDenied: "Ensure your IAM policy includes DynamoDB permissions. " +
		"Run: sentinel permissions --feature approval_workflow",
	ErrCodeDynamoDBTableNotFound: "The DynamoDB table does not exist. " +
		"Create it with CloudFormation or Terraform using the template from: sentinel permissions --format terraform",
	ErrCodeDynamoDBThrottled:       "DynamoDB throughput exceeded. Wait a moment and retry, or increase table capacity.",
	ErrCodeDynamoDBConditionFailed: "The DynamoDB conditional check failed. The item may have been modified by another process.",
	ErrCodeIAMSimulateAccessDenied: "Permission checking requires iam:SimulatePrincipalPolicy. " +
		"This permission is optional - you can verify permissions manually instead.",
	ErrCodeIAMRoleNotFound:          "The IAM role does not exist. Verify the role ARN in your profile configuration.",
	ErrCodeIAMAccessDenied:          "IAM access denied. Check your IAM policies and permissions.",
	ErrCodePolicyDenied:             "Access denied by Sentinel policy.",
	ErrCodePolicyNotConfigured:      "No Sentinel policy is configured for this profile. Run: sentinel init wizard",
	ErrCodeConfigMissingCredentials: "No AWS credentials found. Configure credentials using: " +
		"aws configure, environment variables, or IAM role",
	ErrCodeConfigInvalidRegion:   "Invalid AWS region specified. Use a valid region code like us-east-1.",
	ErrCodeConfigProfileNotFound: "AWS profile not found in ~/.aws/config. " +
		"List available profiles with: aws configure list-profiles",
}

// GetSuggestion returns the default suggestion for an error code.
// Returns empty string if no suggestion is defined.
func GetSuggestion(code string) string {
	return Suggestions[code]
}

// WrapSSMError examines an SSM error and returns a SentinelError with context.
func WrapSSMError(err error, parameter string) SentinelError {
	if err == nil {
		return nil
	}

	var code string
	var message string
	var suggestion string

	errStr := strings.ToLower(err.Error())

	switch {
	case isParameterNotFound(errStr):
		code = ErrCodeSSMParameterNotFound
		message = fmt.Sprintf("SSM parameter not found: %s", parameter)
		suggestion = Suggestions[ErrCodeSSMParameterNotFound]
	case isKMSAccessDenied(errStr):
		code = ErrCodeSSMKMSAccessDenied
		message = fmt.Sprintf("KMS access denied for SSM parameter: %s", parameter)
		suggestion = Suggestions[ErrCodeSSMKMSAccessDenied]
	case isAccessDenied(errStr):
		code = ErrCodeSSMAccessDenied
		message = fmt.Sprintf("Access denied to SSM parameter: %s", parameter)
		suggestion = Suggestions[ErrCodeSSMAccessDenied]
	case isThrottled(errStr):
		code = ErrCodeSSMThrottled
		message = fmt.Sprintf("SSM API throttled while accessing: %s", parameter)
		suggestion = Suggestions[ErrCodeSSMThrottled]
	case isValidationError(errStr):
		code = ErrCodeSSMInvalidParameter
		message = fmt.Sprintf("Invalid SSM parameter: %s", parameter)
		suggestion = Suggestions[ErrCodeSSMInvalidParameter]
	default:
		code = ErrCodeSSMAccessDenied
		message = fmt.Sprintf("SSM error for parameter %s: %v", parameter, err)
		suggestion = "Check your AWS credentials and SSM permissions"
	}

	se := New(code, message, suggestion, err)
	return WithContext(se, "parameter", parameter)
}

// WrapDynamoDBError examines a DynamoDB error and returns a SentinelError.
func WrapDynamoDBError(err error, table, operation string) SentinelError {
	if err == nil {
		return nil
	}

	var code string
	var message string
	var suggestion string

	errStr := strings.ToLower(err.Error())

	switch {
	case isResourceNotFound(errStr):
		code = ErrCodeDynamoDBTableNotFound
		message = fmt.Sprintf("DynamoDB table not found: %s", table)
		suggestion = Suggestions[ErrCodeDynamoDBTableNotFound]
	case isAccessDenied(errStr):
		code = ErrCodeDynamoDBAccessDenied
		message = fmt.Sprintf("Access denied to DynamoDB table: %s", table)
		suggestion = Suggestions[ErrCodeDynamoDBAccessDenied]
	case isThrottled(errStr) || isProvisionedThroughputExceeded(errStr):
		code = ErrCodeDynamoDBThrottled
		message = fmt.Sprintf("DynamoDB throughput exceeded for table: %s", table)
		suggestion = Suggestions[ErrCodeDynamoDBThrottled]
	case isConditionalCheckFailed(errStr):
		code = ErrCodeDynamoDBConditionFailed
		message = fmt.Sprintf("DynamoDB conditional check failed for table: %s", table)
		suggestion = Suggestions[ErrCodeDynamoDBConditionFailed]
	default:
		code = ErrCodeDynamoDBAccessDenied
		message = fmt.Sprintf("DynamoDB error for table %s during %s: %v", table, operation, err)
		suggestion = "Check your AWS credentials and DynamoDB permissions"
	}

	se := New(code, message, suggestion, err)
	se = WithContext(se, "table", table)
	return WithContext(se, "operation", operation)
}

// WrapIAMError examines an IAM error and returns a SentinelError.
func WrapIAMError(err error, action, resource string) SentinelError {
	if err == nil {
		return nil
	}

	var code string
	var message string
	var suggestion string

	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "simulateprincipal") && isAccessDenied(errStr):
		code = ErrCodeIAMSimulateAccessDenied
		message = "Access denied to SimulatePrincipalPolicy"
		suggestion = Suggestions[ErrCodeIAMSimulateAccessDenied]
	case isNoSuchEntity(errStr):
		code = ErrCodeIAMRoleNotFound
		message = fmt.Sprintf("IAM entity not found: %s", resource)
		suggestion = Suggestions[ErrCodeIAMRoleNotFound]
	case isAccessDenied(errStr):
		code = ErrCodeIAMAccessDenied
		message = fmt.Sprintf("IAM access denied for action: %s", action)
		suggestion = Suggestions[ErrCodeIAMAccessDenied]
	default:
		code = ErrCodeIAMAccessDenied
		message = fmt.Sprintf("IAM error during %s on %s: %v", action, resource, err)
		suggestion = "Check your IAM policies and permissions"
	}

	se := New(code, message, suggestion, err)
	se = WithContext(se, "action", action)
	return WithContext(se, "resource", resource)
}

// PolicyRule represents a rule that was matched in policy evaluation.
// This is a simplified representation for error messaging.
type PolicyRule struct {
	Name        string
	Effect      string
	Description string
}

// NewPolicyDeniedError creates a SentinelError for policy denials.
func NewPolicyDeniedError(user, profile string, matchedRule *PolicyRule, hasApprovalWorkflow, hasBreakGlass bool) SentinelError {
	var message string
	var suggestion string

	if matchedRule == nil {
		message = fmt.Sprintf("Access denied for user %s to profile %s: no rule matches your request", user, profile)
		suggestion = "Contact your administrator to add a policy rule for this access pattern."
	} else if matchedRule.Effect == "deny" {
		message = fmt.Sprintf("Access denied for user %s to profile %s: rule '%s' explicitly denies access", user, profile, matchedRule.Name)
		if matchedRule.Description != "" {
			suggestion = fmt.Sprintf("Rule '%s' denies access because: %s", matchedRule.Name, matchedRule.Description)
		} else {
			suggestion = fmt.Sprintf("Rule '%s' explicitly denies this access. Contact your administrator if you need access.", matchedRule.Name)
		}
	} else {
		message = fmt.Sprintf("Access denied for user %s to profile %s", user, profile)
		suggestion = "No matching allow rule found. Contact your administrator."
	}

	// Add suggestions for alternative access methods
	var alternatives []string
	if hasApprovalWorkflow {
		alternatives = append(alternatives, fmt.Sprintf("Request access with: sentinel request --profile %s", profile))
	}
	if hasBreakGlass {
		alternatives = append(alternatives, fmt.Sprintf("For emergencies, use: sentinel breakglass --profile %s", profile))
	}

	if len(alternatives) > 0 {
		suggestion += "\n\nAlternatives:\n- " + strings.Join(alternatives, "\n- ")
	}

	se := New(ErrCodePolicyDenied, message, suggestion, nil)
	se = WithContext(se, "user", user)
	se = WithContext(se, "profile", profile)
	if matchedRule != nil {
		se = WithContext(se, "matched_rule", matchedRule.Name)
	}
	return se
}

// isAccessDenied checks if error contains access denied indicators.
func isAccessDenied(errStr string) bool {
	return strings.Contains(errStr, "accessdenied") ||
		strings.Contains(errStr, "access denied") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "not authorized") ||
		strings.Contains(errStr, "403")
}

// isParameterNotFound checks if error indicates parameter not found.
func isParameterNotFound(errStr string) bool {
	return strings.Contains(errStr, "parameternotfound") ||
		strings.Contains(errStr, "parameter not found") ||
		strings.Contains(errStr, "parameterversionnotfound")
}

// isResourceNotFound checks if error indicates resource not found.
func isResourceNotFound(errStr string) bool {
	return strings.Contains(errStr, "resourcenotfound") ||
		strings.Contains(errStr, "resource not found") ||
		strings.Contains(errStr, "table not found") ||
		strings.Contains(errStr, "cannot do operations on a non-existent table")
}

// isThrottled checks if error indicates throttling.
func isThrottled(errStr string) bool {
	return strings.Contains(errStr, "throttl") ||
		strings.Contains(errStr, "rate exceeded") ||
		strings.Contains(errStr, "too many requests") ||
		strings.Contains(errStr, "slowdown")
}

// isKMSAccessDenied checks if error indicates KMS access denied.
func isKMSAccessDenied(errStr string) bool {
	return (strings.Contains(errStr, "kms") || strings.Contains(errStr, "key")) &&
		isAccessDenied(errStr)
}

// isValidationError checks if error indicates validation failure.
func isValidationError(errStr string) bool {
	return strings.Contains(errStr, "validation") ||
		strings.Contains(errStr, "invalid parameter")
}

// isNoSuchEntity checks if error indicates entity not found.
func isNoSuchEntity(errStr string) bool {
	return strings.Contains(errStr, "nosuchentity") ||
		strings.Contains(errStr, "no such entity") ||
		strings.Contains(errStr, "cannot find")
}

// isProvisionedThroughputExceeded checks if error indicates throughput exceeded.
func isProvisionedThroughputExceeded(errStr string) bool {
	return strings.Contains(errStr, "provisionedthroughputexceeded") ||
		strings.Contains(errStr, "throughput exceeded") ||
		strings.Contains(errStr, "capacity")
}

// isConditionalCheckFailed checks if error indicates conditional check failure.
func isConditionalCheckFailed(errStr string) bool {
	return strings.Contains(errStr, "conditionalcheckfailed") ||
		strings.Contains(errStr, "conditional check failed") ||
		strings.Contains(errStr, "condition expression")
}
