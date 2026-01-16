package bootstrap

import (
	"encoding/json"
	"strings"
)

// IAMPolicyDocument represents an AWS IAM policy document.
type IAMPolicyDocument struct {
	Version   string         `json:"Version"`
	Statement []IAMStatement `json:"Statement"`
}

// IAMStatement represents a single statement in an IAM policy.
type IAMStatement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// IAM policy version required by AWS.
const iamPolicyVersion = "2012-10-17"

// SSM read actions for the reader policy.
var ssmReadActions = []string{
	"ssm:GetParameter",
	"ssm:GetParameters",
	"ssm:GetParametersByPath",
}

// SSM write actions for the admin policy (in addition to read actions).
var ssmWriteActions = []string{
	"ssm:PutParameter",
	"ssm:DeleteParameter",
	"ssm:AddTagsToResource",
	"ssm:RemoveTagsFromResource",
}

// GenerateReaderPolicy creates an IAM policy document for read-only access
// to Sentinel policy parameters in SSM.
func GenerateReaderPolicy(policyRoot string) IAMPolicyDocument {
	return IAMPolicyDocument{
		Version: iamPolicyVersion,
		Statement: []IAMStatement{
			{
				Sid:      "SentinelPolicyRead",
				Effect:   "Allow",
				Action:   ssmReadActions,
				Resource: []string{buildSSMResourceARN(policyRoot)},
			},
		},
	}
}

// GenerateAdminPolicy creates an IAM policy document for full access
// to Sentinel policy parameters in SSM.
func GenerateAdminPolicy(policyRoot string) IAMPolicyDocument {
	// Combine read and write actions
	allActions := make([]string, 0, len(ssmReadActions)+len(ssmWriteActions))
	allActions = append(allActions, ssmReadActions...)
	allActions = append(allActions, ssmWriteActions...)

	return IAMPolicyDocument{
		Version: iamPolicyVersion,
		Statement: []IAMStatement{
			{
				Sid:      "SentinelPolicyAdmin",
				Effect:   "Allow",
				Action:   allActions,
				Resource: []string{buildSSMResourceARN(policyRoot)},
			},
		},
	}
}

// FormatIAMPolicy marshals an IAM policy document to indented JSON.
func FormatIAMPolicy(doc IAMPolicyDocument) (string, error) {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// buildSSMResourceARN constructs the ARN pattern for SSM parameters.
// Uses wildcards for region and account for portability.
// Format: arn:aws:ssm:*:*:parameter{policyRoot}/*
func buildSSMResourceARN(policyRoot string) string {
	// Normalize: remove trailing slash if present
	root := strings.TrimSuffix(policyRoot, "/")
	return "arn:aws:ssm:*:*:parameter" + root + "/*"
}
