package permissions

// registry maps features to their required AWS IAM permissions.
// This is the source of truth for Sentinel's permission requirements.
var registry = map[Feature]FeaturePermissions{
	FeaturePolicyLoad: {
		Feature:   FeaturePolicyLoad,
		Subsystem: SubsystemCore,
		Permissions: []Permission{
			{
				Service: "ssm",
				Actions: []string{
					"ssm:GetParameter",
					"ssm:GetParameters",
					"ssm:GetParametersByPath",
				},
				Resource:    "arn:aws:ssm:*:*:parameter/sentinel/policies/*",
				Description: "Read policy parameters from SSM Parameter Store",
			},
		},
		Optional: false,
	},

	FeatureCredentialIssue: {
		Feature:   FeatureCredentialIssue,
		Subsystem: SubsystemCredentials,
		Permissions: []Permission{
			{
				Service: "sts",
				Actions: []string{
					"sts:AssumeRole",
				},
				Resource:    "arn:aws:iam::*:role/*",
				Description: "Assume IAM roles with SourceIdentity stamping",
			},
		},
		Optional: false,
	},

	FeatureApprovalWorkflow: {
		Feature:   FeatureApprovalWorkflow,
		Subsystem: SubsystemApprovals,
		Permissions: []Permission{
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:PutItem",
					"dynamodb:GetItem",
					"dynamodb:DeleteItem",
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-requests",
				Description: "Manage approval requests in DynamoDB",
			},
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-requests/index/*",
				Description: "Query approval requests by GSI (requester, status, profile)",
			},
		},
		Optional: false,
	},

	FeatureBreakGlass: {
		Feature:   FeatureBreakGlass,
		Subsystem: SubsystemBreakGlass,
		Permissions: []Permission{
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:PutItem",
					"dynamodb:GetItem",
					"dynamodb:DeleteItem",
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-breakglass",
				Description: "Manage break-glass events in DynamoDB",
			},
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-breakglass/index/*",
				Description: "Query break-glass events by GSI (invoker, status, profile)",
			},
		},
		Optional: false,
	},

	FeatureNotifySNS: {
		Feature:   FeatureNotifySNS,
		Subsystem: SubsystemNotifications,
		Permissions: []Permission{
			{
				Service: "sns",
				Actions: []string{
					"sns:Publish",
				},
				Resource:    "arn:aws:sns:*:*:sentinel-*",
				Description: "Publish notification events to SNS topics",
			},
		},
		Optional: true,
	},

	FeatureNotifyWebhook: {
		Feature:     FeatureNotifyWebhook,
		Subsystem:   SubsystemNotifications,
		Permissions: []Permission{},
		Optional:    true,
	},

	FeatureAuditVerify: {
		Feature:   FeatureAuditVerify,
		Subsystem: SubsystemAudit,
		Permissions: []Permission{
			{
				Service: "cloudtrail",
				Actions: []string{
					"cloudtrail:LookupEvents",
				},
				Resource:    "*",
				Description: "Query CloudTrail for session verification (resource-level permissions not supported for LookupEvents)",
			},
		},
		Optional: false,
	},

	FeatureEnforceAnalyze: {
		Feature:   FeatureEnforceAnalyze,
		Subsystem: SubsystemEnforce,
		Permissions: []Permission{
			{
				Service: "iam",
				Actions: []string{
					"iam:GetRole",
				},
				Resource:    "arn:aws:iam::*:role/*",
				Description: "Analyze IAM role trust policies for enforcement status",
			},
		},
		Optional: false,
	},

	FeatureBootstrapPlan: {
		Feature:   FeatureBootstrapPlan,
		Subsystem: SubsystemBootstrap,
		Permissions: []Permission{
			{
				Service: "ssm",
				Actions: []string{
					"ssm:GetParameter",
					"ssm:GetParametersByPath",
				},
				Resource:    "arn:aws:ssm:*:*:parameter/sentinel/*",
				Description: "Read existing SSM parameters for bootstrap planning",
			},
		},
		Optional: false,
	},

	FeatureBootstrapApply: {
		Feature:   FeatureBootstrapApply,
		Subsystem: SubsystemBootstrap,
		Permissions: []Permission{
			{
				Service: "ssm",
				Actions: []string{
					"ssm:PutParameter",
					"ssm:DeleteParameter",
					"ssm:AddTagsToResource",
					"ssm:RemoveTagsFromResource",
				},
				Resource:    "arn:aws:ssm:*:*:parameter/sentinel/*",
				Description: "Create and manage SSM parameters for bootstrap",
			},
		},
		Optional: false,
	},

	FeatureSessionTracking: {
		Feature:   FeatureSessionTracking,
		Subsystem: SubsystemSessions,
		Permissions: []Permission{
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:PutItem",
					"dynamodb:GetItem",
					"dynamodb:UpdateItem",
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-sessions",
				Description: "Manage server sessions in DynamoDB",
			},
			{
				Service: "dynamodb",
				Actions: []string{
					"dynamodb:Query",
				},
				Resource:    "arn:aws:dynamodb:*:*:table/sentinel-sessions/index/*",
				Description: "Query server sessions by GSI (user, status, profile)",
			},
		},
		Optional: false,
	},
}

// GetFeaturePermissions returns the permissions for a specific feature.
// Returns false if the feature is not registered.
func GetFeaturePermissions(f Feature) (FeaturePermissions, bool) {
	fp, ok := registry[f]
	return fp, ok
}

// GetSubsystemPermissions returns all permissions for features in a subsystem.
func GetSubsystemPermissions(s Subsystem) []FeaturePermissions {
	var result []FeaturePermissions
	for _, fp := range registry {
		if fp.Subsystem == s {
			result = append(result, fp)
		}
	}
	return result
}

// GetAllPermissions returns all registered feature permissions.
func GetAllPermissions() []FeaturePermissions {
	result := make([]FeaturePermissions, 0, len(registry))
	for _, fp := range registry {
		result = append(result, fp)
	}
	return result
}

// GetRequiredPermissions returns only non-optional feature permissions.
func GetRequiredPermissions() []FeaturePermissions {
	var result []FeaturePermissions
	for _, fp := range registry {
		if !fp.Optional {
			result = append(result, fp)
		}
	}
	return result
}

// UniqueActions returns a deduplicated list of all IAM actions from the given permissions.
func UniqueActions(perms []FeaturePermissions) []string {
	seen := make(map[string]bool)
	var result []string

	for _, fp := range perms {
		for _, p := range fp.Permissions {
			for _, action := range p.Actions {
				if !seen[action] {
					seen[action] = true
					result = append(result, action)
				}
			}
		}
	}

	return result
}

// ByService groups permissions by AWS service name.
func ByService(perms []FeaturePermissions) map[string][]Permission {
	result := make(map[string][]Permission)

	for _, fp := range perms {
		for _, p := range fp.Permissions {
			result[p.Service] = append(result[p.Service], p)
		}
	}

	return result
}
