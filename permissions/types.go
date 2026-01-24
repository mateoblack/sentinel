// Package permissions provides permission types and registry for Sentinel features.
// It enables programmatic discovery of what AWS IAM actions each Sentinel feature
// requires, supporting the `sentinel permissions` command and guided setup.
package permissions

// Subsystem identifies a functional grouping of Sentinel features.
type Subsystem string

const (
	// SubsystemCore provides policy loading from SSM.
	SubsystemCore Subsystem = "core"
	// SubsystemCredentials provides STS operations for credential issuance.
	SubsystemCredentials Subsystem = "credentials"
	// SubsystemApprovals provides DynamoDB storage for approval workflows.
	SubsystemApprovals Subsystem = "approvals"
	// SubsystemBreakGlass provides DynamoDB storage for break-glass events.
	SubsystemBreakGlass Subsystem = "breakglass"
	// SubsystemNotifications provides SNS and webhook notification delivery.
	SubsystemNotifications Subsystem = "notifications"
	// SubsystemAudit provides CloudTrail session verification.
	SubsystemAudit Subsystem = "audit"
	// SubsystemEnforce provides IAM trust policy analysis.
	SubsystemEnforce Subsystem = "enforce"
	// SubsystemBootstrap provides SSM parameter management for setup.
	SubsystemBootstrap Subsystem = "bootstrap"
	// SubsystemSessions provides DynamoDB storage for server session tracking.
	SubsystemSessions Subsystem = "sessions"
)

// IsValid returns true if the Subsystem is a known value.
func (s Subsystem) IsValid() bool {
	switch s {
	case SubsystemCore, SubsystemCredentials, SubsystemApprovals,
		SubsystemBreakGlass, SubsystemNotifications, SubsystemAudit,
		SubsystemEnforce, SubsystemBootstrap, SubsystemSessions:
		return true
	}
	return false
}

// String returns the string representation of the Subsystem.
func (s Subsystem) String() string {
	return string(s)
}

// AllSubsystems returns all valid subsystem values.
func AllSubsystems() []Subsystem {
	return []Subsystem{
		SubsystemCore,
		SubsystemCredentials,
		SubsystemApprovals,
		SubsystemBreakGlass,
		SubsystemNotifications,
		SubsystemAudit,
		SubsystemEnforce,
		SubsystemBootstrap,
		SubsystemSessions,
	}
}

// Feature identifies a specific Sentinel capability that requires AWS permissions.
type Feature string

const (
	// FeaturePolicyLoad loads policies from SSM Parameter Store.
	FeaturePolicyLoad Feature = "policy_load"
	// FeatureCredentialIssue issues credentials via STS AssumeRole.
	FeatureCredentialIssue Feature = "credential_issue"
	// FeatureApprovalWorkflow manages approval requests with DynamoDB.
	FeatureApprovalWorkflow Feature = "approval_workflow"
	// FeatureBreakGlass manages emergency access events with DynamoDB.
	FeatureBreakGlass Feature = "breakglass"
	// FeatureNotifySNS delivers notifications via AWS SNS.
	FeatureNotifySNS Feature = "notify_sns"
	// FeatureNotifyWebhook delivers notifications via HTTP webhooks (no AWS permissions).
	FeatureNotifyWebhook Feature = "notify_webhook"
	// FeatureAuditVerify verifies sessions using CloudTrail.
	FeatureAuditVerify Feature = "audit_verify"
	// FeatureEnforceAnalyze analyzes IAM trust policies for enforcement.
	FeatureEnforceAnalyze Feature = "enforce_analyze"
	// FeatureBootstrapPlan plans bootstrap operations (SSM read).
	FeatureBootstrapPlan Feature = "bootstrap_plan"
	// FeatureBootstrapApply applies bootstrap operations (SSM write).
	FeatureBootstrapApply Feature = "bootstrap_apply"
	// FeatureSessionTracking manages server sessions with DynamoDB.
	FeatureSessionTracking Feature = "session_tracking"
)

// IsValid returns true if the Feature is a known value.
func (f Feature) IsValid() bool {
	switch f {
	case FeaturePolicyLoad, FeatureCredentialIssue, FeatureApprovalWorkflow,
		FeatureBreakGlass, FeatureNotifySNS, FeatureNotifyWebhook,
		FeatureAuditVerify, FeatureEnforceAnalyze, FeatureBootstrapPlan,
		FeatureBootstrapApply, FeatureSessionTracking:
		return true
	}
	return false
}

// String returns the string representation of the Feature.
func (f Feature) String() string {
	return string(f)
}

// AllFeatures returns all valid feature values.
func AllFeatures() []Feature {
	return []Feature{
		FeaturePolicyLoad,
		FeatureCredentialIssue,
		FeatureApprovalWorkflow,
		FeatureBreakGlass,
		FeatureNotifySNS,
		FeatureNotifyWebhook,
		FeatureAuditVerify,
		FeatureEnforceAnalyze,
		FeatureBootstrapPlan,
		FeatureBootstrapApply,
		FeatureSessionTracking,
	}
}

// subsystemFeatures maps subsystems to their features.
var subsystemFeatures = map[Subsystem][]Feature{
	SubsystemCore:          {FeaturePolicyLoad},
	SubsystemCredentials:   {FeatureCredentialIssue},
	SubsystemApprovals:     {FeatureApprovalWorkflow},
	SubsystemBreakGlass:    {FeatureBreakGlass},
	SubsystemNotifications: {FeatureNotifySNS, FeatureNotifyWebhook},
	SubsystemAudit:         {FeatureAuditVerify},
	SubsystemEnforce:       {FeatureEnforceAnalyze},
	SubsystemBootstrap:     {FeatureBootstrapPlan, FeatureBootstrapApply},
	SubsystemSessions:      {FeatureSessionTracking},
}

// Features returns the features belonging to this subsystem.
func (s Subsystem) Features() []Feature {
	return subsystemFeatures[s]
}

// Permission represents a single AWS IAM permission requirement.
type Permission struct {
	// Service is the AWS service name (e.g., "ssm", "dynamodb", "sns").
	Service string
	// Actions are the IAM actions required (e.g., "ssm:GetParameter").
	Actions []string
	// Resource is the ARN pattern for the resource (e.g., "arn:aws:ssm:*:*:parameter/sentinel/*").
	Resource string
	// Description provides human-readable context for this permission.
	Description string
}

// FeaturePermissions contains the permissions required for a specific feature.
type FeaturePermissions struct {
	// Feature identifies which feature these permissions are for.
	Feature Feature
	// Subsystem identifies which subsystem this feature belongs to.
	Subsystem Subsystem
	// Permissions lists all AWS permissions required for this feature.
	Permissions []Permission
	// Optional indicates if the feature works without these permissions.
	// True for features like notifications that enhance but don't block core functionality.
	Optional bool
}
