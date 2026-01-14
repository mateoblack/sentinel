package policy

import "time"

// Request represents a credential request to be evaluated.
type Request struct {
	User    string
	Profile string
	Time    time.Time
}

// Decision represents the outcome of policy evaluation.
type Decision struct {
	Effect      Effect
	MatchedRule string
	Reason      string
}

// Evaluate evaluates a credential request against a policy.
// It returns the decision for the first matching rule, or default deny if no rules match.
func Evaluate(policy *Policy, req *Request) Decision {
	// Stub implementation - tests should fail
	return Decision{}
}
