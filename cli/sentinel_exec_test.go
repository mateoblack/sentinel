package cli

import (
	"context"
	"strings"
	"testing"
)

func TestSentinelExecCommand_NestedSubshell(t *testing.T) {
	// Set AWS_SENTINEL to simulate nested shell
	t.Setenv("AWS_SENTINEL", "test-profile")

	input := SentinelExecCommandInput{
		ProfileName:     "test",
		PolicyParameter: "/sentinel/test",
	}

	_, err := SentinelExecCommand(context.Background(), input, nil)
	if err == nil {
		t.Fatal("expected error for nested subshell")
	}
	if !strings.Contains(err.Error(), "existing sentinel subshell") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSentinelExecCommand_NestedSubshell_ErrorMessage(t *testing.T) {
	// Set AWS_SENTINEL to simulate nested shell
	t.Setenv("AWS_SENTINEL", "production")

	input := SentinelExecCommandInput{
		ProfileName:     "different-profile",
		PolicyParameter: "/sentinel/policies/default",
	}

	_, err := SentinelExecCommand(context.Background(), input, nil)
	if err == nil {
		t.Fatal("expected error for nested subshell")
	}

	// Verify the error message contains helpful guidance
	errMsg := err.Error()
	if !strings.Contains(errMsg, "exit") {
		t.Errorf("error should mention 'exit' as a solution: %v", errMsg)
	}
	if !strings.Contains(errMsg, "unset AWS_SENTINEL") {
		t.Errorf("error should mention 'unset AWS_SENTINEL' as a solution: %v", errMsg)
	}
}

// Example showing how to use sentinel exec command.
func Example_sentinelExecCommand() {
	// The sentinel exec command executes a subprocess with policy-gated AWS credentials:
	//
	//   sentinel exec --profile myprofile --policy-parameter /sentinel/policies/default -- aws s3 ls
	//
	// This will:
	// 1. Load the policy from SSM parameter /sentinel/policies/default
	// 2. Evaluate if the current user can access the "myprofile" profile at the current time
	// 3. If allowed, retrieve credentials and inject them into the subprocess environment
	// 4. Execute "aws s3 ls" with the injected credentials
}
