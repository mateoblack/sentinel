package cli

import (
	"testing"
)

func TestGenerateLoginURL(t *testing.T) {
	tests := []struct {
		name            string
		region          string
		path            string
		wantURLPrefix   string
		wantDestination string
	}{
		{
			name:            "empty region and path uses us-east-1 defaults",
			region:          "",
			path:            "",
			wantURLPrefix:   "https://us-east-1.signin.aws.amazon.com/federation",
			wantDestination: "https://console.aws.amazon.com/",
		},
		{
			name:            "us-east-1 region with no path",
			region:          "us-east-1",
			path:            "",
			wantURLPrefix:   "https://us-east-1.signin.aws.amazon.com/federation",
			wantDestination: "https://us-east-1.console.aws.amazon.com/console/home?region=us-east-1",
		},
		{
			name:            "us-west-2 region with path",
			region:          "us-west-2",
			path:            "s3",
			wantURLPrefix:   "https://us-east-1.signin.aws.amazon.com/federation",
			wantDestination: "https://us-west-2.console.aws.amazon.com/s3?region=us-west-2",
		},
		{
			name:            "china region cn-north-1",
			region:          "cn-north-1",
			path:            "",
			wantURLPrefix:   "https://signin.amazonaws.cn/federation",
			wantDestination: "https://cn-north-1.console.amazonaws.cn/console/home?region=cn-north-1",
		},
		{
			name:            "china region with path",
			region:          "cn-northwest-1",
			path:            "ec2",
			wantURLPrefix:   "https://signin.amazonaws.cn/federation",
			wantDestination: "https://cn-northwest-1.console.amazonaws.cn/ec2?region=cn-northwest-1",
		},
		{
			name:            "govcloud us-gov-west-1",
			region:          "us-gov-west-1",
			path:            "",
			wantURLPrefix:   "https://signin.amazonaws-us-gov.com/federation",
			wantDestination: "https://us-gov-west-1.console.amazonaws-us-gov.com/console/home?region=us-gov-west-1",
		},
		{
			name:            "govcloud with path",
			region:          "us-gov-east-1",
			path:            "iam",
			wantURLPrefix:   "https://signin.amazonaws-us-gov.com/federation",
			wantDestination: "https://us-gov-east-1.console.amazonaws-us-gov.com/iam?region=us-gov-east-1",
		},
		{
			name:            "eu sovereign cloud eusc-de-east-1",
			region:          "eusc-de-east-1",
			path:            "",
			wantURLPrefix:   "https://signin.amazonaws-eusc.eu/federation",
			wantDestination: "https://eusc-de-east-1.console.amazonaws-eusc.eu/console/home?region=eusc-de-east-1",
		},
		{
			name:            "eu sovereign cloud with path",
			region:          "eusc-de-east-1",
			path:            "cloudwatch",
			wantURLPrefix:   "https://signin.amazonaws-eusc.eu/federation",
			wantDestination: "https://eusc-de-east-1.console.amazonaws-eusc.eu/cloudwatch?region=eusc-de-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURLPrefix, gotDestination := generateLoginURL(tt.region, tt.path)
			if gotURLPrefix != tt.wantURLPrefix {
				t.Errorf("generateLoginURL() URLPrefix = %q, want %q", gotURLPrefix, tt.wantURLPrefix)
			}
			if gotDestination != tt.wantDestination {
				t.Errorf("generateLoginURL() destination = %q, want %q", gotDestination, tt.wantDestination)
			}
		})
	}
}

func TestCanProviderBeUsedForLogin(t *testing.T) {
	tests := []struct {
		name     string
		provider interface{}
		want     bool
	}{
		{
			name:     "nil provider returns false",
			provider: nil,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test with nil - note: can't easily test typed providers without
			// creating full vault instances, which requires AWS credentials.
			// This tests the base case.
			got, err := canProviderBeUsedForLogin(nil)
			if err != nil {
				t.Errorf("canProviderBeUsedForLogin() error = %v", err)
				return
			}
			if got != false {
				t.Errorf("canProviderBeUsedForLogin(nil) = %v, want false", got)
			}
		})
	}
}

func TestLoginCommandInput_Defaults(t *testing.T) {
	input := LoginCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.UseStdout != false {
		t.Errorf("expected UseStdout to be false, got %v", input.UseStdout)
	}
	if input.Path != "" {
		t.Errorf("expected empty Path, got %q", input.Path)
	}
	if input.NoSession != false {
		t.Errorf("expected NoSession to be false, got %v", input.NoSession)
	}
	if input.AutoLogout != false {
		t.Errorf("expected AutoLogout to be false, got %v", input.AutoLogout)
	}
}

func TestLoginCommandInput_WithValues(t *testing.T) {
	input := LoginCommandInput{
		ProfileName: "test-profile",
		UseStdout:   true,
		Path:        "ec2",
		NoSession:   true,
		AutoLogout:  true,
	}

	if input.ProfileName != "test-profile" {
		t.Errorf("expected ProfileName 'test-profile', got %q", input.ProfileName)
	}
	if !input.UseStdout {
		t.Errorf("expected UseStdout to be true")
	}
	if input.Path != "ec2" {
		t.Errorf("expected Path 'ec2', got %q", input.Path)
	}
	if !input.NoSession {
		t.Errorf("expected NoSession to be true")
	}
	if !input.AutoLogout {
		t.Errorf("expected AutoLogout to be true")
	}
}

func TestGenerateLoginURL_EdgeCases(t *testing.T) {
	// Test with unusual but valid path
	prefix, dest := generateLoginURL("us-east-1", "lambda/home")
	if prefix != "https://us-east-1.signin.aws.amazon.com/federation" {
		t.Errorf("unexpected prefix: %s", prefix)
	}
	if dest != "https://us-east-1.console.aws.amazon.com/lambda/home?region=us-east-1" {
		t.Errorf("unexpected destination: %s", dest)
	}

	// Test with path containing query-like characters (should be included as-is)
	prefix, dest = generateLoginURL("eu-west-1", "ec2/v2/home")
	if dest != "https://eu-west-1.console.aws.amazon.com/ec2/v2/home?region=eu-west-1" {
		t.Errorf("unexpected destination with nested path: %s", dest)
	}
}
