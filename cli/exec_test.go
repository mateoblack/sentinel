package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func ExampleExecCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExecCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"--debug", "exec", "--no-session", "llamas", "--", "sh", "-c", "echo $AWS_ACCESS_KEY_ID",
	}))

	// Output:
	// ABC
}

func TestExecCommandInput_Validate_Success(t *testing.T) {
	input := ExecCommandInput{
		ProfileName: "test",
		NoSession:   false,
	}

	err := input.validate()
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestExecCommandInput_Validate_Ec2AndEcsConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEc2Server: true,
		StartEcsServer: true,
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when both --ec2-server and --ecs-server are set")
	}
}

func TestExecCommandInput_Validate_Ec2AndJsonConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEc2Server: true,
		JSONDeprecated: true,
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when both --ec2-server and --json are set")
	}
}

func TestExecCommandInput_Validate_Ec2AndNoSessionConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEc2Server: true,
		NoSession:      true,
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when both --ec2-server and --no-session are set")
	}
}

func TestExecCommandInput_Validate_EcsAndJsonConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEcsServer: true,
		JSONDeprecated: true,
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when both --ecs-server and --json are set")
	}
}

func TestExecCommandInput_Validate_EcsAndNoSessionConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEcsServer: true,
		NoSession:      true,
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when both --ecs-server and --no-session are set")
	}
}

func TestExecCommandInput_Validate_EcsAndTerminalPromptConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEcsServer: true,
		Config:         vault.ProfileConfig{MfaPromptMethod: "terminal"},
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when --ecs-server is used with terminal prompt")
	}
}

func TestExecCommandInput_Validate_Ec2AndTerminalPromptConflict(t *testing.T) {
	input := ExecCommandInput{
		StartEc2Server: true,
		Config:         vault.ProfileConfig{MfaPromptMethod: "terminal"},
	}

	err := input.validate()
	if err == nil {
		t.Error("expected error when --ec2-server is used with terminal prompt")
	}
}

func TestHasBackgroundServer(t *testing.T) {
	tests := []struct {
		name   string
		input  ExecCommandInput
		expect bool
	}{
		{
			name:   "no server",
			input:  ExecCommandInput{},
			expect: false,
		},
		{
			name:   "ecs server",
			input:  ExecCommandInput{StartEcsServer: true},
			expect: true,
		},
		{
			name:   "ec2 server",
			input:  ExecCommandInput{StartEc2Server: true},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasBackgroundServer(tt.input)
			if got != tt.expect {
				t.Errorf("hasBackgroundServer() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestCreateEnv(t *testing.T) {
	// Save and clear AWS env vars
	savedVars := make(map[string]string)
	varsToSave := []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_FILE", "AWS_DEFAULT_PROFILE",
		"AWS_PROFILE", "AWS_SDK_LOAD_CONFIG",
	}
	for _, v := range varsToSave {
		savedVars[v] = os.Getenv(v)
		os.Setenv(v, "test-value-"+v)
	}
	defer func() {
		for k, v := range savedVars {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	env := createEnv("myprofile", "us-west-2", "")

	// Check AWS_VAULT is set
	awsVaultFound := false
	for _, e := range env {
		if e == "AWS_VAULT=myprofile" {
			awsVaultFound = true
		}
		// Check that AWS credential vars are unset
		for _, v := range varsToSave {
			if e == v+"=test-value-"+v {
				t.Errorf("expected %s to be unset, but found in env", v)
			}
		}
	}

	if !awsVaultFound {
		t.Error("expected AWS_VAULT=myprofile in env")
	}

	// Check region vars
	regionFound := false
	defaultRegionFound := false
	for _, e := range env {
		if e == "AWS_REGION=us-west-2" {
			regionFound = true
		}
		if e == "AWS_DEFAULT_REGION=us-west-2" {
			defaultRegionFound = true
		}
	}
	if !regionFound {
		t.Error("expected AWS_REGION=us-west-2 in env")
	}
	if !defaultRegionFound {
		t.Error("expected AWS_DEFAULT_REGION=us-west-2 in env")
	}
}

func TestCreateEnv_WithEndpointURL(t *testing.T) {
	env := createEnv("myprofile", "", "http://localhost:4566")

	endpointFound := false
	for _, e := range env {
		if e == "AWS_ENDPOINT_URL=http://localhost:4566" {
			endpointFound = true
		}
	}
	if !endpointFound {
		t.Error("expected AWS_ENDPOINT_URL in env")
	}
}

func TestCreateEnv_NoRegion(t *testing.T) {
	env := createEnv("myprofile", "", "")

	// Should not have region vars when region is empty
	for _, e := range env {
		if e == "AWS_REGION=" || e == "AWS_DEFAULT_REGION=" {
			t.Error("expected no empty region vars in env")
		}
	}
}

func TestEnviron_Set(t *testing.T) {
	env := environ{"FOO=bar", "BAZ=qux"}
	env.Set("NEW", "value")

	found := false
	for _, e := range env {
		if e == "NEW=value" {
			found = true
		}
	}
	if !found {
		t.Error("expected NEW=value in env")
	}
}

func TestEnviron_Set_Override(t *testing.T) {
	env := environ{"FOO=bar", "BAZ=qux"}
	env.Set("FOO", "newvalue")

	fooCount := 0
	hasNewValue := false
	for _, e := range env {
		if e == "FOO=bar" || e == "FOO=newvalue" {
			fooCount++
		}
		if e == "FOO=newvalue" {
			hasNewValue = true
		}
	}

	if fooCount != 1 {
		t.Errorf("expected exactly 1 FOO entry, got %d", fooCount)
	}
	if !hasNewValue {
		t.Error("expected FOO=newvalue in env")
	}
}

func TestEnviron_Unset(t *testing.T) {
	env := environ{"FOO=bar", "BAZ=qux", "OTHER=val"}
	env.Unset("BAZ")

	for _, e := range env {
		if e == "BAZ=qux" {
			t.Error("expected BAZ to be unset")
		}
	}
}

func TestEnviron_Unset_NotFound(t *testing.T) {
	env := environ{"FOO=bar", "BAZ=qux"}
	originalLen := len(env)
	env.Unset("NOTFOUND")

	if len(env) != originalLen {
		t.Error("expected env length to remain unchanged when unsetting non-existent key")
	}
}

func TestGetDefaultShell(t *testing.T) {
	// Save and restore SHELL env
	savedShell := os.Getenv("SHELL")
	defer func() {
		if savedShell == "" {
			os.Unsetenv("SHELL")
		} else {
			os.Setenv("SHELL", savedShell)
		}
	}()

	// Test with SHELL set
	os.Setenv("SHELL", "/bin/zsh")
	shell := getDefaultShell()
	if shell != "/bin/zsh" {
		t.Errorf("expected /bin/zsh, got %s", shell)
	}

	// Test without SHELL
	os.Unsetenv("SHELL")
	shell = getDefaultShell()
	if runtime.GOOS == "windows" {
		if shell != "cmd.exe" {
			t.Errorf("expected cmd.exe on windows, got %s", shell)
		}
	} else {
		if shell != "/bin/sh" {
			t.Errorf("expected /bin/sh on unix, got %s", shell)
		}
	}
}

func TestExecCommand_InNestedVaultError(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile test]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_VAULT", "existing-profile") // Simulate nested vault
	defer os.Unsetenv("AWS_VAULT")

	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "test", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := ExecCommandInput{
		ProfileName: "test",
		Command:     "echo",
		Args:        []string{"hello"},
	}

	_, err = ExecCommand(input, configFile, kr)
	if err == nil {
		t.Error("expected error when running in nested aws-vault")
	}
}

func TestExecCommandInput_Defaults(t *testing.T) {
	input := ExecCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.Command != "" {
		t.Errorf("expected empty Command, got %q", input.Command)
	}
	if input.StartEc2Server {
		t.Error("expected StartEc2Server to be false")
	}
	if input.StartEcsServer {
		t.Error("expected StartEcsServer to be false")
	}
	if input.Lazy {
		t.Error("expected Lazy to be false")
	}
	if input.NoSession {
		t.Error("expected NoSession to be false")
	}
	if input.SessionDuration != 0 {
		t.Errorf("expected zero SessionDuration, got %v", input.SessionDuration)
	}
}

func TestExecCommandInput_WithValues(t *testing.T) {
	input := ExecCommandInput{
		ProfileName:     "production",
		Command:         "aws",
		Args:            []string{"s3", "ls"},
		StartEcsServer:  true,
		Lazy:            true,
		SessionDuration: time.Hour,
	}

	if input.ProfileName != "production" {
		t.Errorf("expected 'production', got %q", input.ProfileName)
	}
	if input.Command != "aws" {
		t.Errorf("expected 'aws', got %q", input.Command)
	}
	if len(input.Args) != 2 {
		t.Errorf("expected 2 args, got %d", len(input.Args))
	}
	if !input.StartEcsServer {
		t.Error("expected StartEcsServer to be true")
	}
	if !input.Lazy {
		t.Error("expected Lazy to be true")
	}
	if input.SessionDuration != time.Hour {
		t.Errorf("expected 1h duration, got %v", input.SessionDuration)
	}
}
