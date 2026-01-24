package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func ExampleExportCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureExportCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"export", "--format=ini", "--no-session", "llamas",
	}))

	// Output:
	// [llamas]
	// aws_access_key_id=ABC
	// aws_secret_access_key=XYZ
	// region=us-east-1
}

func TestExportCommand_InNestedVaultError(t *testing.T) {
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

	input := ExportCommandInput{
		ProfileName: "test",
		Format:      FormatTypeEnv,
		NoSession:   true,
	}

	err = ExportCommand(input, configFile, kr)
	if err == nil {
		t.Error("expected error when running in nested aws-vault")
	}
}

func TestExportCommandInput_Defaults(t *testing.T) {
	input := ExportCommandInput{}

	if input.ProfileName != "" {
		t.Errorf("expected empty ProfileName, got %q", input.ProfileName)
	}
	if input.Format != "" {
		t.Errorf("expected empty Format, got %q", input.Format)
	}
	if input.NoSession {
		t.Error("expected NoSession to be false")
	}
	if input.UseStdout {
		t.Error("expected UseStdout to be false")
	}
	if input.SessionDuration != 0 {
		t.Errorf("expected zero SessionDuration, got %v", input.SessionDuration)
	}
}

func TestExportCommandInput_WithValues(t *testing.T) {
	input := ExportCommandInput{
		ProfileName:     "production",
		Format:          FormatTypeExportJSON,
		NoSession:       true,
		UseStdout:       true,
		SessionDuration: time.Hour,
	}

	if input.ProfileName != "production" {
		t.Errorf("expected 'production', got %q", input.ProfileName)
	}
	if input.Format != FormatTypeExportJSON {
		t.Errorf("expected 'json', got %q", input.Format)
	}
	if !input.NoSession {
		t.Error("expected NoSession to be true")
	}
	if !input.UseStdout {
		t.Error("expected UseStdout to be true")
	}
	if input.SessionDuration != time.Hour {
		t.Errorf("expected 1h duration, got %v", input.SessionDuration)
	}
}

func TestFormatTypeConstants(t *testing.T) {
	if FormatTypeEnv != "env" {
		t.Errorf("expected FormatTypeEnv to be 'env', got %q", FormatTypeEnv)
	}
	if FormatTypeExportEnv != "export-env" {
		t.Errorf("expected FormatTypeExportEnv to be 'export-env', got %q", FormatTypeExportEnv)
	}
	if FormatTypeExportJSON != "json" {
		t.Errorf("expected FormatTypeExportJSON to be 'json', got %q", FormatTypeExportJSON)
	}
	if FormatTypeExportINI != "ini" {
		t.Errorf("expected FormatTypeExportINI to be 'ini', got %q", FormatTypeExportINI)
	}
}

// mockCredsProvider implements aws.CredentialsProvider for testing
type mockCredsProvider struct {
	creds aws.Credentials
	err   error
}

func (m *mockCredsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if m.err != nil {
		return aws.Credentials{}, m.err
	}
	return m.creds, nil
}

func TestPrintJSON(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token123",
			CanExpire:       true,
			Expires:         time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
		Format:      FormatTypeExportJSON,
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printJSON(input, provider)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printJSON failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify JSON contains expected fields
	if !containsSubstring(output, "AccessKeyId") {
		t.Error("expected AccessKeyId in JSON output")
	}
	if !containsSubstring(output, "SecretAccessKey") {
		t.Error("expected SecretAccessKey in JSON output")
	}
	if !containsSubstring(output, "SessionToken") {
		t.Error("expected SessionToken in JSON output")
	}
	if !containsSubstring(output, "Expiration") {
		t.Error("expected Expiration in JSON output")
	}
	if !containsSubstring(output, "Version") {
		t.Error("expected Version in JSON output")
	}
}

func TestPrintINI(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token123",
			CanExpire:       true,
			Expires:         time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printINI(provider, "testprofile", "us-west-2")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printINI failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify INI contains expected sections and keys
	if !containsSubstring(output, "[testprofile]") {
		t.Error("expected [testprofile] section in INI output")
	}
	if !containsSubstring(output, "aws_access_key_id") {
		t.Error("expected aws_access_key_id in INI output")
	}
	if !containsSubstring(output, "aws_secret_access_key") {
		t.Error("expected aws_secret_access_key in INI output")
	}
	if !containsSubstring(output, "aws_session_token") {
		t.Error("expected aws_session_token in INI output")
	}
	if !containsSubstring(output, "region") {
		t.Error("expected region in INI output")
	}
}

func TestPrintEnv_WithPrefix(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "token123",
			CanExpire:       true,
			Expires:         time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printEnv(input, provider, "us-east-1", "export ")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printEnv failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify output has export prefix
	if !containsSubstring(output, "export AWS_ACCESS_KEY_ID=") {
		t.Error("expected 'export AWS_ACCESS_KEY_ID=' in output")
	}
	if !containsSubstring(output, "export AWS_SECRET_ACCESS_KEY=") {
		t.Error("expected 'export AWS_SECRET_ACCESS_KEY=' in output")
	}
	if !containsSubstring(output, "export AWS_SESSION_TOKEN=") {
		t.Error("expected 'export AWS_SESSION_TOKEN=' in output")
	}
	if !containsSubstring(output, "export AWS_REGION=") {
		t.Error("expected 'export AWS_REGION=' in output")
	}
}

func TestPrintEnv_NoPrefix(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printEnv(input, provider, "", "")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printEnv failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify output has no export prefix
	if containsSubstring(output, "export ") {
		t.Error("expected no 'export' prefix in output")
	}
	if !containsSubstring(output, "AWS_ACCESS_KEY_ID=") {
		t.Error("expected 'AWS_ACCESS_KEY_ID=' in output")
	}
}

func TestPrintEnv_NoRegion(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printEnv(input, provider, "", "")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printEnv failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify no region vars when region is empty
	if containsSubstring(output, "AWS_REGION=") {
		t.Error("expected no AWS_REGION when region is empty")
	}
}

func TestPrintEnv_NoSessionToken(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "", // No session token
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printEnv(input, provider, "", "")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printEnv failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Verify no session token when empty
	if containsSubstring(output, "AWS_SESSION_TOKEN=") {
		t.Error("expected no AWS_SESSION_TOKEN when token is empty")
	}
}

func TestPrintJSON_NoExpiration(t *testing.T) {
	provider := &mockCredsProvider{
		creds: aws.Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			CanExpire:       false, // No expiration
		},
	}

	input := ExportCommandInput{
		ProfileName: "test",
	}

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printJSON(input, provider)

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("printJSON failed: %v", err)
	}

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// When CanExpire is false, Expiration should be empty/omitted
	// The JSON will have "Expiration": "" or no Expiration field
	if containsSubstring(output, "2099") {
		t.Error("expected no expiration date in output when CanExpire is false")
	}
}

// containsSubstring is a helper to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
