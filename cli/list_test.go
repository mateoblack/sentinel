package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

func ExampleListCommand() {
	app := kingpin.New("aws-vault", "")
	awsVault := ConfigureGlobals(app)
	awsVault.keyringImpl = keyring.NewArrayKeyring([]keyring.Item{
		{Key: "llamas", Data: []byte(`{"AccessKeyID":"ABC","SecretAccessKey":"XYZ"}`)},
	})
	ConfigureListCommand(app, awsVault)
	kingpin.MustParse(app.Parse([]string{
		"list", "--credentials",
	}))

	// Output:
	// llamas
}

func TestListCommand_ProfilesOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile alpha]
region = us-east-1

[profile beta]
region = eu-west-1

[profile gamma]
region = ap-southeast-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := ListCommandInput{OnlyProfiles: true}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed: %v", err)
	}
}

func TestListCommand_CredentialsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile test]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "test", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
		{Key: "other", Data: []byte(`{"AccessKeyID":"AKIA456","SecretAccessKey":"secret2"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := ListCommandInput{OnlyCredentials: true}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed: %v", err)
	}
}

func TestListCommand_SessionsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile test]
region = us-east-1
sso_start_url = https://example.awsapps.com/start
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "oidc:https://example.awsapps.com/start", Data: []byte(`{"Token":{},"Expiration":"2099-01-01T00:00:00Z"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := ListCommandInput{OnlySessions: true}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed: %v", err)
	}
}

func TestListCommand_FullOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile production]
region = us-east-1

[profile staging]
region = us-west-2
sso_start_url = https://staging.awsapps.com/start
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "production", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
		{Key: "orphaned", Data: []byte(`{"AccessKeyID":"AKIA789","SecretAccessKey":"secret3"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Full output (no flags)
	input := ListCommandInput{}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed: %v", err)
	}
}

func TestListCommand_EmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	// Empty config file
	if err := os.WriteFile(configPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	kr := keyring.NewArrayKeyring([]keyring.Item{})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	input := ListCommandInput{}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed on empty config: %v", err)
	}
}

func TestStringslice_Has(t *testing.T) {
	tests := []struct {
		name   string
		slice  stringslice
		search string
		want   bool
	}{
		{
			name:   "found in slice",
			slice:  stringslice{"a", "b", "c"},
			search: "b",
			want:   true,
		},
		{
			name:   "not found in slice",
			slice:  stringslice{"a", "b", "c"},
			search: "d",
			want:   false,
		},
		{
			name:   "empty slice",
			slice:  stringslice{},
			search: "a",
			want:   false,
		},
		{
			name:   "first element",
			slice:  stringslice{"a", "b", "c"},
			search: "a",
			want:   true,
		},
		{
			name:   "last element",
			slice:  stringslice{"a", "b", "c"},
			search: "c",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slice.has(tt.search)
			if got != tt.want {
				t.Errorf("stringslice.has(%q) = %v, want %v", tt.search, got, tt.want)
			}
		})
	}
}

func TestStringslice_Remove(t *testing.T) {
	tests := []struct {
		name     string
		slice    stringslice
		toRemove []string
		want     []string
	}{
		{
			name:     "remove some elements",
			slice:    stringslice{"a", "b", "c", "d"},
			toRemove: []string{"b", "d"},
			want:     []string{"a", "c"},
		},
		{
			name:     "remove all elements",
			slice:    stringslice{"a", "b"},
			toRemove: []string{"a", "b"},
			want:     nil,
		},
		{
			name:     "remove nothing",
			slice:    stringslice{"a", "b", "c"},
			toRemove: []string{"x", "y"},
			want:     []string{"a", "b", "c"},
		},
		{
			name:     "empty slice",
			slice:    stringslice{},
			toRemove: []string{"a"},
			want:     nil,
		},
		{
			name:     "empty removal list",
			slice:    stringslice{"a", "b", "c"},
			toRemove: []string{},
			want:     []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.slice.remove(tt.toRemove)
			if len(got) != len(tt.want) {
				t.Errorf("stringslice.remove() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("stringslice.remove()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestListCommandInput_Defaults(t *testing.T) {
	input := ListCommandInput{}

	if input.OnlyProfiles {
		t.Error("expected OnlyProfiles to be false")
	}
	if input.OnlySessions {
		t.Error("expected OnlySessions to be false")
	}
	if input.OnlyCredentials {
		t.Error("expected OnlyCredentials to be false")
	}
}

func TestListCommand_CredentialsWithoutProfiles(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config")
	configContent := `[profile existing]
region = us-east-1
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	t.Setenv("AWS_CONFIG_FILE", configPath)

	// Credential exists but no corresponding profile in config
	kr := keyring.NewArrayKeyring([]keyring.Item{
		{Key: "orphan-creds", Data: []byte(`{"AccessKeyID":"AKIA123","SecretAccessKey":"secret"}`)},
	})

	configFile, err := vault.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// This should display the orphan credentials under "-" profile
	input := ListCommandInput{}
	err = ListCommand(input, configFile, kr)
	if err != nil {
		t.Fatalf("ListCommand failed: %v", err)
	}
}
