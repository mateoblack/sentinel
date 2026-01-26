package cli

import (
	"fmt"
	"io"
	"log"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// sentinelKeyringConfigDefaults mirrors the aws-vault keyring config
// to share the same credential store.
var sentinelKeyringConfigDefaults = keyring.Config{
	ServiceName:             "aws-vault",
	FilePasswordFunc:        fileKeyringPassphrasePrompt,
	LibSecretCollectionName: "awsvault",
	KWalletAppID:            "aws-vault",
	KWalletFolder:           "aws-vault",
	WinCredPrefix:           "aws-vault",
	OPConnectTokenEnv:       "AWS_VAULT_OP_CONNECT_TOKEN",
	OPTokenEnv:              "AWS_VAULT_OP_SERVICE_ACCOUNT_TOKEN",
	OPTokenFunc:             keyringPassphrasePrompt,

	// macOS Keychain security hardening:
	// - TrustApplication: allows this app to access items it created without prompting
	// - AccessibleWhenUnlocked: false = credentials unavailable when device locked
	// - Synchronizable: false = prevent credential sync to iCloud
	KeychainTrustApplication:       true,
	KeychainAccessibleWhenUnlocked: false,
	KeychainSynchronizable:         false,

	// Linux kernel keyring security:
	// - KeyCtlScope: "user" = keys visible only to current user's keyring
	// - KeyCtlPerm: possessor-only permissions (0x3f000000)
	//   Possessor: all permissions (bits 24-29)
	//   User/Group/Other: no permissions
	//   This prevents other processes (even same user) from accessing keys
	KeyCtlScope: "user",
	KeyCtlPerm:  keyring.KEYCTL_PERM_ALL << keyring.KEYCTL_PERM_PROCESS,
}

// Sentinel holds shared state for all sentinel commands.
type Sentinel struct {
	Debug          bool
	KeyringConfig  keyring.Config
	KeyringBackend string

	keyringImpl   keyring.Keyring
	awsConfigFile *vault.ConfigFile
}

// Keyring returns the keyring instance, opening it if necessary.
func (s *Sentinel) Keyring() (keyring.Keyring, error) {
	if s.keyringImpl == nil {
		if s.KeyringBackend != "" {
			s.KeyringConfig.AllowedBackends = []keyring.BackendType{keyring.BackendType(s.KeyringBackend)}
		}
		var err error
		s.keyringImpl, err = keyring.Open(s.KeyringConfig)
		if err != nil {
			return nil, err
		}

		// Log keychain security status on first keyring access
		vault.LogKeychainSecurityStatus()
	}

	return s.keyringImpl, nil
}

// AwsConfigFile returns the AWS config file, loading it if necessary.
func (s *Sentinel) AwsConfigFile() (*vault.ConfigFile, error) {
	if s.awsConfigFile == nil {
		var err error
		s.awsConfigFile, err = vault.LoadConfigFromEnv()
		if err != nil {
			return nil, err
		}
	}

	return s.awsConfigFile, nil
}

// ValidateProfile checks if profile exists in AWS config file.
// Returns nil if valid, error with available profiles if not found.
func (s *Sentinel) ValidateProfile(profileName string) error {
	configFile, err := s.AwsConfigFile()
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	_, ok, err := configFile.ProfileSection(profileName)
	if err != nil {
		return fmt.Errorf("failed to parse profile %q: %w", profileName, err)
	}
	if !ok {
		availableProfiles := configFile.ProfileNames()
		return fmt.Errorf("profile %q not found in AWS config; available profiles: %v", profileName, availableProfiles)
	}

	return nil
}

// ConfigureSentinelGlobals sets up global flags for the sentinel CLI.
func ConfigureSentinelGlobals(app *kingpin.Application) *Sentinel {
	s := &Sentinel{
		KeyringConfig: sentinelKeyringConfigDefaults,
	}

	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}

	app.Flag("debug", "Show debugging output").
		BoolVar(&s.Debug)

	app.Flag("backend", fmt.Sprintf("Secret backend to use %v", backendsAvailable)).
		Default(backendsAvailable[0]).
		Envar("AWS_VAULT_BACKEND").
		EnumVar(&s.KeyringBackend, backendsAvailable...)

	app.Flag("keychain", "Name of macOS keychain to use, if it doesn't exist it will be created").
		Default("aws-vault").
		Envar("AWS_VAULT_KEYCHAIN_NAME").
		StringVar(&s.KeyringConfig.KeychainName)

	app.Flag("secret-service-collection", "Name of secret-service collection to use, if it doesn't exist it will be created").
		Default("awsvault").
		Envar("AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME").
		StringVar(&s.KeyringConfig.LibSecretCollectionName)

	app.Flag("pass-dir", "Pass password store directory").
		Envar("AWS_VAULT_PASS_PASSWORD_STORE_DIR").
		StringVar(&s.KeyringConfig.PassDir)

	app.Flag("pass-cmd", "Name of the pass executable").
		Envar("AWS_VAULT_PASS_CMD").
		StringVar(&s.KeyringConfig.PassCmd)

	app.Flag("pass-prefix", "Prefix to prepend to the item path stored in pass").
		Envar("AWS_VAULT_PASS_PREFIX").
		StringVar(&s.KeyringConfig.PassPrefix)

	app.Flag("file-dir", "Directory for the \"file\" password store").
		Default("~/.awsvault/keys/").
		Envar("AWS_VAULT_FILE_DIR").
		StringVar(&s.KeyringConfig.FileDir)

	app.Flag("op-timeout", "Timeout for 1Password API operations (1Password Service Accounts only)").
		Default("15s").
		Envar("AWS_VAULT_OP_TIMEOUT").
		DurationVar(&s.KeyringConfig.OPTimeout)

	app.Flag("op-vault-id", "UUID of the 1Password vault").
		Envar("AWS_VAULT_OP_VAULT_ID").
		StringVar(&s.KeyringConfig.OPVaultID)

	app.Flag("op-item-title-prefix", "Prefix to prepend to 1Password item titles").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TITLE_PREFIX").
		StringVar(&s.KeyringConfig.OPItemTitlePrefix)

	app.Flag("op-item-tag", "Tag to apply to 1Password items").
		Default("aws-vault").
		Envar("AWS_VAULT_OP_ITEM_TAG").
		StringVar(&s.KeyringConfig.OPItemTag)

	app.Flag("op-connect-host", "1Password Connect server HTTP(S) URI").
		Envar("AWS_VAULT_OP_CONNECT_HOST").
		StringVar(&s.KeyringConfig.OPConnectHost)

	app.PreAction(func(c *kingpin.ParseContext) error {
		if !s.Debug {
			log.SetOutput(io.Discard)
		}
		keyring.Debug = s.Debug

		log.Printf("sentinel %s", app.Model().Version)
		return nil
	})

	return s
}
