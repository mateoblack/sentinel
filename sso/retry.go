// Package sso provides SSO error detection and login trigger infrastructure
// for automatic SSO authentication flows.
package sso

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/byteness/aws-vault/v7/vault"
	"github.com/byteness/keyring"
)

// AutoLoginConfig contains configuration for automatic SSO login on errors.
type AutoLoginConfig struct {
	// ProfileName is the profile to check for SSO config.
	ProfileName string

	// ConfigFile is the AWS config file for profile lookup.
	ConfigFile *vault.ConfigFile

	// Keyring is for storing refreshed OIDC token.
	Keyring keyring.Keyring

	// UseStdout prints URL instead of opening browser.
	UseStdout bool

	// Stderr is for user messages (default os.Stderr).
	Stderr io.Writer
}

// GetSSOConfigForProfile extracts SSO configuration from an AWS profile.
// Returns nil if the profile doesn't have SSO configuration (no sso_start_url).
// Returns nil without error if profile is not found (no SSO config to extract).
func GetSSOConfigForProfile(configFile *vault.ConfigFile, profileName string) (*SSOLoginConfig, error) {
	if configFile == nil {
		return nil, fmt.Errorf("configFile is nil")
	}

	// Load profile section
	profileSection, ok := configFile.ProfileSection(profileName)
	if !ok {
		// Profile not found - return nil (no SSO config available)
		return nil, nil
	}

	// Check if profile has SSO configuration
	startURL := profileSection.SSOStartURL
	ssoRegion := profileSection.SSORegion

	// If profile uses sso_session, get the SSO config from the sso-session section
	if profileSection.SSOSession != "" {
		ssoSession, ok := configFile.SSOSessionSection(profileSection.SSOSession)
		if ok {
			if ssoSession.SSOStartURL != "" {
				startURL = ssoSession.SSOStartURL
			}
			if ssoSession.SSORegion != "" {
				ssoRegion = ssoSession.SSORegion
			}
		}
	}

	// Return nil if no SSO configuration
	if startURL == "" {
		return nil, nil
	}

	return &SSOLoginConfig{
		StartURL:   startURL,
		Region:     ssoRegion,
		ClientName: "sentinel",
	}, nil
}

// WithAutoLogin wraps a function that may return SSO credential errors.
// If the function returns an SSO-related error and the profile has SSO config,
// it will trigger SSO login and retry the operation once.
//
// Type parameter T is the return type of the function being wrapped.
func WithAutoLogin[T any](ctx context.Context, config AutoLoginConfig, fn func() (T, error)) (T, error) {
	var zero T

	// Get stderr writer
	stderr := config.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Execute the function
	result, err := fn()
	if err == nil {
		return result, nil
	}

	// Check if this is an SSO credential error
	if !IsSSOCredentialError(err) {
		return zero, err
	}

	// Get SSO config for the profile
	ssoConfig, ssoErr := GetSSOConfigForProfile(config.ConfigFile, config.ProfileName)
	if ssoErr != nil {
		// Can't get SSO config - return original error
		return zero, err
	}
	if ssoConfig == nil {
		// Profile doesn't have SSO config - can't auto-login
		return zero, err
	}

	// Print message to stderr
	fmt.Fprintf(stderr, "SSO credentials expired. Initiating login...\n")

	// Configure SSO login
	ssoConfig.UseStdout = config.UseStdout

	// Trigger SSO login
	loginResult, loginErr := TriggerSSOLogin(ctx, *ssoConfig)
	if loginErr != nil {
		return zero, fmt.Errorf("SSO login failed: %w (original error: %v)", loginErr, err)
	}

	// Store new OIDC token in keyring if provided
	if config.Keyring != nil && loginResult != nil {
		// The keyring storage is handled by the SSO provider internally
		// when using aws-vault's SSO flow. For explicit token storage,
		// this would be the place to implement it.
		// For now, we rely on the AWS SDK's built-in caching.
		_ = loginResult
	}

	// Retry the function once
	fmt.Fprintf(stderr, "Retrying operation...\n")
	return fn()
}
